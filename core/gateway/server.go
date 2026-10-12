// GatewayService 的 gRPC 适配层（05 §6.4）。
//
// 与 scopekernel/prism/aperture/orchestrate/governor 的 server.go 同一分工：
// 只做 proto 消息 ↔ gateway.Gateway 的翻译与错误映射。
//
// # ★ 一条不可妥协的规则：真实值不出现在任何响应里
//
// `TokenizeResult.mappings` 是 `TokenMapping`（05 §6.4），它只有
// `category` / `token` / `masked_value` 三个字段 —— **没有真实值字段**，
// 且契约注释原文："真实值不随消息回传，只返回掩码形式供审计"。
//
// 这不是"实现时注意一下"，而是**类型系统层面的保证**：proto 里没有
// 可放真实值的字段，因此本适配层无法泄漏它（07 §A2：映射表仅存本地
// 且不落日志）。
//
// # 会话隔离
//
// 映射表按 `session_id` 隔离（M6 §4.1 的确定性要求是"同一真实值在
// **同一会话内**映射到同一 token"）。跨会话共用一个 Gateway 会让
// 两个会话的 token 编号互相影响，破坏"同值同 token"的确定性。
package gateway

import (
	"context"
	"sync"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server 实现 alethv1.GatewayServiceServer。
type Server struct {
	alethv1.UnimplementedGatewayServiceServer

	mu       sync.Mutex
	sessions map[string]*Gateway
	// defaultSession 用于未指定 session_id 的调用。
	//
	// 给默认会话是**有意的**：要求每个调用点都传 session_id 会让
	// 漏传变成错误（fail-closed，好），但也让单会话（单机模式的主场景）
	// 无处安放。折中：漏传归入 default 会话，但**不跨真实会话复用**
	// —— 因此不会破坏会话隔离。
	defaultSession string
}

// DefaultSessionID 是未指定会话时的归属。
const DefaultSessionID = "default"

// NewServer 装配 GatewayService。
func NewServer() *Server {
	return &Server{
		sessions:       map[string]*Gateway{},
		defaultSession: DefaultSessionID,
	}
}

// Tokenize 把真实敏感值替换为确定性 token（05 §6.4）。
func (s *Server) Tokenize(ctx context.Context, req *alethv1.TokenizeRequest) (*alethv1.TokenizeResult, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	g := s.sessionFor(req.GetSessionId())
	tokenized, applied := g.Tokenize(req.GetContent())

	// 构造映射清单 —— 只含 category / token / masked_value。
	//
	// 真实值**不在这里**：Tokenize 只返回 token 列表（`applied`），
	// 不返回真实值。因此本方法在类型层面无法泄漏它们。
	mappings := make([]*alethv1.TokenMapping, 0, len(applied))
	for _, tok := range applied {
		cat := categoryOfToken(tok)
		mappings = append(mappings, &alethv1.TokenMapping{
			Category: cat,
			Token:    tok,
			// masked_value 对 token 本身做掩码：token 已是脱敏形式，
			// 再掩码是为了让审计日志里连 token 编号也不完整
			// （07 §A2 的"映射表不落普通日志"）。
			MaskedValue: maskToken(tok),
		})
	}
	return &alethv1.TokenizeResult{Tokenized: tokenized, Mappings: mappings}, nil
}

// Detokenize 把 token 回注为真实值（**仅工具执行前一刻**，05 §6.4）。
//
// 契约注释原文："仅工具执行前一刻调用。回注后工具看到真实值，
// 仅模型侧脱敏。"
//
// 这是唯一会返回真实值的接口 —— 它在语义上就是"给工具用的"，
// 而不是"给模型用的"。调用方（M1 的沙箱执行路径）拿到的就是
// 要传给工具的 argv/参数。
func (s *Server) Detokenize(ctx context.Context, req *alethv1.DetokenizeRequest) (*alethv1.DetokenizeResult, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	g := s.sessionFor(req.GetSessionId())
	return &alethv1.DetokenizeResult{Restored: g.Detokenize(req.GetContent())}, nil
}

// ScanOutbound 出站二次扫描（05 §6.4）：命中即阻断。
func (s *Server) ScanOutbound(ctx context.Context, req *alethv1.ScanRequest) (*alethv1.ScanResult, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	g := s.sessionFor(req.GetSessionId())
	hits := g.ScanOutbound(req.GetContent())

	out := &alethv1.ScanResult{Clean: len(hits) == 0}
	for _, h := range hits {
		// 契约的 `LeakHit`（05 §6.4）只有三个字段：
		// category / offset / excerpt_masked。
		//
		// 注意**没有 value_hash** —— 内部 `gateway.LeakHit` 有该字段
		// （供本地审计比对），但**契约不带**它。这符合 07 §A2 的
		// "映射表不落普通日志"：连哈希都不出站，避免被当作
		// 可爆破的指纹。
		//
		// excerpt 已是掩码形式（`gateway.LeakHit` 的契约：
		// "excerpt 必须掩码 —— 告警日志不含真实值"）。
		out.Hits = append(out.Hits, &alethv1.LeakHit{
			Category:      h.Category,
			Offset:        uint32(h.Offset),
			ExcerptMasked: h.Excerpt,
		})
	}
	return out, nil
}

// ---- 内部 ----

// sessionFor 取（或惰性建立）某会话的映射表。
func (s *Server) sessionFor(sessionID string) *Gateway {
	if sessionID == "" {
		sessionID = s.defaultSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if g, ok := s.sessions[sessionID]; ok {
		return g
	}
	g := NewGateway()
	s.sessions[sessionID] = g
	return g
}

// categoryOfToken 从 token 文本反推类别。
//
// token 形如 `IP_PRIVATE_001`（gateway.tokenFor 的格式），
// 因此前缀即可判定类别。不可识别时返回空串 —— **不猜**
// （猜错会让审计里的类别标签失真）。
func categoryOfToken(tok string) string {
	for _, c := range []TokenCategory{
		CatIPPrivate, CatHostInternal, CatEmail, CatCredential, CatPathInternal,
	} {
		p := c.String() + "_"
		if len(tok) > len(p) && tok[:len(p)] == p {
			return c.String()
		}
	}
	return ""
}

// maskToken 对 token 做审计用掩码（保留类别前缀，隐藏序号）。
//
// 例：`IP_PRIVATE_001` → `IP_PRIVATE_***`
func maskToken(tok string) string {
	for _, c := range []TokenCategory{
		CatIPPrivate, CatHostInternal, CatEmail, CatCredential, CatPathInternal,
	} {
		p := c.String() + "_"
		if len(tok) > len(p) && tok[:len(p)] == p {
			return c.String() + "_***"
		}
	}
	return "***"
}

func ctxErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return status.Error(codes.Canceled, ctx.Err().Error())
	default:
		return nil
	}
}
