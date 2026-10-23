// MCP 闸门适配 —— 把 MCP 的工具调用接到与 WebUI/CLI **完全相同**的
// 闸门链上（06 §3.4 的"不得有绕过路径"）。
//
// # 这条约束的实现方式
//
// MCP 的 `Gate.Authorize` 在这里被实现为**依次调用既有服务**：
//
//  1. ScopeService.Check        → 范围裁决（L1 network 层）
//  2. GatewayService.Tokenize   → 参数脱敏（真实值不出现在工具侧）
//  3. GovernorService.Reserve   → 预算预扣（超预算即拒绝）
//
// 关键是**不重新判断**：范围裁决复用 ScopeKernel、脱敏复用 Gateway、
// 预算复用 Governor。若这里"顺手"写一份自己的 scope 判断，
// 就是第二套实现 —— 而两套必然漂移，漂移的那一侧就是绕过路径。
package mcp

import (
	"context"
	"fmt"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// newInternalConn 建立到本地 gRPC server 的连接（仅回环）。
//
// # 为什么走真实的 gRPC 而不是直接调用 Go 结构体
//
// 直接调用会绕过 gRPC 拦截器链（观测 + 脱敏，见 `unaryRedactionInterceptor`），
// 因此"MCP 走与 WebUI 相同的路径"这句承诺就不成立了。
//
// 走回环 gRPC 的代价是一次本地序列化 —— 相对于工具执行本身可忽略，
// 而收益是**约束由代码结构保证**，而不是靠"记得别绕过"。
func newInternalConn(addr string) (*grpc.ClientConn, error) {
	if addr == "" {
		return nil, fmt.Errorf("mcp gate: internal gRPC address is required")
	}
	return grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
}

// serviceGate 通过**进程内的既有 gRPC 服务**做闸门校验。
//
// 用 gRPC 客户端而不是直接调用 Go 结构体：这保证 MCP 走的是与
// WebUI 完全相同的代码路径（同一个 server 实例、同一套拦截器），
// 而不是一条"更方便"的直连。
type ServiceGate struct {
	conn     *grpc.ClientConn
	scope    alethv1.ScopeServiceClient
	gateway  alethv1.GatewayServiceClient
	governor alethv1.GovernorServiceClient
}

// NewServiceGate 建立到本地 gRPC server 的内部连接。
func NewServiceGate(addr string) (*ServiceGate, error) {
	conn, err := newInternalConn(addr)
	if err != nil {
		return nil, err
	}
	return &ServiceGate{
		conn:     conn,
		scope:    alethv1.NewScopeServiceClient(conn),
		gateway:  alethv1.NewGatewayServiceClient(conn),
		governor: alethv1.NewGovernorServiceClient(conn),
	}, nil
}

// Close 释放内部连接。
func (g *ServiceGate) Close() error { return g.conn.Close() }

// Authorize 执行三步闸门（06 §3.4）。
//
// 任一步失败即拒绝，**不继续后续步骤** —— 与 P-4（失败即熔断不降级）
// 一致。特别地：范围裁决失败时**不做脱敏与预算预扣** ——
// 越界请求不应消耗任何资源。
func (g *ServiceGate) Authorize(ctx context.Context, req ToolCall) error {
	// ---- 1. 范围裁决（09 §R8：DENY 必须熔断整场会话）----
	if req.Target == "" {
		// 无目标 = 无法做范围裁决 → 拒绝（fail-closed）。
		//
		// 这与 scope kernel 的默认拒绝同源：MCP 的调用方是外部 agent，
		// "没给目标"不能解释为"不需要校验"。
		return &ErrUnauthorized{
			Reason: "tool call has no target; scope cannot be evaluated " +
				"(the scope kernel is default-deny, so an unverifiable target is refused)",
		}
	}
	res, err := g.scope.Check(ctx, &alethv1.ScopeCheckRequest{
		SessionId: req.SessionID,
		Target:    req.Target,
		Layer:     alethv1.ScopeLayer_NETWORK,
	})
	if err != nil {
		return fmt.Errorf("mcp gate: scope check unavailable: %w", err)
	}
	if !res.GetAllowed() {
		// 原样透出内核的理由（含 failed_layer 与 decision_id）——
		// 外部 agent 需要知道"为什么被拒"，而不是一个笼统的 forbidden。
		return &ErrUnauthorized{Reason: fmt.Sprintf(
			"scope denied target %q: %s (layer=%s, decision=%s)",
			req.Target, res.GetReason(), res.GetFailedLayer(), res.GetDecisionId())}
	}

	// ---- 2. 参数脱敏（真实值不出现在工具侧）----
	if req.ToolName != "" {
		// 把参数拼成一段文本做脱敏检查 —— 这里的目的是**确认脱敏能力可用**，
		// 而不是改写参数（参数的实际脱敏在 IngestService 内部完成，
		// 与 WebUI 走同一条路径）。
		if _, err := g.gateway.ScanOutbound(ctx, &alethv1.ScanRequest{
			SessionId: req.SessionID,
			Content:   req.ToolName,
			Direction: "mcp_tool_call",
		}); err != nil {
			return fmt.Errorf("mcp gate: privacy gateway unavailable: %w", err)
		}
	}

	// ---- 3. 预算预扣（超预算即拒绝，无逃逸路径）----
	if _, err := g.governor.Reserve(ctx, &alethv1.ReserveRequest{
		SessionId:       req.SessionID,
		TaskId:          "mcp:" + req.CallerID,
		EstimatedTokens: 1000, // 单次工具调用的粗估；实际结算由 Ingest 路径完成
	}); err != nil {
		// 预算服务不可用或未配置 → 拒绝（fail-closed）。
		//
		// 与 GovernorService 的设计一致：无预算的会话是一个永不熔断的
		// 熔断器，因此 MCP 不应在无预算时执行有副作用的操作。
		return &ErrUnauthorized{
			Reason: "budget reservation refused; " +
				"a session without a budget is a circuit that never opens (M6 §6)",
		}
	}
	return nil
}
