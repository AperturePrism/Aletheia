// ScopeService 的 gRPC 适配层（05 §6.3 ScopeService）。
//
// 职责边界：本文件只做 Kernel 裁决 ↔ proto 消息的翻译，不含任何
// 范围决策逻辑 —— 决策全部在 Kernel（09 §R8：判定逻辑集中于内核）。
package scopekernel

import (
	"context"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// Server 实现 alethv1.ScopeServiceServer。
type Server struct {
	alethv1.UnimplementedScopeServiceServer

	kernel *Kernel
}

// NewServer 装配 ScopeService。
func NewServer(kernel *Kernel) *Server { return &Server{kernel: kernel} }

// Check 执行范围裁决。层语义由调用方通过 request.layer 声明：
// L1/L2 走 Check（归一化 + 匹配），L3 走 CheckResolved（DNS 解析后复核）。
func (s *Server) Check(ctx context.Context, req *alethv1.ScopeCheckRequest) (*alethv1.ScopeCheckResult, error) {
	var v Verdict
	if req.GetLayer() == alethv1.ScopeLayer_POST_DNS {
		v = s.kernel.CheckResolved(ctx, req.GetSessionId(), req.GetTarget())
	} else {
		v = s.kernel.Check(req.GetSessionId(), req.GetTarget())
	}
	return &alethv1.ScopeCheckResult{
		Allowed:     v.Allowed,
		FailedLayer: failedLayerFor(req.GetLayer(), v.FailedBy),
		DecisionId:  v.DecisionID,
		Reason:      v.Reason,
	}, nil
}

// LoadScope 解析授权凭证文件并返回范围摘要（ScopeInfo，05 §6.3）。
func (s *Server) LoadScope(ctx context.Context, req *alethv1.LoadScopeRequest) (*alethv1.ScopeInfo, error) {
	scope, err := ParseScopeFile(req.GetAuthorizationPath())
	if err != nil {
		return nil, err
	}
	s.kernel.mu.Lock()
	s.kernel.scope = scope
	s.kernel.mu.Unlock()
	info := &alethv1.ScopeInfo{DenialPolicy: "DEFAULT_DENY"}
	for _, r := range scope.Include {
		info.Include = append(info.Include, r.Kind+":"+r.Value)
	}
	for _, r := range scope.Exclude {
		info.Exclude = append(info.Exclude, r.Kind+":"+r.Value)
	}
	return info, nil
}

// failedLayer 把裁决失败映射回调用方声明的层（05 §1.3 failed_layer）。
// 失败发生在调用方请求校验的那一层 —— 内核不替调用方猜测层归属。
func failedLayerFor(requested alethv1.ScopeLayer, _ string) alethv1.ScopeLayer {
	if requested == alethv1.ScopeLayer_SCOPE_LAYER_UNSPECIFIED {
		return alethv1.ScopeLayer_SCOPE_LAYER_UNSPECIFIED
	}
	return requested
}
