// GovernorService 的 gRPC 适配层（05 §6.3）。
//
// 与 scopekernel/prism/aperture/orchestrate 的 server.go 同一分工：
// 只做 proto 消息 ↔ governor.Governor 的翻译与错误映射。
//
// I3 遗留说明：`core/governor` 在 I3 已实现并测试（预扣制 + 双阈值熔断），
// 但当时**未接 gRPC**（`registry.Governor` 一直是 unimplementedGovernor）。
// 本文件补齐该接线 —— 04 §I6 的「成本与预算面板」（06 页面 10）需要它
// 才能显示实时消耗。
package governor

import (
	"context"
	"errors"
	"fmt"
	"sync"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server 实现 alethv1.GovernorServiceServer。
//
// 会话模型：一个 session_id 一个 Governor 实例（M6 §6：会话级预算账本，
// 与 M2 按会话分区的同源设计）。预算总额由 BudgetProvider 提供 ——
// 它必须**显式设定**（NewGovernor 拒绝零预算：无预算的会话是一个
// 永不熔断的熔断器）。
type Server struct {
	alethv1.UnimplementedGovernorServiceServer

	mu       sync.Mutex
	sessions map[string]*Governor
	// budgetFor 返回某会话的预算总额。返回 0 表示未配置 —— 此时
	// Reserve 显式失败（fail-closed），而不是给一个默认值。
	//
	// 为什么不给默认值：预算默认值会让"忘了配置预算"变成"跑起来了
	// 但用一个猜测的上限"，而预算正是成本约束本身（05 §6.3）。
	budgetFor func(sessionID string) uint64
}

// NewServer 装配 GovernorService。
//
// budgetFor 为 nil 时所有 Reserve 都会失败（fail-closed）——
// 这是有意的：没有预算来源的编排层不应能执行任何任务。
func NewServer(budgetFor func(sessionID string) uint64) *Server {
	return &Server{
		sessions:  map[string]*Governor{},
		budgetFor: budgetFor,
	}
}

// Reserve 预扣预算（fail-closed：失败即拒绝执行，不许 best-effort 继续）。
func (s *Server) Reserve(ctx context.Context, req *alethv1.ReserveRequest) (*alethv1.ReserveResult, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	g, err := s.session(req.GetSessionId())
	if err != nil {
		return &alethv1.ReserveResult{
			Reserved: false,
			State:    &alethv1.BudgetState{},
			Error: &alethv1.Error{
				Code:        alethv1.ErrorCode_UPSTREAM_UNAVAILABLE,
				Message:     err.Error(),
				Remediation: "configure a token budget for this session before executing tasks",
			},
		}, nil
	}
	if req.GetTaskId() == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id is required")
	}

	if err := g.Reserve(req.GetTaskId(), uint64(req.GetEstimatedTokens())); err != nil {
		// 预扣被拒**不是** gRPC 错误 —— 它是业务结论（reserved=false +
		// 状态 + 原因），调用方据此降级或等待，而非把它当传输故障。
		return &alethv1.ReserveResult{
			Reserved: false,
			State:    stateToProto(g.State()),
			Error: &alethv1.Error{
				Code:    alethv1.ErrorCode_BUDGET_EXCEEDED,
				Message: err.Error(),
				Remediation: "narrow the aperture, shrink the task, or raise the session budget " +
					"(a refused reserve is transient contention unless the circuit is open)",
			},
		}, nil
	}
	g.mu.Lock()
	reserved := g.reservedTokens[req.GetTaskId()]
	g.mu.Unlock()
	return &alethv1.ReserveResult{
		Reserved:       true,
		ReservedTokens: uint32(reserved),
		State:          stateToProto(g.State()),
	}, nil
}

// Consume 结算实际消耗。
func (s *Server) Consume(ctx context.Context, req *alethv1.ConsumeRequest) (*alethv1.BudgetState, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	g, err := s.session(req.GetSessionId())
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	if req.GetTaskId() == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id is required")
	}
	if err := g.Consume(req.GetTaskId(), uint64(req.GetActualTokens())); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return stateToProto(g.State()), nil
}

// State 返回当前预算状态。
func (s *Server) State(ctx context.Context, req *alethv1.BudgetStateRequest) (*alethv1.BudgetState, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	g, err := s.session(req.GetSessionId())
	if err != nil {
		// 未配置预算的会话返回全零状态而非错误：面板需要能显示
		// "这个会话还没有预算"这一事实，而不是一个红色的失败态。
		return &alethv1.BudgetState{}, nil
	}
	return stateToProto(g.State()), nil
}

// CheckCircuit 检查熔断状态（调用方必须据此停止）。
func (s *Server) CheckCircuit(ctx context.Context, req *alethv1.CircuitCheckRequest) (*alethv1.CircuitState, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	g, err := s.session(req.GetSessionId())
	if err != nil {
		return &alethv1.CircuitState{
			CircuitOpen:   false,
			TriggerReason: "no budget configured for this session",
			Budget:        &alethv1.BudgetState{},
		}, nil
	}
	st := g.State()
	return &alethv1.CircuitState{
		CircuitOpen:   st.CircuitOpen,
		TriggerReason: circuitReason(st),
		Budget:        stateToProto(st),
	}, nil
}

// ---- 内部 ----

// session 取（或惰性建立）某会话的账本。
func (s *Server) session(sessionID string) (*Governor, error) {
	if sessionID == "" {
		return nil, errors.New("session_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if g, ok := s.sessions[sessionID]; ok {
		return g, nil
	}
	if s.budgetFor == nil {
		return nil, errors.New("no budget provider configured; refusing to execute (fail-closed)")
	}
	total := s.budgetFor(sessionID)
	if total == 0 {
		return nil, fmt.Errorf(
			"session %q has no token budget; a session without a budget is a circuit that never opens",
			sessionID)
	}
	g, err := NewGovernor(total)
	if err != nil {
		return nil, err
	}
	s.sessions[sessionID] = g
	return g, nil
}

// stateToProto 把领域状态映射为契约消息（05 §6.3 BudgetState）。
func stateToProto(st State) *alethv1.BudgetState {
	return &alethv1.BudgetState{
		TotalTokens:      uint32(st.Total),
		ConsumedTokens:   uint32(st.Consumed),
		ReservedTokens:   uint32(st.Reserved),
		Utilization:      st.Utilization,
		CircuitOpen:      st.CircuitOpen,
		ApertureNarrowed: st.ApertureNarrowed,
	}
}

// circuitReason 给出熔断原因（或收窄提示）—— 面板与编排层都要显示它。
func circuitReason(st State) string {
	switch {
	case st.CircuitOpen:
		return "budget exhausted: all callers must stop (no escape path)"
	case st.ApertureNarrowed:
		return "utilization ≥ 0.8: aperture narrowed, only high-value tasks should proceed"
	default:
		return ""
	}
}

func ctxErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return status.Error(codes.Canceled, ctx.Err().Error())
	default:
		return nil
	}
}
