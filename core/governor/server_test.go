package governor

import (
	"context"
	"strings"
	"testing"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// 本文件是 GovernorService gRPC 适配的测试（I3 实现 + I6 接线）。
//
// 契约依据：05 §6.3 GovernorService / BudgetState。

func newServer(budget uint64) *Server {
	return NewServer(func(string) uint64 { return budget })
}

func TestReserveSucceedsWithinBudget(t *testing.T) {
	s := newServer(1000)
	res, err := s.Reserve(context.Background(), &alethv1.ReserveRequest{
		SessionId: "s1", TaskId: "t1", EstimatedTokens: 400,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.GetReserved() {
		t.Fatalf("reserve should succeed: %v", res.GetError())
	}
	if res.GetReservedTokens() != 400 {
		t.Fatalf("reserved = %d, want 400", res.GetReservedTokens())
	}
	if res.GetState().GetTotalTokens() != 1000 {
		t.Fatalf("total = %d, want 1000", res.GetState().GetTotalTokens())
	}
}

func TestReserveRefusalIsBusinessResultNotTransportError(t *testing.T) {
	// 预扣被拒是**业务结论**（reserved=false + 状态 + 原因），
	// 不是 gRPC 传输错误 —— 调用方据此降级或等待，而非当成服务故障重试。
	s := newServer(100)
	res, err := s.Reserve(context.Background(), &alethv1.ReserveRequest{
		SessionId: "s1", TaskId: "big", EstimatedTokens: 500,
	})
	if err != nil {
		t.Fatalf("a refused reserve must not be a transport error: %v", err)
	}
	if res.GetReserved() {
		t.Fatal("reserve beyond budget must be refused")
	}
	if res.GetError() == nil {
		t.Fatal("refusal must carry an explicit reason")
	}
	if res.GetError().GetCode() != alethv1.ErrorCode_BUDGET_EXCEEDED {
		t.Fatalf("code = %v, want BUDGET_EXCEEDED", res.GetError().GetCode())
	}
	// 关键：被拒**不**熔断（瞬时争用语义，见 governor.go 的 Reserve 注释）。
	if res.GetState().GetCircuitOpen() {
		t.Fatal("a refused reserve must not open the circuit (nothing was consumed)")
	}
}

func TestSessionWithoutBudgetFailsClosed(t *testing.T) {
	// 无预算来源时 Reserve 显式失败 —— 不给默认值。
	// 预算默认值会让"忘了配置"变成"用猜测的上限跑起来了"，
	// 而预算正是成本约束本身（05 §6.3）。
	s := NewServer(nil)
	res, err := s.Reserve(context.Background(), &alethv1.ReserveRequest{
		SessionId: "s1", TaskId: "t1", EstimatedTokens: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetReserved() {
		t.Fatal("reserve without a configured budget must fail closed")
	}
	if res.GetError().GetCode() != alethv1.ErrorCode_UPSTREAM_UNAVAILABLE {
		t.Fatalf("code = %v, want UPSTREAM_UNAVAILABLE", res.GetError().GetCode())
	}
}

func TestZeroBudgetSessionFailsClosed(t *testing.T) {
	s := newServer(0) // 提供方返回 0 = 未配置
	res, err := s.Reserve(context.Background(), &alethv1.ReserveRequest{
		SessionId: "s1", TaskId: "t1", EstimatedTokens: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetReserved() {
		t.Fatal("a zero-budget session must refuse to execute")
	}
}

func TestConsumeSettlesAndReportsState(t *testing.T) {
	s := newServer(1000)
	_, _ = s.Reserve(context.Background(), &alethv1.ReserveRequest{
		SessionId: "s1", TaskId: "t1", EstimatedTokens: 600,
	})
	st, err := s.Consume(context.Background(), &alethv1.ConsumeRequest{
		SessionId: "s1", TaskId: "t1", ActualTokens: 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetConsumedTokens() != 600 {
		t.Fatalf("consumed = %d, want 600", st.GetConsumedTokens())
	}
	if st.GetReservedTokens() != 0 {
		t.Fatalf("reserved should be released, got %d", st.GetReservedTokens())
	}
	if st.GetCircuitOpen() {
		t.Fatal("600/1000 must not open the circuit")
	}
}

func TestApertureNarrowedFlagAt80Percent(t *testing.T) {
	s := newServer(1000)
	_, _ = s.Reserve(context.Background(), &alethv1.ReserveRequest{
		SessionId: "s1", TaskId: "t1", EstimatedTokens: 850,
	})
	st, err := s.State(context.Background(), &alethv1.BudgetStateRequest{SessionId: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	if !st.GetApertureNarrowed() {
		t.Fatal("utilization ≥ 0.8 must set aperture_narrowed (M6 §6)")
	}
	if st.GetCircuitOpen() {
		t.Fatal("below 100% must not open the circuit")
	}
}

func TestStateOnUnbudgetedSessionReturnsZeros(t *testing.T) {
	// 面板需要能显示"这个会话还没有预算"这一事实，
	// 而不是一个红色失败态 —— 因此返回零状态而非错误。
	s := NewServer(func(string) uint64 { return 0 })
	st, err := s.State(context.Background(), &alethv1.BudgetStateRequest{SessionId: "nope"})
	if err != nil {
		t.Fatalf("State on an unbudgeted session should not error: %v", err)
	}
	if st.GetTotalTokens() != 0 {
		t.Fatalf("expected zero state, got %+v", st)
	}
}

func TestCircuitOpensOnRealExhaustion(t *testing.T) {
	s := newServer(500)
	_, _ = s.Reserve(context.Background(), &alethv1.ReserveRequest{
		SessionId: "s1", TaskId: "t1", EstimatedTokens: 500,
	})
	_, _ = s.Consume(context.Background(), &alethv1.ConsumeRequest{
		SessionId: "s1", TaskId: "t1", ActualTokens: 500,
	})
	cs, err := s.CheckCircuit(context.Background(), &alethv1.CircuitCheckRequest{SessionId: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	if !cs.GetCircuitOpen() {
		t.Fatal("consuming the full budget must open the circuit")
	}
	if !strings.Contains(cs.GetTriggerReason(), "exhausted") {
		t.Fatalf("circuit reason should explain the trigger: %q", cs.GetTriggerReason())
	}
	// 熔断后无逃逸路径。
	res, _ := s.Reserve(context.Background(), &alethv1.ReserveRequest{
		SessionId: "s1", TaskId: "t2", EstimatedTokens: 1,
	})
	if res.GetReserved() {
		t.Fatal("reserve after circuit open must be refused (no escape path)")
	}
}

func TestCheckCircuitNarrowingReason(t *testing.T) {
	s := newServer(1000)
	_, _ = s.Reserve(context.Background(), &alethv1.ReserveRequest{
		SessionId: "s1", TaskId: "t1", EstimatedTokens: 900,
	})
	cs, _ := s.CheckCircuit(context.Background(), &alethv1.CircuitCheckRequest{SessionId: "s1"})
	if cs.GetCircuitOpen() {
		t.Fatal("should not be open at 90%")
	}
	if !strings.Contains(cs.GetTriggerReason(), "narrowed") {
		t.Fatalf("expected a narrowing hint: %q", cs.GetTriggerReason())
	}
}

func TestSessionsAreIsolated(t *testing.T) {
	// 会话级账本（M6 §6）—— 一个会话的消耗不影响另一个。
	s := newServer(1000)
	_, _ = s.Reserve(context.Background(), &alethv1.ReserveRequest{
		SessionId: "sA", TaskId: "t", EstimatedTokens: 900,
	})
	stB, _ := s.State(context.Background(), &alethv1.BudgetStateRequest{SessionId: "sB"})
	if stB.GetConsumedTokens() != 0 || stB.GetReservedTokens() != 0 {
		t.Fatalf("session B must be unaffected: %+v", stB)
	}
}

func TestReserveRequiresTaskID(t *testing.T) {
	s := newServer(1000)
	if _, err := s.Reserve(context.Background(), &alethv1.ReserveRequest{
		SessionId: "s1", EstimatedTokens: 100,
	}); err == nil {
		t.Fatal("reserve without task_id must be rejected")
	}
}

func TestReserveRequiresSessionID(t *testing.T) {
	s := newServer(1000)
	res, err := s.Reserve(context.Background(), &alethv1.ReserveRequest{
		TaskId: "t1", EstimatedTokens: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetReserved() {
		t.Fatal("reserve without session_id must fail closed")
	}
}
