package governor

import (
	"testing"
)

func TestReserveRefusalIsTransientNotCircuitOpen(t *testing.T) {
	// 回归（缺陷：预扣被拒即永久熔断）：
	// 预扣被拒是**瞬时争用**，不是预算耗尽 —— 被拒的请求从未执行、零消耗，
	// 若因此置位熔断，剩余预算会被永久锁死且无解除路径。
	g, err := NewGovernor(1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Reserve("task1", 600); err != nil {
		t.Fatal(err)
	}
	if err := g.Reserve("task2", 600); err == nil {
		t.Fatal("over-committed reserve must be refused")
	}
	// 关键断言：被拒**不**熔断（旧实现在此失败）。
	if g.State().CircuitOpen {
		t.Fatal("a refused reserve must NOT open the circuit (no budget was consumed)")
	}
	// task1 正常结算后仍有 400 余量，必须可用。
	if err := g.Consume("task1", 600); err != nil {
		t.Fatal(err)
	}
	if err := g.Reserve("task3", 400); err != nil {
		t.Fatalf("remaining budget must be usable after a refused reserve: %v", err)
	}
}

func TestCircuitOpensOnlyOnRealExhaustion(t *testing.T) {
	// Q9 的正确读法：熔断对应「预算确实耗尽」，不是「某次预扣被拒」。
	g, _ := NewGovernor(1000)
	_ = g.Reserve("t1", 600)
	_ = g.Reserve("t2", 600) // 被拒，不熔断
	_ = g.Consume("t1", 600)
	_ = g.Reserve("t3", 400)
	_ = g.Consume("t3", 400) // 累计 1000 == total → 真实耗尽
	if !g.State().CircuitOpen {
		t.Fatal("circuit must open once consumption reaches the total")
	}
	// 熔断后无逃逸路径。
	if err := g.Reserve("t4", 1); err == nil {
		t.Fatal("reserve after circuit open must be refused (no bypass)")
	}
}

func TestConsumeIsIdempotent(t *testing.T) {
	// 调用方重试不得造成超计 —— 第二次 Consume 同一 taskID 是 no-op。
	g, _ := NewGovernor(1000)
	_ = g.Reserve("a", 100)
	_ = g.Consume("a", 100)
	_ = g.Consume("a", 100)
	_ = g.Consume("a", 100)
	if got := g.State().Consumed; got != 100 {
		t.Fatalf("repeated Consume double-counted: consumed=%d, want 100", got)
	}
}

func TestReleaseFreesReservation(t *testing.T) {
	// 失败/取消的任务必须能归还预扣，否则额度会被永久占住。
	g, _ := NewGovernor(100)
	if err := g.Reserve("x", 90); err != nil {
		t.Fatal(err)
	}
	if err := g.Reserve("y", 90); err == nil {
		t.Fatal("90+90 > 100 must be refused")
	}
	g.Release("x")
	if err := g.Reserve("y", 90); err != nil {
		t.Fatalf("released budget must be reusable: %v", err)
	}
}

func TestConsumeSettlesAndMayOpenCircuit(t *testing.T) {
	g, _ := NewGovernor(1000)
	_ = g.Reserve("task1", 500)
	if err := g.Consume("task1", 1200); err != nil { // 实际消耗超出总预算
		t.Fatal(err)
	}
	st := g.State()
	if st.Consumed != 1200 || st.Reserved != 0 {
		t.Fatalf("state = %+v", st)
	}
	if !st.CircuitOpen {
		t.Fatal("consuming 1200/1000 must open the circuit at settlement")
	}
}

func TestApertureNarrowedAt80(t *testing.T) {
	g, _ := NewGovernor(1000)
	_ = g.Reserve("t1", 850) // 85% ≥ 80%
	st := g.State()
	if !st.ApertureNarrowed {
		t.Fatal("utilization ≥ 0.8 must narrow aperture")
	}
	if st.CircuitOpen {
		t.Fatal("below 100% must not open the circuit")
	}
}

func TestZeroBudgetIsConfigError(t *testing.T) {
	// 无预算 = 永不熔断的熔断器 —— 配置层面就拒绝。
	if _, err := NewGovernor(0); err == nil {
		t.Fatal("zero budget must be a config error")
	}
}
