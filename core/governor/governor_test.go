package governor

import (
	"strings"
	"testing"
)

func TestReserveFailsWhenBudgetExhausted(t *testing.T) {
	// Q9：预算耗尽必熔断，无逃逸路径。
	g, err := NewGovernor(1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Reserve("task1", 600); err != nil {
		t.Fatal(err)
	}
	if err := g.Reserve("task2", 300); err != nil {
		t.Fatal(err)
	}
	// 600+300=900 已预扣；再要 200 → 超支 → 拒绝 + 熔断。
	err = g.Reserve("task3", 200)
	if err == nil {
		t.Fatal("over-budget reserve must be refused")
	}
	if !strings.Contains(err.Error(), "circuit opened") {
		t.Fatalf("refusal must open the circuit: %v", err)
	}
	// 熔断后任何新预扣都拒绝 —— 不存在"还有余量就放行"的逃逸路径。
	if err := g.Reserve("task4", 1); err == nil {
		t.Fatal("reserve after circuit open must be refused")
	}
	if !g.State().CircuitOpen {
		t.Fatal("circuit must be open")
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
