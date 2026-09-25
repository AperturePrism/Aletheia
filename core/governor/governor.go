// Package governor 实现 M6 CostGovernor（modules/M6 §6，Q9 预算熔断）。
//
// 预扣制（§6.2）：任务开始前 Reserve 预扣，失败即拒绝执行 —— 防止并发
// 任务同时消耗导致超支。P0 阶段门禁第 5 条「预算耗尽必熔断，无逃逸路径」
// 的执行体：
//
//	utilization ≥ 0.8 → aperture_narrowed（收窄光圈，M3 消费）
//	utilization ≥ 1.0 → circuit_open（硬熔断，全部调用方必须停止）
package governor

import (
	"fmt"
	"sync"
)

// Governor 是会话级预算账本。一个实例对应一个会话（M2 按会话分区的同源设计）。
type Governor struct {
	mu             sync.Mutex
	totalTokens    uint64
	consumedTokens uint64
	reservedTokens map[string]uint64 // taskID → 预扣中的额度
	circuitOpen    bool
}

// NewGovernor 建立预算账本。totalTokens <= 0 是配置错误（预算必须显式设定 ——
// "无预算"意味着成本约束不存在，违反 05 §6.3 BudgetState 语义）。
func NewGovernor(totalTokens uint64) (*Governor, error) {
	if totalTokens == 0 {
		return nil, fmt.Errorf("budget total must be set explicitly (a session without a budget is a circuit that never opens)")
	}
	return &Governor{
		totalTokens:    totalTokens,
		reservedTokens: make(map[string]uint64),
	}, nil
}

// Reserve 预扣额度。预扣失败即拒绝执行（P-4），不存在"先跑再补预算"。
func (g *Governor) Reserve(taskID string, tokens uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.circuitOpen {
		return fmt.Errorf("budget circuit is open; refusing reserve for task %q", taskID)
	}
	committed := g.consumedTokens
	for _, r := range g.reservedTokens {
		committed += r
	}
	if committed+tokens > g.totalTokens {
		g.circuitOpen = true // 预算耗尽：硬熔断，无逃逸路径（Q9）
		return fmt.Errorf("budget exceeded: committed %d + reserve %d > total %d; circuit opened",
			committed, tokens, g.totalTokens)
	}
	g.reservedTokens[taskID] = tokens
	return nil
}

// Consume 结算实际消耗：释放预扣、累加 consumed。
// 实际消耗超过预扣同样可能触发熔断（结算时复核）。
func (g *Governor) Consume(taskID string, actual uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.consumedTokens += actual
	delete(g.reservedTokens, taskID)
	if g.consumedTokens >= g.totalTokens {
		g.circuitOpen = true
	}
	return nil
}

// State 返回当前预算状态（05 §6.3 BudgetState）。
func (g *Governor) State() State {
	g.mu.Lock()
	defer g.mu.Unlock()
	var reserved uint64
	for _, r := range g.reservedTokens {
		reserved += r
	}
	committed := g.consumedTokens + reserved
	util := 0.0
	if g.totalTokens > 0 {
		util = float64(committed) / float64(g.totalTokens)
	}
	return State{
		Total:            g.totalTokens,
		Consumed:         g.consumedTokens,
		Reserved:         reserved,
		Utilization:      util,
		CircuitOpen:      g.circuitOpen || util >= 1.0,
		ApertureNarrowed: util >= 0.8,
	}
}

// State 是 05 §6.3 BudgetState 的 Go 形态。
type State struct {
	Total            uint64
	Consumed         uint64
	Reserved         uint64
	Utilization      float64
	CircuitOpen      bool
	ApertureNarrowed bool
}
