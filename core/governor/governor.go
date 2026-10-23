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
//
// 熔断语义（Q9「预算耗尽必然熔断，无逃逸路径」的正确读法）：
// 熔断对应**预算确实耗尽**这一事实，不是对应"某次预扣被拒"这一事件。
//
// 区分二者的必要性：预扣被拒可能只是**瞬时并发争用** —— 已提交额度
// 加上本次请求超了总额，但这些额度尚未真正消耗（Consume 结算后可能
// 大幅回退）。若在此时置 circuitOpen，被拒请求本身**从未执行、零消耗**，
// 却把整个会话永久锁死：剩余预算不可再用，且没有解除路径。
//
// 因此这里**不**置位熔断；熔断只由「已消耗 ≥ 总额」这一真实事实触发
// （见 Consume 与 State）。被拒的调用方应把本次拒绝视为可重试的
// 资源争用，而不是会话终止信号。
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
		return fmt.Errorf("budget reserve denied: committed %d + reserve %d > total %d "+
			"(transient contention; circuit NOT opened — budget is only exhausted on actual consumption)",
			committed, tokens, g.totalTokens)
	}
	g.reservedTokens[taskID] = tokens
	return nil
}

// Consume 结算实际消耗：释放预扣、累加 consumed。
// 实际消耗达到总额即熔断（真实耗尽 —— Q9 的唯一触发条件）。
//
// 幂等性：对同一 taskID 重复结算不会重复累加（第二次起 pre-deduction
// 已不存在，按"未预扣的补记"处理会双计）。这里只在该 taskID 仍有
// 预扣记录时累加，重复调用是 no-op —— 防止调用方重试逻辑造成超计。
func (g *Governor) Consume(taskID string, actual uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, reserved := g.reservedTokens[taskID]; reserved {
		g.consumedTokens += actual
		delete(g.reservedTokens, taskID)
	}
	if g.consumedTokens >= g.totalTokens {
		g.circuitOpen = true
	}
	return nil
}

// Release 释放预扣而不计消耗（任务失败/取消时调用）。
// 这是必需的对称操作：没有它，失败任务的预扣会永久占住额度，
// 最终把所有后续请求挤成"预扣被拒"。
func (g *Governor) Release(taskID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.reservedTokens, taskID)
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
