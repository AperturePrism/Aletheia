// ListSessions 所需的跨模块状态适配器（`contract:2026-11-02`）。
//
// # 为什么放在装配层
//
// `core/orchestrate` 只知道自己有哪些任务图；预算在 M6 Governor、
// finding 计数在账本（Python 侧，经 `focalplane.Proxy` 代理）。
// 若让编排层直接去查那两个模块，它就变成了聚合层。
//
// 因此 `SessionSource` 的接口定义在编排层，**实现在这里** ——
// 与既有的 `checkpointSnapshotAdapter` 完全同一套做法。
//
// # 为什么 findings 计数如实返回"未提供"
//
// 账本在 Python 侧（`core/focalplane/proxy.go` 转发），Go 进程内
// 没有 finding 集合可供计数。此时有两种做法：
//
//   · 填 0 —— 页面会显示"0 个 finding"，与"真的没有 finding"无法区分；
//   · 如实说明"未提供" —— 页面显示为空/未知。
//
// 选后者。`docs/10` §0 明确反对"用绿灯替换有效性"：一个假的 0
// 比一个诚实的空白危险得多 —— 它会让"漏了"看起来像"没问题"。

package main

import (
	"context"

	"github.com/AperturePrism/aleth/core/orchestrate"
)

// sessionSourceAdapter 为 `ListSessions` 提供预算与 finding 摘要。
type sessionSourceAdapter struct {
	// budgetState 返回某会话的预算摘要（consume, total, circuitOpen, ok）。
	// nil 表示未接线 —— 此时预算字段留空并告警，不填 0。
	budgetState func(sessionID string) (consume, total uint64, circuitOpen bool, ok bool)
}

// SessionBudget 返回会话的预算摘要。
func (a sessionSourceAdapter) SessionBudget(
	_ context.Context, sessionID string,
) (orchestrate.SessionBudget, bool, error) {
	if a.budgetState == nil {
		return orchestrate.SessionBudget{}, false, nil
	}
	consume, total, open, ok := a.budgetState(sessionID)
	if !ok {
		return orchestrate.SessionBudget{}, false, nil
	}
	// 契约里这两个字段是 uint32（`05` §6.2 SessionSummary）。
	// 溢出时**饱和**而不是回绕：回绕会让一个超大的消耗显示成很小的数，
	// 那是最糟的显示错误（用户会以为预算还很充裕）。
	return orchestrate.SessionBudget{
		TotalTokens: saturateUint32(total),
		Consumed:    saturateUint32(consume),
		CircuitOpen: open,
	}, true, nil
}

// SessionFindings 返回会话的 finding 计数。
//
// 当前**恒为"未提供"**：账本在 Python 侧，Go 进程内没有可计数的集合。
// 这不是 TODO 占位 —— 返回 false 会让 `ListSessions` 把这两个字段留空，
// 页面会显示为未知，而不是谎报 0。
//
// 若将来账本提供计数接口（例如 `LedgerService.CountByState`），
// 在这里接上即可，无需改编排层。
func (a sessionSourceAdapter) SessionFindings(
	_ context.Context, _ string,
) (orchestrate.SessionFindings, bool, error) {
	return orchestrate.SessionFindings{}, false, nil
}

// saturateUint32 把 uint64 饱和到 uint32 上限。
func saturateUint32(v uint64) uint32 {
	const maxUint32 = uint64(^uint32(0))
	if v > maxUint32 {
		return uint32(maxUint32)
	}
	return uint32(v)
}

// 编译期护栏：适配器必须满足编排层的接口（接口变更时此处立刻报错，
// 而不是等到运行时发现 ListSessions 的预算恒为空）。
var _ orchestrate.SessionSource = sessionSourceAdapter{}

// newSessionSourceAdapter 构造适配器。
func newSessionSourceAdapter(
	budgetState func(sessionID string) (consume, total uint64, circuitOpen bool, ok bool),
) sessionSourceAdapter {
	return sessionSourceAdapter{budgetState: budgetState}
}

// describeSessionSource 用于启动日志：如实说明哪些字段是空的。
func describeSessionSource(a sessionSourceAdapter) string {
	if a.budgetState == nil {
		return "session source: budget NOT wired, findings NOT available"
	}
	return "session source: budget wired, findings NOT available (ledger is Python-side)"
}
