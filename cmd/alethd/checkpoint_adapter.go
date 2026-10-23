// M2（core/prism）+ M6（core/governor）→ M5（core/orchestrate）的
// 检查点状态适配。
//
// 与 cmd/alethd/aperture_adapter.go 同一做法：orchestrate 定义它需要的
// 接口（SnapshotSource），本文件把 M2 与 M6 的具体实现接上去。
// **适配层零决策** —— 它只搬运数据。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/AperturePrism/aleth/core/orchestrate"
	"github.com/AperturePrism/aleth/core/prism"
)

// checkpointSnapshotAdapter 为检查点提供跨模块状态快照（05 §6.2 的
// `graph_version` 与 `budget_snapshot_hash`）。
//
// # 为什么需要它
//
// I6 交付时这两个字段是空的（`BudgetHash: ""` 带注释"I6 接线预留"）。
// 空值让检查点无法与其他模块的状态对齐 —— 那正是"rewind 后证据一致"
// 需要比对的东西（04 §I6 DoD③）。
type checkpointSnapshotAdapter struct {
	store *prism.Store
	// budgetState 返回当前预算状态（sessionID → 摘要）。
	// nil 表示未接线 —— 此时预算哈希留空并告警。
	budgetState func(sessionID string) (consume, total uint64, circuitOpen bool, ok bool)
}

// GraphVersion 返回心智地图当前认知状态的哈希。
//
// 实现：用 M2 的 `StateHash`（`core/prism` 已有的能力）—— 它就是
// "当前认知状态的规范哈希"，正是检查点需要的"图版本"。
//
// 刻意**不**新建一个版本号计数器：那会引入第二套"版本"概念，
// 而 M2 的 `StateHash` 已经是内容的确定性函数（相同状态必得相同哈希）。
func (a checkpointSnapshotAdapter) GraphVersion(ctx context.Context, sessionID string) (string, error) {
	if a.store == nil {
		return "", fmt.Errorf("prism store not wired")
	}
	// 主分支的当前状态 —— I6 的检查点对应会话的主分支。
	h, err := a.store.StateHash(ctx, prism.MainBranchID)
	if err != nil {
		return "", err
	}
	return h, nil
}

// BudgetSnapshotHash 返回预算状态的哈希。
//
// 用哈希而非完整状态：检查点需要的是"能判定两次快照是否相同"，
// 而不是可回滚的预算副本（**预算不回滚** —— 与账本同源的设计，
// 见 modules/M5 §4.3）。
func (a checkpointSnapshotAdapter) BudgetSnapshotHash(ctx context.Context, sessionID string) (string, error) {
	_ = ctx
	if a.budgetState == nil {
		return "", fmt.Errorf("budget source not wired")
	}
	consume, total, open, ok := a.budgetState(sessionID)
	if !ok {
		return "", fmt.Errorf("no budget state for session %q", sessionID)
	}
	// 确定性序列化：字段顺序固定，因此相同状态必得相同哈希。
	raw := fmt.Sprintf("consume=%d;total=%d;open=%t", consume, total, open)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16]), nil
}

// newCheckpointSnapshotAdapter 装配适配器。
func newCheckpointSnapshotAdapter(
	store *prism.Store,
	budget func(sessionID string) (uint64, uint64, bool, bool),
) orchestrate.SnapshotSource {
	return checkpointSnapshotAdapter{store: store, budgetState: budget}
}

// budgetStateFromGovernor 从预算总额与已消耗计算预算摘要。
//
// 传入的是**当前值**（不持有 Governor 实例）：GovernorService 内部按
// 会话管理账本，这里只需要"某个会话此刻的消耗与总额"。
func budgetStateFromGovernor(
	sessionID string, budgetTotal uint64, consumed uint64, open bool,
) (uint64, uint64, bool, bool) {
	return consumed, budgetTotal, open, budgetTotal > 0
}

// 编译期护栏：适配器必须满足 orchestrate 的接口。
var _ orchestrate.SnapshotSource = checkpointSnapshotAdapter{}
