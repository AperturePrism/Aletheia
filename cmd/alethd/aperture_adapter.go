// M2（core/prism）→ M3（core/aperture）的依赖适配。
//
// 与 cmd/alethd/adapters.go 里 Scope/Gateway 的适配同一做法：
// M3 定义它需要的接口（GraphSource / ConflictSource），本文件把
// M2 的具体实现接上去。**适配层零决策** —— 它只搬运数据，
// 任何语义判断都留在各自模块内。
package main

import (
	"context"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"github.com/AperturePrism/aleth/core/prism"
)

// prismGraphAdapter 把 prism.Store 适配为 aperture.GraphSource。
type prismGraphAdapter struct {
	store *prism.Store
}

// Project 转发到 M2 的投影（M3 §2.2 N1：M3 不做图遍历实现）。
func (a prismGraphAdapter) Project(
	ctx context.Context, branchID, focus string, maxHops, maxEntities uint32,
	kinds []alethv1.EntityKind,
) (*alethv1.ProjectedSubgraph, error) {
	return a.store.Project(ctx, branchID, focus, maxHops, maxEntities, kinds)
}

// prismConflictAdapter 把 M2 的冲突查询适配为 aperture.ConflictSource。
type prismConflictAdapter struct {
	store *prism.Store
}

// ConflictEntityIDs 返回存在多版本的实体集合。
//
// 冲突判定口径（与 M2 §4.3 的多源写入语义对应）：同一 entity_id 在该
// 分支下存在 **version > 1** 的当前有效版本，说明该实体的属性曾被
// 不同来源写入过不同值 —— 那就是冲突。
//
// 为什么不用"同时存在多个 valid_to IS NULL 的版本"判定：M2 的写入语义
// 保证任一时刻只有一个当前有效版本（旧版本翻 valid_to），因此"多版本
// 并存"永远不会发生。冲突的事实记录在 version 号上。
func (a prismConflictAdapter) ConflictEntityIDs(
	ctx context.Context, branchID string,
) (map[string]bool, error) {
	return a.store.ConflictEntityIDs(ctx, branchID)
}
