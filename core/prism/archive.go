// 归档降采样与 downlink 恢复（modules/M2 §4.6，T2.7）。
//
// M2 §4.6 的核心主张：**归档不是有损摘要** —— 与 chain summarization
// 的本质区别是「可下钻」：聚合节点只承载计数/时间范围/属性值域，
// 单条明细沿 downlink 指针恢复，恢复结果与归档前一致（DoD⑤，
// 一致性由 TestArchiveRestoreRoundTrip 字节级锁定）。
//
// 与实体表的关系：归档节点存独立的 archive_node 表（批量迁移时
// 建好），**不新增 EntityKind** —— 05 §3.1 的 7 类枚举是契约冻结面，
// 归档聚合体不是发现物，不该污染实体类型系统。
//
// 降采样判据：当前有效、main 分支、最新版本 valid_from 早于
// olderThan 的实体 —— 按 (kind, entity_id) 逐实体聚合，同 kind 的
// 陈旧实体合并为一个归档节点（M2 §4.6 的「聚合」语义）。
package prism

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// ArchiveStale 把 last-write 早于 olderThan 的 main 分支实体降采样为
// 归档节点（同 kind 一个节点），并把明细软删除（valid_to := now）。
// 返回归档节点 ID 与被归档的实体 ID（供测试与审计）。
//
// 恢复路径：RestoreArchive(archiveID) —— 沿 downlinks 把明细的
// valid_to 还原为 NULL，明细与归档前一致，归档节点行删除。
func (s *Store) ArchiveStale(ctx context.Context, olderThan time.Time) (string, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()

	// 候选：当前有效、main 分支、最新版本的 valid_from 早于 olderThan。
	rows, err := s.db.QueryContext(ctx,
		`SELECT e.entity_id, e.kind, e.attrs, e.valid_from, e.confidence
		 FROM entity e
		 JOIN (SELECT entity_id, MAX(valid_from) AS mf
		       FROM entity WHERE valid_to IS NULL AND branch_id = ? AND is_hypothesis = 0
		       GROUP BY entity_id) cur
		   ON cur.entity_id = e.entity_id AND cur.mf = e.valid_from
		 WHERE e.valid_to IS NULL AND e.valid_from < ? AND e.branch_id = ?`,
		MainBranchID, olderThan.UnixNano(), MainBranchID) // UnixNano：与写入侧同构
	if err != nil {
		return "", nil, fmt.Errorf("prism: archive scan: %w", err)
	}
	type cand struct {
		id         string
		kind       int64
		attrs      string
		validFrom  time.Time
		confidence float64
	}
	var cands []cand
	for rows.Next() {
		var c cand
		var vf int64
		if err := rows.Scan(&c.id, &c.kind, &c.attrs, &vf, &c.confidence); err != nil {
			rows.Close()
			return "", nil, fmt.Errorf("prism: archive scan row: %w", err)
		}
		c.validFrom = time.Unix(0, vf)
		cands = append(cands, c)
	}
	rows.Close()
	if len(cands) == 0 {
		return "", nil, nil // 无陈旧实体：空归档（不是错误）
	}

	// 按 kind 分组：同 kind 一个归档节点（M2 §4.6「聚合」）。
	byKind := map[int64][]cand{}
	kinds := []int64{}
	for _, c := range cands {
		if _, ok := byKind[c.kind]; !ok {
			kinds = append(kinds, c.kind)
		}
		byKind[c.kind] = append(byKind[c.kind], c)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] }) // 确定性

	var firstArchive string
	var allArchived []string
	for _, kind := range kinds {
		group := byKind[kind]
		// 属性值域：聚合节点保留出现过的属性键（M2 §4.6「属性值域」）。
		attrKeys := map[string]bool{}
		minVF, maxVF := group[0].validFrom, group[0].validFrom
		for _, c := range group {
			var attrs map[string]string
			if err := json.Unmarshal([]byte(c.attrs), &attrs); err != nil {
				return "", nil, fmt.Errorf("prism: archive attrs of %q: %w", c.id, err)
			}
			for k := range attrs {
				attrKeys[k] = true
			}
			if c.validFrom.Before(minVF) {
				minVF = c.validFrom
			}
			if c.validFrom.After(maxVF) {
				maxVF = c.validFrom
			}
		}
		keys := make([]string, 0, len(attrKeys))
		for k := range attrKeys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		aggregate, _ := json.Marshal(map[string]any{
			"count":      len(group),
			"valid_from": minVF.Format(time.RFC3339Nano),
			"valid_to":   maxVF.Format(time.RFC3339Nano),
			"attr_keys":  keys,
			"older_than": olderThan.Format(time.RFC3339Nano),
		})

		archiveID := "arch_" + archiveHash(kind, aggregate)
		ids := make([]string, 0, len(group))
		for _, c := range group {
			ids = append(ids, c.id)
		}
		downlinks, _ := json.Marshal(ids)

		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO archive_node (archive_id, kind, aggregate, downlinks, created_at, branch_id)
			 VALUES (?, ?, ?, ?, ?, 'main')`,
			archiveID, kind, string(aggregate), string(downlinks), now.UnixNano(), MainBranchID); err != nil {
			return "", nil, fmt.Errorf("prism: insert archive node: %w", err)
		}
		// 明细软删除（可恢复 —— downlink 是唯一真相，不删版本行）。
		for _, id := range ids {
			if _, err := s.db.ExecContext(ctx,
				`UPDATE entity SET valid_to = ? WHERE entity_id = ? AND valid_to IS NULL`,
				now.UnixNano(), id); err != nil {
				return "", nil, fmt.Errorf("prism: archive soft-delete %q: %w", id, err)
			}
		}
		if firstArchive == "" {
			firstArchive = archiveID
		}
		allArchived = append(allArchived, ids...)
	}
	return firstArchive, allArchived, nil
}

// RestoreArchive 沿 downlink 恢复归档明细（M2 §4.6 DoD⑤）：
// 被归档实体的 valid_to 还原为 NULL（归档前状态），归档节点行删除。
// 恢复后 SnapshotAt 的指纹与归档前一致 —— 由测试字节级锁定。
func (s *Store) RestoreArchive(ctx context.Context, archiveID string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var kind int64
	var downlinks string
	err := s.db.QueryRowContext(ctx,
		`SELECT kind, downlinks FROM archive_node WHERE archive_id = ?`, archiveID).
		Scan(&kind, &downlinks)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("prism: archive %q not found", archiveID)
		}
		return nil, fmt.Errorf("prism: load archive %q: %w", archiveID, err)
	}
	var ids []string
	if err := json.Unmarshal([]byte(downlinks), &ids); err != nil {
		return nil, fmt.Errorf("prism: archive %q downlinks: %w", archiveID, err)
	}
	for _, id := range ids {
		// 归档时被置 valid_to 的正是归档时点的当前版本 —— 还原为有效。
		if _, err := s.db.ExecContext(ctx,
			`UPDATE entity SET valid_to = NULL
			  WHERE entity_id = ? AND valid_to = (SELECT MAX(valid_to) FROM entity WHERE entity_id = ?)`,
			id, id); err != nil {
			return nil, fmt.Errorf("prism: restore %q: %w", id, err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM archive_node WHERE archive_id = ?`, archiveID); err != nil {
		return nil, fmt.Errorf("prism: delete archive node %q: %w", archiveID, err)
	}
	return ids, nil
}

// ListArchives 返回现存归档节点 ID（审计/运维入口，确定性排序）。
func (s *Store) ListArchives(ctx context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.QueryContext(ctx, `SELECT archive_id FROM archive_node ORDER BY archive_id`)
	if err != nil {
		return nil, fmt.Errorf("prism: list archives: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// archiveHash 是归档节点 ID 的确定性哈希（同 batch = 同 ID，幂等归档）。
func archiveHash(kind int64, aggregate []byte) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("aleth/archive/v1|%d|%s", kind, aggregate)))
	return hex.EncodeToString(sum[:12])
}
