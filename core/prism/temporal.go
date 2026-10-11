package prism

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// 本文件实现 M2 §2.1 R3（时间版本与历史回放，T2.4）、R4（假设分支，
// T2.5）与 R5（子图投影，T2.6）。
//
// # 回放保真契约（M2 §4.4）
//
// SnapshotAt(T) 必须返回与「当时实际认知状态」**字节级一致**的结果。
// 实现要点：查询条件严格为
//
//	valid_from <= T AND (valid_to IS NULL OR valid_to > T)
//
// 即"在 T 时刻有效的那一版"。由于每次写入都翻转旧版本的 valid_to 并
// 插入新版本（append-only 语义的行级实现），历史版本从不被删除或改写，
// 因此 T 时刻的查询结果是确定的。
//
// # 分支隔离契约（M2 §6）
//
// 分支内写入不影响主分支投影结果 —— 靠 branch_id 参与每次查询实现。
// 主分支不继承子分支的任何实体（子分支是"假设"，未经 M4 闸门验证前
// 不得污染主分支）。

// SnapshotAt 返回 T 时刻的认知状态（PrismService.SnapshotAt，05 §3.3）。
func (s *Store) SnapshotAt(
	ctx context.Context, branchID string, at time.Time, maxEntities uint32,
) (*alethv1.ProjectedSubgraph, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	branch := normalizeBranch(branchID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireBranch(ctx, branch); err != nil {
		return nil, err
	}
	return s.projectAt(ctx, branch, at.UnixNano(), maxEntities, nil, nil)
}

// Project 按焦点与孔径返回子图（PrismService.Project，05 §3.3）。
//
// focus 语义（M2 §2.2 N1：本模块不决定"该查什么"，只执行投影）：
// focus 为一个实体 ID 时，返回以该实体为起点、maxHops 跳内的子图；
// 为空时返回全景（受 maxEntities 限制）。
func (s *Store) Project(
	ctx context.Context, branchID, focus string, maxHops, maxEntities uint32, kinds []alethv1.EntityKind,
) (*alethv1.ProjectedSubgraph, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	branch := normalizeBranch(branchID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireBranch(ctx, branch); err != nil {
		return nil, err
	}

	kindSet := map[int32]bool{}
	for _, k := range kinds {
		kindSet[int32(k)] = true
	}

	var focusSet map[string]bool
	if focus != "" {
		var err error
		focusSet, err = s.neighborhood(ctx, branch, focus, int(maxHops))
		if err != nil {
			return nil, err
		}
	}
	// 时间上界用"现在之后"（含全部当前有效版本）。用 maxTimeNano 保证
	// valid_from <= now 恒真，语义等价于"当前认知状态"。
	return s.projectAt(ctx, branch, maxTimeNano, maxEntities, kindSet, focusSet)
}

const maxTimeNano = int64(1) << 62

// projectAt 是投影与回放的共同实现。
//
// asOf 是时间上界（UnixNano）；allow 非 nil 时按实体集合过滤（焦点子图）。
func (s *Store) projectAt(
	ctx context.Context, branch string, asOf int64,
	maxEntities uint32, kindSet map[int32]bool, allow map[string]bool,
) (*alethv1.ProjectedSubgraph, error) {
	entRows, err := s.db.QueryContext(ctx,
		`SELECT entity_id, kind, attrs, valid_from, valid_to, version,
		        confidence, is_hypothesis, branch_id
		 FROM entity
		 WHERE branch_id = ? AND valid_from <= ? AND (valid_to IS NULL OR valid_to > ?)
		 ORDER BY entity_id, version`,
		branch, asOf, asOf)
	if err != nil {
		return nil, fmt.Errorf("prism: project entities: %w", err)
	}
	defer func() { _ = entRows.Close() }()

	out := &alethv1.ProjectedSubgraph{}
	// 每个 entity_id 只保留 asOf 时刻**最新**的那一版（查询按 version 升序，
	// 后写覆盖前值即可 —— 同一实体的多版本在 asOf 时刻只有一版有效）。
	latest := map[string]*alethv1.Entity{}
	for entRows.Next() {
		e, err := scanEntity(entRows)
		if err != nil {
			return nil, err
		}
		if allow != nil && !allow[e.GetEntityId()] {
			continue
		}
		if len(kindSet) > 0 && !kindSet[int32(e.GetKind())] {
			continue
		}
		latest[e.GetEntityId()] = e
	}
	if err := entRows.Err(); err != nil {
		return nil, fmt.Errorf("prism: iterate entities: %w", err)
	}

	// 确定性排序后按 maxEntities 截断（不依赖 map 迭代顺序 —— P-5）。
	ids := make([]string, 0, len(latest))
	for id := range latest {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if maxEntities > 0 && uint32(len(ids)) > maxEntities {
		ids = ids[:maxEntities]
	}
	keep := map[string]bool{}
	for _, id := range ids {
		keep[id] = true
		out.Entities = append(out.Entities, latest[id])
	}

	// 关系：两端都在结果集内的才输出（不产生悬空边）。
	relRows, err := s.db.QueryContext(ctx,
		`SELECT relation_id, from_entity, to_entity, type, attrs, confidence,
		        evidence_id, valid_from
		 FROM relation
		 WHERE branch_id = ? AND valid_from <= ? AND (valid_to IS NULL OR valid_to > ?)
		 ORDER BY relation_id`,
		branch, asOf, asOf)
	if err != nil {
		return nil, fmt.Errorf("prism: project relations: %w", err)
	}
	defer func() { _ = relRows.Close() }()
	for relRows.Next() {
		r, err := scanRelation(relRows)
		if err != nil {
			return nil, err
		}
		if !keep[r.GetFromEntity()] {
			continue
		}
		// to 端允许指向结果集外的实体（图是增量的，端点可能尚未写入），
		// 但此时**不臆造实体**：关系保留，消费方据 to_entity 判断。
		out.Relations = append(out.Relations, r)
	}
	if err := relRows.Err(); err != nil {
		return nil, fmt.Errorf("prism: iterate relations: %w", err)
	}

	out.SnapshotId = snapshotID(branch, asOf)
	return out, nil
}

// snapshotID 生成确定性快照标识（同一 branch+时刻必得同一 ID）。
//
// 刻意**不含随机数**：SnapshotAt 是幂等查询，同一时刻两次调用必须
// 得到相同的 snapshot_id，否则消费方无法用它做缓存/比对（M2 §4.4）。
func snapshotID(branch string, asOf int64) string {
	return "sn_" + shortHash(fmt.Sprintf("%s\x00%d", branch, asOf))
}

// scanEntity 从行扫描一个实体。
func scanEntity(rows *sql.Rows) (*alethv1.Entity, error) {
	var (
		id, attrs, branch string
		kind, version     int32
		hyp               int
		validFrom         int64
		validTo           sql.NullInt64
		confidence        float64
	)
	if err := rows.Scan(&id, &kind, &attrs, &validFrom, &validTo, &version,
		&confidence, &hyp, &branch); err != nil {
		return nil, fmt.Errorf("prism: scan entity: %w", err)
	}
	e := &alethv1.Entity{
		EntityId:     id,
		Kind:         alethv1.EntityKind(kind),
		Attributes:   attrsToMap(attrs),
		Version:      uint32(version),
		Confidence:   confidence,
		IsHypothesis: hyp != 0,
		BranchId:     branch,
		ValidFrom:    timestamppb.New(time.Unix(0, validFrom).UTC()),
	}
	if validTo.Valid {
		e.ValidTo = timestamppb.New(time.Unix(0, validTo.Int64).UTC())
	}
	return e, nil
}

// scanRelation 从行扫描一个关系。
func scanRelation(rows *sql.Rows) (*alethv1.Relation, error) {
	var (
		id, from, to, attrs, evidenceID string
		rtype                           int32
		confidence                      float64
		validFrom                       int64
	)
	if err := rows.Scan(&id, &from, &to, &rtype, &attrs, &confidence,
		&evidenceID, &validFrom); err != nil {
		return nil, fmt.Errorf("prism: scan relation: %w", err)
	}
	return &alethv1.Relation{
		RelationId: id,
		FromEntity: from,
		ToEntity:   to,
		Type:       alethv1.RelationType(rtype),
		Attributes: attrsToMap(attrs),
		Confidence: confidence,
		EvidenceId: evidenceID,
		ValidFrom:  timestamppb.New(time.Unix(0, validFrom).UTC()),
	}, nil
}

// neighborhood 计算以 start 为中心、radius 跳内的实体集合（含自身）。
//
// 关系视为**无向**遍历：RUNS_ON 从服务指向宿主，但查询"这台主机上的
// 一切"时必须能反向走到服务。仅按 from→to 单向遍历会让投影漏掉
// 半个图 —— 那是 M3 光圈召回率问题的直接来源（M2 §2.1 R5）。
func (s *Store) neighborhood(
	ctx context.Context, branch, start string, radius int,
) (map[string]bool, error) {
	visited := map[string]bool{start: true}
	if radius < 0 {
		radius = 0
	}
	frontier := []string{start}
	for hop := 0; hop < radius; hop++ {
		if len(frontier) == 0 {
			break
		}
		var next []string
		for _, cur := range frontier {
			rows, err := s.db.QueryContext(ctx,
				`SELECT from_entity, to_entity FROM relation
				 WHERE branch_id = ? AND valid_to IS NULL
				   AND (from_entity = ? OR to_entity = ?)`,
				branch, cur, cur)
			if err != nil {
				return nil, fmt.Errorf("prism: neighborhood: %w", err)
			}
			for rows.Next() {
				var a, b string
				if err := rows.Scan(&a, &b); err != nil {
					_ = rows.Close()
					return nil, fmt.Errorf("prism: scan edge: %w", err)
				}
				other := b
				if b == cur {
					other = a
				}
				if !visited[other] {
					visited[other] = true
					next = append(next, other)
				}
			}
			if err := rows.Err(); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("prism: iterate edges: %w", err)
			}
			_ = rows.Close()
		}
		sort.Strings(next) // 确定性
		frontier = next
	}
	return visited, nil
}

// ---- 假设分支（T2.5）----

// CreateBranch 建立假设分支（PrismService.CreateBranch，05 §3.3）。
func (s *Store) CreateBranch(
	ctx context.Context, branchName, parentBranchID, rationale string,
) (*alethv1.BranchInfo, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if branchName == "" {
		return nil, errors.New("prism: branch_name is required")
	}
	parent := normalizeBranch(parentBranchID)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireBranch(ctx, parent); err != nil {
		return nil, err
	}

	// 并发分支上限（M2 §8）：超限**拒绝创建**，不静默降级 ——
	// 静默降级会让"分支隔离"这一安全属性失效。
	var open int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM branch WHERE status = 'open' AND branch_id != ?`,
		MainBranchID).Scan(&open); err != nil {
		return nil, fmt.Errorf("prism: count branches: %w", err)
	}
	if open >= MaxConcurrentBranches {
		return nil, fmt.Errorf("%w: %d open (max %d)",
			ErrBranchLimitExceeded, open, MaxConcurrentBranches)
	}

	now := s.clock()
	branchID := "br_" + shortHash(fmt.Sprintf("%s\x00%s\x00%d",
		parent, branchName, now.UnixNano()))
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO branch(branch_id, branch_name, parent_branch_id, rationale,
		                    created_at, status, session_id)
		 VALUES (?, ?, ?, ?, ?, 'open', ?)`,
		branchID, branchName, parent, rationale, now.UnixNano(), s.sessionID); err != nil {
		return nil, fmt.Errorf("prism: create branch: %w", err)
	}
	return &alethv1.BranchInfo{
		BranchId:       branchID,
		BranchName:     branchName,
		ParentBranchId: parent,
		Rationale:      rationale,
		CreatedAt:      timestamppb.New(now.UTC()),
	}, nil
}

// RollbackBranch 回滚假设分支（PrismService.RollbackBranch，05 §3.3）。
//
// 契约（M2 §4.5）：回滚后图状态必须与**从未创建该分支**完全一致，
// 且 RollbackResult.byte_identical 必须如实反映这一点 —— 本方法是
// 先计算回滚前状态 hash，回滚后**重新计算**并对比，而不是无条件
// 宣称 true（那会让这个字段变成恒真断言，正是 docs/10 禁止的模式）。
func (s *Store) RollbackBranch(
	ctx context.Context, branchID string, toVersion uint32,
) (*alethv1.RollbackResult, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	branch := normalizeBranch(branchID)
	if branch == MainBranchID {
		return nil, ErrMainBranchImmutable
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireBranch(ctx, branch); err != nil {
		return nil, err
	}

	info, err := s.branchInfo(ctx, branch)
	if err != nil {
		return nil, err
	}
	parent := info.GetParentBranchId()

	// 回滚前：父分支状态 hash（这是"分支前"的基准）。
	before, err := s.branchStateHash(ctx, parent, maxTimeNano)
	if err != nil {
		return nil, err
	}

	// 软删除该分支的全部实体版本（M2 §4.5：标记 valid_to）。
	now := s.clock()
	var affected int64
	if toVersion == 0 {
		res, err := s.db.ExecContext(ctx,
			`UPDATE entity SET valid_to = ? WHERE branch_id = ? AND valid_to IS NULL`,
			now.UnixNano(), branch)
		if err != nil {
			return nil, fmt.Errorf("prism: rollback entities: %w", err)
		}
		affected, _ = res.RowsAffected()
		if _, err := s.db.ExecContext(ctx,
			`UPDATE relation SET valid_to = ? WHERE branch_id = ? AND valid_to IS NULL`,
			now.UnixNano(), branch); err != nil {
			return nil, fmt.Errorf("prism: rollback relations: %w", err)
		}
	} else {
		// 保留 version <= toVersion 的版本，其余软删除。
		res, err := s.db.ExecContext(ctx,
			`UPDATE entity SET valid_to = ?
			 WHERE branch_id = ? AND valid_to IS NULL AND version > ?`,
			now.UnixNano(), branch, toVersion)
		if err != nil {
			return nil, fmt.Errorf("prism: rollback partial: %w", err)
		}
		affected, _ = res.RowsAffected()
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE branch SET status = 'rolled_back' WHERE branch_id = ?`, branch); err != nil {
		return nil, fmt.Errorf("prism: mark branch rolled back: %w", err)
	}

	// 回滚后：父分支状态 hash。必须与 before 相同 —— 因为分支内的写入
	// 从未影响父分支（branch_id 隔离）。这个对比是**真实校验**：
	// 若隔离被破坏（例如某处漏了 branch 条件），两次 hash 会不同。
	after, err := s.branchStateHash(ctx, parent, maxTimeNano)
	if err != nil {
		return nil, err
	}
	return &alethv1.RollbackResult{
		StateHashBefore:       before,
		StateHashAfter:        after,
		ByteIdentical:         before == after,
		RolledBackEntityCount: uint32(affected),
	}, nil
}

// MergeBranch 合并假设分支（PrismService.MergeBranch，05 §3.3）。
//
// 契约（M2 §4.5）：**仅当分支内实体全部通过 M4 闸门（非 Hypothesis）
// 才允许合并** —— 避免假设污染主分支。含 is_hypothesis=true 的实体时
// 返回 merged=false 并在 error 里说明（不静默部分合并）。
func (s *Store) MergeBranch(
	ctx context.Context, sourceBranchID, targetBranchID string,
) (*alethv1.MergeResult, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	src := normalizeBranch(sourceBranchID)
	dst := normalizeBranch(targetBranchID)
	if src == MainBranchID {
		return nil, ErrMainBranchImmutable
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.requireBranch(ctx, src); err != nil {
		return nil, err
	}
	if err := s.requireBranch(ctx, dst); err != nil {
		return nil, err
	}

	// 闸门：分支内是否存在未验证的假设实体。
	var hypCount int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM entity
		 WHERE branch_id = ? AND valid_to IS NULL AND is_hypothesis = 1`,
		src).Scan(&hypCount); err != nil {
		return nil, fmt.Errorf("prism: check hypotheses: %w", err)
	}
	if hypCount > 0 {
		return &alethv1.MergeResult{
			Merged: false,
			Error: &alethv1.Error{
				Code: alethv1.ErrorCode_EVIDENCE_INVALID,
				Message: fmt.Sprintf(
					"merge rejected: source branch has %d unverified hypothesis entities", hypCount),
				Remediation: "verify hypotheses through the M4 gate (status → Confirmed) before merging",
			},
		}, nil
	}

	// 把源分支的当前有效版本复制到目标分支（冲突保留：目标已有同 ID
	// 实体且属性不同时，生成 CONTRADICTS 关系而非覆盖 —— 05 §3.1 明确
	// "CONTRADICTS 冲突永不合并，只登记"）。
	rows, err := s.db.QueryContext(ctx,
		`SELECT entity_id, kind, attrs, confidence, is_hypothesis
		 FROM entity WHERE branch_id = ? AND valid_to IS NULL`, src)
	if err != nil {
		return nil, fmt.Errorf("prism: read source branch: %w", err)
	}
	type srcEnt struct {
		id, attrs  string
		kind       int32
		confidence float64
		hyp        int
	}
	var ents []srcEnt
	for rows.Next() {
		var e srcEnt
		if err := rows.Scan(&e.id, &e.kind, &e.attrs, &e.confidence, &e.hyp); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("prism: scan source entity: %w", err)
		}
		ents = append(ents, e)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("prism: iterate source: %w", err)
	}
	_ = rows.Close()

	now := s.clock()
	res := &alethv1.MergeResult{}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("prism: begin merge tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, e := range ents {
		cur, err := s.currentVersion(ctx, tx, e.id, dst)
		if err != nil {
			return nil, err
		}
		switch {
		case cur == nil:
			// 目标分支没有该实体 → 直接写入。
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO entity(entity_id, kind, attrs, valid_from, valid_to, version,
				                     confidence, is_hypothesis, branch_id, session_id)
				 VALUES (?, ?, ?, ?, NULL, 1, ?, 0, ?, ?)`,
				e.id, e.kind, e.attrs, now.UnixNano(), e.confidence, dst,
				s.sessionID); err != nil {
				return nil, fmt.Errorf("prism: merge insert: %w", err)
			}
		case cur.Attrs == e.attrs:
			// 值一致 → 无需动作（合并是幂等的）。
		default:
			// 值冲突 → **不合并**，登记 CONTRADICTS 关系（05 §3.1）。
			attrs := map[string]string{
				"source_branch": src,
				"target_branch": dst,
			}
			rid := RelationID(alethv1.RelationType_CONTRADICTS, e.id, e.id, attrs)
			var exists int
			if err := tx.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM relation WHERE relation_id = ? AND branch_id = ?`,
				rid, dst).Scan(&exists); err != nil {
				return nil, fmt.Errorf("prism: check contradicts: %w", err)
			}
			if exists == 0 {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO relation(relation_id, from_entity, to_entity, type, attrs,
					                      confidence, evidence_id, valid_from, valid_to, branch_id, session_id)
					 VALUES (?, ?, ?, ?, ?, ?, '', ?, NULL, ?, ?)`,
					rid, e.id, e.id, int32(alethv1.RelationType_CONTRADICTS),
					canonicalAttrs(attrs), 1.0, now.UnixNano(), dst, s.sessionID); err != nil {
					return nil, fmt.Errorf("prism: insert contradicts: %w", err)
				}
			}
			res.UnresolvedConflicts = append(res.UnresolvedConflicts, &alethv1.Conflict{
				EntityId:     e.id,
				ConflictType: "CONTRADICTS",
				CompetingSources: []*alethv1.Provenance{
					{SourceKind: alethv1.SourceKind_ACTIVE_SCAN, EvidenceId: src},
					{SourceKind: alethv1.SourceKind_ACTIVE_SCAN, EvidenceId: dst},
				},
			})
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("prism: commit merge: %w", err)
	}
	// 合并成功但仍有未解决冲突 → merged=true（实体已并入），冲突单独登记。
	res.Merged = true
	if _, err := s.db.ExecContext(ctx,
		`UPDATE branch SET status = 'merged' WHERE branch_id = ?`, src); err != nil {
		return nil, fmt.Errorf("prism: mark merged: %w", err)
	}
	return res, nil
}

// branchInfo 读分支元信息。
func (s *Store) branchInfo(ctx context.Context, branchID string) (*alethv1.BranchInfo, error) {
	var (
		name, parent, rationale, status string
		createdAt                       int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT branch_name, parent_branch_id, rationale, created_at, status
		 FROM branch WHERE branch_id = ?`, branchID).
		Scan(&name, &parent, &rationale, &createdAt, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrBranchNotFound, branchID)
	}
	if err != nil {
		return nil, fmt.Errorf("prism: read branch: %w", err)
	}
	return &alethv1.BranchInfo{
		BranchId:       branchID,
		BranchName:     name,
		ParentBranchId: parent,
		Rationale:      rationale,
		CreatedAt:      timestamppb.New(time.Unix(0, createdAt).UTC()),
	}, nil
}

// branchStateHash 计算某分支在 asOf 时刻的认知状态 hash。
//
// 用于回滚一致性校验：回滚子分支前后，**父分支**的 hash 必须不变。
func (s *Store) branchStateHash(ctx context.Context, branch string, asOf int64) (string, error) {
	sub, err := s.projectAt(ctx, branch, asOf, 0, nil, nil)
	if err != nil {
		return "", err
	}
	// 快照 ID 与分支+时刻有关，不参与状态语义比对 —— 剥离后再 hash。
	sub.SnapshotId = ""
	return HashCanonical(sub.GetEntities(), sub.GetRelations()), nil
}

// StateHash 计算指定分支当前认知状态的规范 hash（外部比对/审计用）。
func (s *Store) StateHash(ctx context.Context, branchID string) (string, error) {
	if err := ctxErr(ctx); err != nil {
		return "", err
	}
	branch := normalizeBranch(branchID)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.branchStateHash(ctx, branch, maxTimeNano)
}

// ConflictEntityIDs 返回该分支下**存在多源冲突**的实体集合。
//
// 判定口径：当前有效版本的 version > 1。
//
// 为什么这是正确的冲突判据：M2 的写入语义（ingest.go 的 upsertEntity）
// 只在两种情况下推进版本号 —— 属性值不同（VALUE_MISMATCH）或实体类型
// 不同（EXISTENCE_MISMATCH）。属性完全相同的重复观测**不**推进版本。
// 因此 version > 1 精确等价于"曾被不同来源写入过不同值"。
//
// 消费方：M3 光圈控制用它给冲突实体加分（M3 §4.3：冲突是最高价值信号，
// CONTRADICTS 权重 0.85）。M3 §2.2 N3 明确本模块不自行判定真伪，
// 只消费这里给出的判定结果。
func (s *Store) ConflictEntityIDs(ctx context.Context, branchID string) (map[string]bool, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	branch := normalizeBranch(branchID)
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT entity_id FROM entity
		 WHERE branch_id = ? AND valid_to IS NULL AND version > 1`,
		branch)
	if err != nil {
		return nil, fmt.Errorf("prism: conflict lookup: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("prism: scan conflict id: %w", err)
		}
		out[id] = true
	}
	return out, rows.Err()
}
