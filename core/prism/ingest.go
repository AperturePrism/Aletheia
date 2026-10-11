package prism

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// 本文件实现 M2 §2.1 R2（多源写入与冲突保留，T2.3）与
// R3（时间版本管理，T2.4）。
//
// # 不可协商的写入语义
//
//  1. **不覆盖、不合并**（M2 §4.3）：同一实体的不同来源给出不同属性值时，
//     各自成为**新版本**，全部保留。旧版本置 valid_to，新版本 valid_from。
//     这是对 D12「级联失败」的结构性回应 —— 侦察漏掉一个服务不再导致
//     下游永不测试它。
//  2. **时间由 Store 赋值**：调用方自带的 valid_from 被忽略（M2 §8：
//     禁止应用层自行生成时间戳）。与证据账本拒绝 caller-provided
//     created_at 同一理由 —— 时间线必须由受信组件书写。
//  3. **幂等**：相同 spectrum_id 重复 Ingest 无副作用（M2 §6 测试要求）。
//  4. **属性值完全相同时不产生新版本**：重复观测同一事实不是冲突，
//     否则每次扫描都会让版本号膨胀。此时只追加 provenance（多源审计），
//     这正是"多源一致性"要求的落点：全部来源可追溯。

// Ingest 写入一条光谱（PrismService.Ingest 的实现，05 §3.3），写入主分支。
//
// 分支语义：EvidenceSpectrum 是 [frozen] 消息、无 branch 字段，因此
// 契约上的 Ingest 只能落主分支。假设分支的写入走 IngestInto（见下），
// 由 L4/L5 在假设探索期间显式指定 —— 这保持了契约不动的约束
// （docs/09 R1：不得改 05 契约）。
func (s *Store) Ingest(ctx context.Context, sp *alethv1.EvidenceSpectrum) (*alethv1.IngestResult, error) {
	return s.IngestInto(ctx, sp, MainBranchID)
}

// IngestInto 把光谱写入指定分支（假设探索用）。
// 分支不存在时返回 ErrBranchNotFound（不静默落到主分支 ——
// 那会让"分支隔离"这一安全属性失效）。
func (s *Store) IngestInto(
	ctx context.Context, sp *alethv1.EvidenceSpectrum, branchID string,
) (*alethv1.IngestResult, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if sp == nil {
		return nil, errors.New("prism: nil spectrum")
	}
	if sp.GetSpectrumId() == "" {
		return nil, errors.New("prism: spectrum_id is required (idempotency key)")
	}
	branch := normalizeBranch(branchID)

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.requireBranch(ctx, branch); err != nil {
		return nil, err
	}

	// 幂等：相同 spectrum_id 重复写入直接返回空结果（零副作用）。
	// 契约只要求"无副作用"，重复投递的调用方不关心首次的 ID 列表。
	var seen int
	err := s.db.QueryRowContext(ctx,
		`SELECT entity_count FROM ingest_log WHERE spectrum_id = ?`,
		sp.GetSpectrumId()).Scan(&seen)
	if err == nil {
		return &alethv1.IngestResult{}, nil // 已处理过，零副作用
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("prism: idempotency check: %w", err)
	}

	dec := Decompose(sp)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("prism: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res := &alethv1.IngestResult{}
	now := s.clock()

	// 假设分支内的实体默认标记 is_hypothesis=true（M2 §4.5：
	// 分支写入的实体全部带 is_hypothesis）—— 这是 RollbackBranch 与
	// MergeBranch 判定的依据。实体自带 is_hypothesis 时尊重其值。
	for _, e := range dec.Entities {
		if branch != MainBranchID {
			e.IsHypothesis = true
		}
		created, conflict, err := s.upsertEntity(ctx, tx, e, branch, now)
		if err != nil {
			return nil, err
		}
		if created {
			res.CreatedEntityIds = append(res.CreatedEntityIds, e.GetEntityId())
		} else {
			res.UpdatedEntityIds = append(res.UpdatedEntityIds, e.GetEntityId())
		}
		if conflict != nil {
			res.Conflicts = append(res.Conflicts, conflict)
		}
	}

	// 关系：以「已存在的端点」为准写入。指向未入库实体的关系**不臆造实体**，
	// 但关系本身仍写入（其 from 端有证据支撑）—— 端点实体在后续光谱
	// 到达时自然连上（图是增量的）。
	for _, r := range dec.Relations {
		if err := s.insertRelation(ctx, tx, r, branch, now); err != nil {
			return nil, err
		}
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO ingest_log(spectrum_id, ingested_at, entity_count) VALUES (?, ?, ?)`,
		sp.GetSpectrumId(), now.UnixNano(), len(dec.Entities)); err != nil {
		return nil, fmt.Errorf("prism: record ingest: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("prism: commit ingest: %w", err)
	}
	return res, nil
}

// requireBranch 确认分支存在（fail-closed：不接受未知分支）。
func (s *Store) requireBranch(ctx context.Context, branch string) error {
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM branch WHERE branch_id = ?`, branch).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %s", ErrBranchNotFound, branch)
	}
	if err != nil {
		return fmt.Errorf("prism: check branch: %w", err)
	}
	return nil
}

// upsertEntity 写入一个实体版本。
//
// 语义（M2 §4.3 的核心）：
//   - 该实体在该分支**不存在** → 插入 version=1，返回 created=true；
//   - 已存在且**属性完全相同** → 不产生新版本，只追加 provenance
//     （多源审计），返回 created=false 且无冲突；
//   - 已存在且**属性不同** → 旧版本置 valid_to，插入 version=n+1，
//     并生成 Conflict{VALUE_MISMATCH}（保留多版本，不合并）。
func (s *Store) upsertEntity(
	ctx context.Context, tx *sql.Tx, e *alethv1.Entity, branch string, now time.Time,
) (created bool, conflict *alethv1.Conflict, err error) {
	cur, err := s.currentVersion(ctx, tx, e.GetEntityId(), branch)
	if err != nil {
		return false, nil, err
	}
	attrsJSON := canonicalAttrs(e.GetAttributes())

	if cur == nil {
		if err := s.insertEntityVersion(ctx, tx, e, branch, now, 1, attrsJSON); err != nil {
			return false, nil, err
		}
		if err := s.insertProvenance(ctx, tx, e, branch, 1); err != nil {
			return false, nil, err
		}
		return true, nil, nil
	}

	// 属性完全一致 → 重复观测，不是冲突。只补来源。
	if cur.Attrs == attrsJSON && cur.Kind == int32(e.GetKind()) {
		if err := s.insertProvenance(ctx, tx, e, branch, cur.Version); err != nil {
			return false, nil, err
		}
		return false, nil, nil
	}

	// 属性不同 → 新版本（不覆盖）。旧版本翻 valid_to。
	if _, err := tx.ExecContext(ctx,
		`UPDATE entity SET valid_to = ? WHERE entity_id = ? AND branch_id = ? AND valid_to IS NULL`,
		now.UnixNano(), e.GetEntityId(), branch); err != nil {
		return false, nil, fmt.Errorf("prism: close old version: %w", err)
	}
	next := cur.Version + 1
	if err := s.insertEntityVersion(ctx, tx, e, branch, now, next, attrsJSON); err != nil {
		return false, nil, err
	}
	if err := s.insertProvenance(ctx, tx, e, branch, next); err != nil {
		return false, nil, err
	}

	// 冲突记录：竞争来源需带上**旧版本**的 provenance（M2 §4.3：
	// 全部来源可追溯），因此这里把旧版本的来源一并取出。
	oldSources, err := s.provenanceOf(ctx, tx, e.GetEntityId(), branch, cur.Version)
	if err != nil {
		return false, nil, err
	}
	competing := append([]*alethv1.Provenance{}, oldSources...)
	competing = append(competing, e.GetSources()...)
	ctype := "VALUE_MISMATCH"
	if cur.Kind != int32(e.GetKind()) {
		ctype = "EXISTENCE_MISMATCH"
	}
	return false, &alethv1.Conflict{
		EntityId:         e.GetEntityId(),
		CompetingSources: competing,
		ConflictType:     ctype,
	}, nil
}

// currentVersion 取当前有效版本（valid_to IS NULL）。不存在返回 nil。
type entityVersionRow struct {
	Version int
	Attrs   string
	Kind    int32
}

func (s *Store) currentVersion(
	ctx context.Context, tx *sql.Tx, entityID, branch string,
) (*entityVersionRow, error) {
	var row entityVersionRow
	err := tx.QueryRowContext(ctx,
		`SELECT version, attrs, kind FROM entity
		 WHERE entity_id = ? AND branch_id = ? AND valid_to IS NULL
		 ORDER BY version DESC LIMIT 1`,
		entityID, branch).Scan(&row.Version, &row.Attrs, &row.Kind)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("prism: read current version: %w", err)
	}
	return &row, nil
}

// insertEntityVersion 插入一个实体版本行。
func (s *Store) insertEntityVersion(
	ctx context.Context, tx *sql.Tx, e *alethv1.Entity,
	branch string, now time.Time, version int, attrsJSON string,
) error {
	hyp := 0
	if e.GetIsHypothesis() {
		hyp = 1
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO entity(entity_id, kind, attrs, valid_from, valid_to, version,
		                    confidence, is_hypothesis, branch_id, session_id)
		 VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)`,
		e.GetEntityId(), int32(e.GetKind()), attrsJSON, now.UnixNano(),
		version, e.GetConfidence(), hyp, branch, s.sessionID); err != nil {
		return fmt.Errorf("prism: insert entity version: %w", err)
	}
	return nil
}

// insertProvenance 追加来源记录（多源审计要求：每次写入都留痕）。
// 同一 (entity, version, evidence, source_kind) 重复时不重复插入 ——
// 避免重复投递同一条光谱导致来源膨胀。
func (s *Store) insertProvenance(
	ctx context.Context, tx *sql.Tx, e *alethv1.Entity, branch string, version int,
) error {
	for _, p := range e.GetSources() {
		var exists int
		err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM provenance
			 WHERE entity_id = ? AND branch_id = ? AND version = ?
			   AND evidence_id = ? AND source_kind = ?`,
			e.GetEntityId(), branch, version,
			p.GetEvidenceId(), int32(p.GetSourceKind())).Scan(&exists)
		if err != nil {
			return fmt.Errorf("prism: check provenance: %w", err)
		}
		if exists > 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO provenance(entity_id, version, branch_id, source_kind,
			                        evidence_id, exec_id, observed_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			e.GetEntityId(), version, branch, int32(p.GetSourceKind()),
			p.GetEvidenceId(), p.GetExecId(), tsNano(p.GetObservedAt())); err != nil {
			return fmt.Errorf("prism: insert provenance: %w", err)
		}
	}
	return nil
}

// provenanceOf 读某版本的全部来源。
func (s *Store) provenanceOf(
	ctx context.Context, tx *sql.Tx, entityID, branch string, version int,
) ([]*alethv1.Provenance, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT source_kind, evidence_id, exec_id, observed_at FROM provenance
		 WHERE entity_id = ? AND branch_id = ? AND version = ? ORDER BY row_id`,
		entityID, branch, version)
	if err != nil {
		return nil, fmt.Errorf("prism: read provenance: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*alethv1.Provenance
	for rows.Next() {
		var (
			sk         int32
			ev, ex     string
			observedAt int64
		)
		if err := rows.Scan(&sk, &ev, &ex, &observedAt); err != nil {
			return nil, fmt.Errorf("prism: scan provenance: %w", err)
		}
		p := &alethv1.Provenance{
			SourceKind: alethv1.SourceKind(sk),
			EvidenceId: ev,
			ExecId:     ex,
		}
		if observedAt != 0 {
			p.ObservedAt = timestamppb.New(time.Unix(0, observedAt).UTC())
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// insertRelation 写入关系（幂等：同一 relation_id 在分支内只写一次）。
func (s *Store) insertRelation(
	ctx context.Context, tx *sql.Tx, r *alethv1.Relation, branch string, now time.Time,
) error {
	var exists int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM relation WHERE relation_id = ? AND branch_id = ?`,
		r.GetRelationId(), branch).Scan(&exists); err != nil {
		return fmt.Errorf("prism: check relation: %w", err)
	}
	if exists > 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO relation(relation_id, from_entity, to_entity, type, attrs,
		                      confidence, evidence_id, valid_from, valid_to, branch_id, session_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
		r.GetRelationId(), r.GetFromEntity(), r.GetToEntity(), int32(r.GetType()),
		canonicalAttrs(r.GetAttributes()), r.GetConfidence(), r.GetEvidenceId(),
		now.UnixNano(), branch, s.sessionID); err != nil {
		return fmt.Errorf("prism: insert relation: %w", err)
	}
	return nil
}

// attrsToMap 反序列化规范属性 JSON。
func attrsToMap(raw string) map[string]string {
	if raw == "" || raw == "{}" {
		return map[string]string{}
	}
	out := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return map[string]string{}
	}
	return out
}
