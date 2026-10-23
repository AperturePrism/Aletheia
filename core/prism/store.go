// Package prism 实现 M2 棱镜分解与心智地图（L1）—— 系统的唯一真源。
//
// 契约依据：05 §3 ｜ 模块规格：modules/M2 ｜ 迭代：I4
//
// 职责（M2 §2.1 R1–R6）：
//
//	R1 光谱 → 实体/关系的分解（7 类实体）
//	R2 多源写入与冲突保留（不合并、不覆盖）
//	R3 时间版本管理（valid_from / valid_to）与历史回放
//	R4 假设分支（创建 / 回滚 / 合并）
//	R5 子图投影（按焦点与半径）
//	R6 归档压缩（降采样为聚合节点，保留下钻能力）
//
// 明确不做（M2 §2.2）：不决定"该查什么"（M3）、不做预算判断（M3）、
// 不判定漏洞状态（M4）、不调用 LLM 抽取实体（M1 解析器负责）、
// **不采用多套存储**（单一图 + 逻辑视图投影 —— 对 PentAGI 四套存储的回应）。
//
// # 核心不变量（本项目第一原则「可证明性」在图上的落地）
//
//  1. 不覆盖、不合并：同一实体的冲突值各自成为**新版本**，全部保留。
//     侦察漏掉的服务不再导致下游永不测试它（对 D12 级联失败的回应）。
//  2. 时间由本包统一赋值，调用方不得自带时间戳 —— 与证据账本同源设计
//     （M4 拒绝 caller-provided created_at 的同一理由：时间线必须由
//     受信组件书写）。
//  3. 回放保真：SnapshotAt(T) 必须与"当时实际认知状态"字节级一致。
//  4. 回滚一致性：RollbackBranch 后图状态必须与**从未创建该分支**完全一致。
//  5. 幂等：相同 spectrum_id 重复 Ingest 无副作用。
//
// # 存储选择
//
// 单进程嵌入式 SQLite（modernc.org/sqlite 纯 Go 驱动，无 cgo 依赖）。
// 理由：I4 是单机形态（06 §5.1），零运维；schema 不用 SQLite 特有语法，
// PostgreSQL 迁移属部署形态决策（团队模式 P3 之后，06 §5.2）。
// 这与 M2 §4.1 的「单库原则」一致 —— 图、关系、来源、分支同库，
// 不做跨存储同步；规模超限时**按会话分区**而非拆库。
package prism

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动（无 cgo）
)

// MainBranchID 是主分支的固定标识。空 branch_id 在契约里表示"主分支"，
// 内部统一归一化为该常量，避免空串在多处比较。
const MainBranchID = "br_main"

// MaxConcurrentBranches 是并发假设分支上限（M2 §8：超限拒绝创建，
// 而非静默降级 —— 静默降级会让"分支隔离"这一安全属性失效）。
const MaxConcurrentBranches = 8

// schemaVersion 是图 schema 版本。与证据账本同构：版本不符拒绝打开
// （fail-closed），避免用新代码读旧结构产生静默误读。
const schemaVersion = 1

// 预置错误。调用方用 errors.Is 判定，不做字符串匹配（P-2 确定性优先）。
var (
	// ErrBranchLimitExceeded 并发分支超限。
	ErrBranchLimitExceeded = errors.New("prism: concurrent branch limit exceeded")
	// ErrBranchNotFound 分支不存在。
	ErrBranchNotFound = errors.New("prism: branch not found")
	// ErrMainBranchImmutable 主分支不可回滚/删除。
	ErrMainBranchImmutable = errors.New("prism: main branch cannot be rolled back or merged away")
	// ErrHypothesisInMerge 合并被拒：源分支含未验证的假设实体。
	ErrHypothesisInMerge = errors.New("prism: merge rejected: source branch contains unverified hypothesis entities")
	// ErrInvalidDraft 实体草稿不合法。
	ErrInvalidDraft = errors.New("prism: invalid entity draft")
)

// Clock 是统一时间源（M2 §8：所有写入走统一时间源，禁止应用层自行生成
// 时间戳）。测试注入固定时钟以获得确定性结果。
type Clock func() time.Time

// Store 是单一属性图（心智地图）。
//
// 并发模型：写路径以实例锁串行（保证版本号推进与 valid_to 翻转原子），
// 读路径共用同一 *sql.DB 连接池。
type Store struct {
	mu    sync.Mutex
	db    *sql.DB
	clock Clock
	// sessionID 用于按会话分区（M2 §8 风险缓解：图规模按会话隔离）。
	sessionID string
}

// Options 构造选项。
type Options struct {
	// DSN 是 SQLite 数据源。":memory:" 用于测试。
	DSN string
	// SessionID 会话标识（多会话分区用）。
	SessionID string
	// Clock 时间源。nil 时用 time.Now。
	Clock Clock
}

// Open 打开/建立心智地图。
func Open(opts Options) (*Store, error) {
	if opts.DSN == "" {
		return nil, errors.New("prism: DSN is required")
	}
	db, err := sql.Open("sqlite", opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("prism: open %q: %w", opts.DSN, err)
	}
	// 单写者模型：SQLite 的并发写会串行化，显式限制连接数避免
	// "database is locked" 抖动。
	db.SetMaxOpenConns(1)

	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	s := &Store{db: db, clock: clock, sessionID: opts.SessionID}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	// main 分支隐式存在（M2 §4.5：所有假设分支的父分支）——
	// 无此行则 requireBranch 对 main 报 not found（branch 表空）。
	if _, err := db.Exec(
		`INSERT OR IGNORE INTO branch (branch_id, branch_name, parent_branch_id, rationale, created_at, status)
		 VALUES (?, 'main', '', 'implicit main branch (M2 §4.5)', ?, 'open')`,
		MainBranchID, time.Now().UnixNano()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("prism: seed main branch: %w", err)
	}
	return s, nil
}

// Close 释放连接。
func (s *Store) Close() error { return s.db.Close() }

// migrate 建立 schema（幂等）。
//
// 表结构对应 M2 §4.1 的存储模型：entity / relation / provenance / branch /
// archive_node。**版本化行**：同一 entity_id 的每个版本是一行，
// valid_to IS NULL 表示当前有效。
func (s *Store) migrate() error {
	stmts := []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA foreign_keys=ON`,
		`PRAGMA trusted_schema=OFF`,
		`CREATE TABLE IF NOT EXISTS graph_meta (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		// entity：一行 = 一个版本。valid_to IS NULL → 当前有效版本。
		`CREATE TABLE IF NOT EXISTS entity (
			row_id      INTEGER PRIMARY KEY AUTOINCREMENT,
			entity_id   TEXT NOT NULL,
			kind        INTEGER NOT NULL,
			attrs       TEXT NOT NULL,        -- JSON（确定性序列化）
			valid_from  INTEGER NOT NULL,     -- UnixNano（统一时间源）
			valid_to    INTEGER,              -- NULL = 当前有效
			version     INTEGER NOT NULL,
			confidence  REAL NOT NULL,
			is_hypothesis INTEGER NOT NULL DEFAULT 0,
			branch_id   TEXT NOT NULL,
			session_id  TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_entity_current
			ON entity(entity_id, branch_id, valid_to)`,
		`CREATE INDEX IF NOT EXISTS idx_entity_kind
			ON entity(kind, branch_id, valid_to)`,
		// provenance：多源写入的审计要求（每个版本可追溯到具体来源）。
		`CREATE TABLE IF NOT EXISTS provenance (
			row_id      INTEGER PRIMARY KEY AUTOINCREMENT,
			entity_id   TEXT NOT NULL,
			version     INTEGER NOT NULL,
			branch_id   TEXT NOT NULL,
			source_kind INTEGER NOT NULL,
			evidence_id TEXT NOT NULL DEFAULT '',
			exec_id     TEXT NOT NULL DEFAULT '',
			observed_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_prov_entity
			ON provenance(entity_id, branch_id, version)`,
		// relation：关系也带时间版本（Relation.valid_from 契约字段）。
		`CREATE TABLE IF NOT EXISTS relation (
			row_id      INTEGER PRIMARY KEY AUTOINCREMENT,
			relation_id TEXT NOT NULL,
			from_entity TEXT NOT NULL,
			to_entity   TEXT NOT NULL,
			type        INTEGER NOT NULL,
			attrs       TEXT NOT NULL,
			confidence  REAL NOT NULL,
			evidence_id TEXT NOT NULL DEFAULT '',
			valid_from  INTEGER NOT NULL,
			valid_to    INTEGER,
			branch_id   TEXT NOT NULL,
			session_id  TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_relation_from
			ON relation(from_entity, branch_id, valid_to)`,
		`CREATE INDEX IF NOT EXISTS idx_relation_to
			ON relation(to_entity, branch_id, valid_to)`,
		// branch：假设分支。
		`CREATE TABLE IF NOT EXISTS branch (
			branch_id        TEXT PRIMARY KEY,
			branch_name      TEXT NOT NULL,
			parent_branch_id TEXT NOT NULL DEFAULT '',
			rationale        TEXT NOT NULL DEFAULT '',
			created_at       INTEGER NOT NULL,
			status           TEXT NOT NULL DEFAULT 'open',
			session_id       TEXT NOT NULL DEFAULT ''
		)`,
		// ingest_log：幂等保证（相同 spectrum_id 重复 Ingest 无副作用）。
		`CREATE TABLE IF NOT EXISTS ingest_log (
			spectrum_id TEXT PRIMARY KEY,
			ingested_at INTEGER NOT NULL,
			entity_count INTEGER NOT NULL
		)`,
		// archive_node：归档聚合节点（R6，可下钻）。
		`CREATE TABLE IF NOT EXISTS archive_node (
			archive_id   TEXT PRIMARY KEY,
			kind         INTEGER NOT NULL,
			aggregate    TEXT NOT NULL,   -- JSON：计数/时间范围/属性值域
			downlinks    TEXT NOT NULL,   -- JSON 数组：归档前的 entity_id
			created_at   INTEGER NOT NULL,
			branch_id    TEXT NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("prism: migrate: %w", err)
		}
	}
	// schema 版本校验（与账本同构的 fail-closed）。
	var got string
	err := s.db.QueryRow(`SELECT value FROM graph_meta WHERE key='schema_version'`).Scan(&got)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := s.db.Exec(
			`INSERT INTO graph_meta(key, value) VALUES ('schema_version', ?)`,
			fmt.Sprint(schemaVersion)); err != nil {
			return fmt.Errorf("prism: init schema_version: %w", err)
		}
	case err != nil:
		return fmt.Errorf("prism: read schema_version: %w", err)
	case got != fmt.Sprint(schemaVersion):
		return fmt.Errorf(
			"prism: graph schema version %s != supported %d; refusing to open (fail-closed)",
			got, schemaVersion)
	}
	// 主分支必须存在（回放/投影都以它为根）。
	if _, err := s.db.Exec(
		`INSERT OR IGNORE INTO branch(branch_id, branch_name, parent_branch_id, rationale, created_at, status, session_id)
		 VALUES (?, 'main', '', 'root branch', ?, 'open', ?)`,
		MainBranchID, s.clock().UnixNano(), s.sessionID); err != nil {
		return fmt.Errorf("prism: init main branch: %w", err)
	}
	return nil
}

// normalizeBranch 把契约里的空 branch_id 归一化为主分支。
func normalizeBranch(id string) string {
	if strings.TrimSpace(id) == "" {
		return MainBranchID
	}
	return id
}

// canonicalAttrs 确定性序列化属性表。
//
// 为什么不用 json.Marshal(map)：Go 的 map 迭代顺序随机，
// 序列化结果不稳定 —— 会让本应相同的实体产生不同 hash，破坏
// 回放与回滚的字节级一致性（M2 §7 DoD③ 与 P-5 确定性要求）。
func canonicalAttrs(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(m[k])
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.String()
}

// HashCanonical 计算实体的规范 hash（回放/回滚字节级对比用）。
//
// 覆盖参与"认知状态"的全部字段，**排除**内部 row_id（自增，与语义无关）。
func HashCanonical(entities []*alethv1.Entity, relations []*alethv1.Relation) string {
	h := sha256.New()
	// 稳定排序：投影结果顺序不应影响状态 hash。
	es := append([]*alethv1.Entity(nil), entities...)
	sort.Slice(es, func(i, j int) bool {
		if es[i].GetEntityId() != es[j].GetEntityId() {
			return es[i].GetEntityId() < es[j].GetEntityId()
		}
		return es[i].GetVersion() < es[j].GetVersion()
	})
	for _, e := range es {
		fmt.Fprintf(h, "E|%s|%d|%d|%s|%d|%d|%d|%.6f|%t|%s\n",
			e.GetEntityId(), e.GetKind(), e.GetVersion(),
			canonicalAttrs(e.GetAttributes()),
			tsNano(e.GetValidFrom()), tsNano(e.GetValidTo()),
			len(e.GetSources()), e.GetConfidence(), e.GetIsHypothesis(), e.GetBranchId())
		for _, p := range e.GetSources() {
			fmt.Fprintf(h, "P|%d|%s|%s|%d\n",
				p.GetSourceKind(), p.GetEvidenceId(), p.GetExecId(), tsNano(p.GetObservedAt()))
		}
	}
	rs := append([]*alethv1.Relation(nil), relations...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].GetRelationId() < rs[j].GetRelationId() })
	for _, r := range rs {
		fmt.Fprintf(h, "R|%s|%s|%s|%d|%s|%.6f|%s|%d\n",
			r.GetRelationId(), r.GetFromEntity(), r.GetToEntity(), r.GetType(),
			canonicalAttrs(r.GetAttributes()), r.GetConfidence(),
			r.GetEvidenceId(), tsNano(r.GetValidFrom()))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// tsNano 把 proto Timestamp 转为 UnixNano（nil / 零值 → 0）。
func tsNano(ts *timestamppb.Timestamp) int64 {
	if ts == nil {
		return 0
	}
	return ts.AsTime().UnixNano()
}

// ctxErr 把 context 取消转为显式错误（不吞 —— P-4）。
func ctxErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
