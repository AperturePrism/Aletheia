// Package prism 实现 L1 心智地图（modules/M2，docs/05 §3.3 PrismService）。
//
// M2 是系统的唯一真源：上下文（M3）、agent 记忆、报告（M5）全部从它派生。
//
// 存储决策（M2 §4.1）：部署形态为 PostgreSQL；I4 的运行时一致性 DoD
// （多源版本保留 / SnapshotAt 回放 / 分支回滚字节级一致）由 Store 接口的
// 内存实现承载 —— 契约定死、实现可变（05 §0 C1）；PostgreSQL 绑定在
// 环境就绪后补（map/migrations/0001_init.sql 已按 PG 方言交付）。
//
// 语义不变量（M2 §4.3–§4.5，全部有测试锁定）：
//   - 不覆盖不合并：属性冲突 → 新增版本 + Conflict 记录（VALUE_MISMATCH）
//   - 时间版本：旧版本置 valid_to，新版本 valid_from := 写入时刻
//   - 同一 spectrum_id 重复 Ingest 幂等（无副作用）
//   - RollbackBranch 后图状态与「从未创建该分支」一致
//   - MergeBranch 仅接受非 Hypothesis 实体（防止假设污染主分支）
package prism

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// Clock 注入统一时间源（M2 §8：回放依赖严格时间语义，禁止调用方
// 自行生成时间戳）。相同 clock 值内的多次写入共享同一 valid_from。
type Clock struct {
	mu   sync.Mutex
	now  time.Time
	tick time.Duration // 每次 Now() 推进的最小步长，保证严格递增
}

// NewClock 建立从 start 开始、每次 Now() 推进 tick 的时钟。
// tick 用 1ms：测试中连续写入的可区分时点，且回放窗口稳定。
func NewClock(start time.Time, tick time.Duration) *Clock {
	return &Clock{now: start.Add(-tick), tick: tick}
}

// Now 返回当前时间并推进 tick。
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(c.tick)
	return c.now
}

// Conflict 记录（05 §3.3 IngestResult.conflicts；M2 §4.3）。
type Conflict struct {
	EntityID         string
	ConflictType     string // VALUE_MISMATCH / EXISTENCE_MISMATCH / CONTRADICTS
	CompetingSources []provRec
}

// provRec 是 provenance 的内部轻量记录（非 proto）—— proto 消息含
// sync.Mutex（MessageState），按值存储触发 vet 锁复制告警。
type provRec struct {
	SourceKind string
	EvidenceID string
	ExecID     string
	ObservedAt time.Time
}

// MaxConcurrentBranches 分支上限（M2 §8：超限拒绝创建而非静默降级）。
const MaxConcurrentBranches = 8

// Store 是内存实现的心智地图。并发安全。
//
// 版本模型：每个 entity_id 挂一条**不可变版本链**（append-only）；
// "当前版本" = 链尾 valid_to 为空的版本。写入路径只有 Ingest。
type Store struct {
	mu         sync.RWMutex
	clock      *Clock
	spectrums  map[string]bool              // spectrum_id → 已摄入（幂等）
	versions   map[string][]entityVersion   // entity_id → 版本链（按时间序）
	provenance map[string][]provRec         // entity_id → 全部来源
	relations  map[string][]relationVersion // relation_id → 版本链
	branches   map[string]branchRec         // branch_id → 元信息
	branchOps  map[string][]branchOp        // branch_id → 该分支的全部写入（回滚用）
	conflicts  map[string][]Conflict        // entity_id → 冲突记录
	openBranch []string                     // OPEN 状态分支（限流用）
}

type entityVersion struct {
	attrs        map[string]string
	kind         alethv1.EntityKind
	validFrom    time.Time
	validTo      *time.Time
	version      int
	confidence   float64
	isHypothesis bool
	branchID     string
}

type relationVersion struct {
	from, to  string
	relType   string
	validFrom time.Time
	validTo   *time.Time
}

type branchRec struct {
	parent    string
	createdAt time.Time
	status    string // OPEN / MERGED / ROLLED_BACK
}

type branchOp struct {
	entityID string
	at       time.Time
}

// NewStore 建立空地图（main 分支隐式存在）。
func NewStore(clock *Clock) *Store {
	return &Store{
		clock:      clock,
		spectrums:  make(map[string]bool),
		versions:   make(map[string][]entityVersion),
		provenance: make(map[string][]provRec),
		relations:  make(map[string][]relationVersion),
		branches:   map[string]branchRec{"main": {parent: "", createdAt: clock.Now(), status: "OPEN"}},
		branchOps:  make(map[string][]branchOp),
		conflicts:  make(map[string][]Conflict),
	}
}

// ---- 分支管理（M2 §4.5）----

// CreateBranch 创建假设分支。超限拒绝（M2 §8：默认并发 8）。
func (s *Store) CreateBranch(branchID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.branches[branchID]; dup {
		return fmt.Errorf("branch %q already exists", branchID)
	}
	open := 0
	for _, id := range s.openBranch {
		if s.branches[id].status == "OPEN" && id != "main" {
			open++
		}
	}
	if open >= MaxConcurrentBranches {
		return fmt.Errorf("concurrent branch limit (%d) reached; refusing to create %q (M2 §8)", MaxConcurrentBranches, branchID)
	}
	s.branches[branchID] = branchRec{parent: "main", createdAt: s.clock.Now(), status: "OPEN"}
	s.openBranch = append(s.openBranch, branchID)
	return nil
}

// RollbackBranch 把分支内全部写入的实体置 valid_to（软删除）。
// 契约（M2 §4.5）：回滚后 SnapshotAt(分支前时刻) 与「从未创建分支」一致。
func (s *Store) RollbackBranch(branchID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.branches[branchID]
	if !ok {
		return fmt.Errorf("branch %q not found", branchID)
	}
	if rec.status != "OPEN" {
		return fmt.Errorf("branch %q status is %s; only OPEN branches can be rolled back", branchID, rec.status)
	}
	now := s.clock.Now()
	for _, op := range s.branchOps[branchID] {
		chain := s.versions[op.entityID]
		for i := range chain {
			if chain[i].branchID == branchID && chain[i].validTo == nil {
				t := now
				chain[i].validTo = &t
			}
		}
		s.versions[op.entityID] = chain
	}
	rec.status = "ROLLED_BACK"
	s.branches[branchID] = rec
	return nil
}

// MergeBranch 把分支内实体转正（is_hypothesis 清除）。
// 仅当分支内实体通过 M4 闸门（非 Hypothesis）才允许合并（M2 §4.5）。
func (s *Store) MergeBranch(branchID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.branches[branchID]
	if !ok {
		return fmt.Errorf("branch %q not found", branchID)
	}
	if rec.status != "OPEN" {
		return fmt.Errorf("branch %q status is %s; only OPEN branches can be merged", branchID, rec.status)
	}
	// 逐实体检查：分支内仍处于 HYPOTHESIS 的实体阻止合并。
	for _, op := range s.branchOps[branchID] {
		chain := s.versions[op.entityID]
		if len(chain) == 0 {
			continue
		}
		tail := chain[len(chain)-1]
		if tail.branchID == branchID && tail.validTo == nil && tail.isHypothesis {
			return fmt.Errorf("branch %q contains unverified hypothesis entity %q; merge refused (M2 §4.5)", branchID, op.entityID)
		}
	}
	for _, op := range s.branchOps[branchID] {
		chain := s.versions[op.entityID]
		for i := range chain {
			if chain[i].branchID == branchID {
				chain[i].isHypothesis = false
				chain[i].branchID = "main"
			}
		}
		s.versions[op.entityID] = chain
	}
	rec.status = "MERGED"
	s.branches[branchID] = rec
	return nil
}

// ---- 查询 ----

// SnapshotAt 返回 T 时刻的认知状态（M2 §4.4 回放契约：
// 与「当时实际认知状态」字节级一致 —— 一致性由测试锁定）。
func (s *Store) SnapshotAt(t time.Time, branchID string) *Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap := &Snapshot{At: t, Entities: map[string]EntityView{}}
	for id, chain := range s.versions {
		// 版本链按时间序 append —— 取**最后一个**在 T 时刻有效的版本
		//（即当时的最新认知）。第一个命中是 v1，不是当前版本：
		// 该 bug 曾被回放保真测试漏过（live/replay 同错则指纹仍相等），
		// 由多源冲突测试抓出（M2 §4.4 的「回放到 T」语义 = T 时刻的最新版本）。
		for _, v := range chain {
			if activeAt(v, t, branchID) {
				snap.Entities[id] = EntityView{
					Kind: v.kind, Attrs: copyAttrs(v.attrs),
					Confidence: v.confidence, IsHypothesis: v.isHypothesis,
					Version: v.version, BranchID: v.branchID,
				}
			}
		}
	}
	return snap
}

// Snapshot 是某时刻的认知状态投影。
type Snapshot struct {
	At       time.Time
	Entities map[string]EntityView
}

// EntityView 是快照中的实体只读视图。
type EntityView struct {
	Kind         alethv1.EntityKind
	Attrs        map[string]string
	Confidence   float64
	IsHypothesis bool
	Version      int
	BranchID     string
}

// Fingerprint 是快照的确定性摘要（回放一致性对比用：字节级等价 ⇒ 指纹相等）。
func (s *Snapshot) Fingerprint() string {
	ids := make([]string, 0, len(s.Entities))
	for id := range s.Entities {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	for _, id := range ids {
		v := s.Entities[id]
		keys := make([]string, 0, len(v.Attrs))
		for k := range v.Attrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(&b, "%s|%d|%s|v%d|hyp=%t|br=%s|conf=%.4f\n",
			id, int(v.Kind), strings.Join(keys, ","), v.Version, v.IsHypothesis, v.BranchID, v.Confidence)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %s=%s\n", k, v.Attrs[k])
		}
	}
	return b.String()
}

func activeAt(v entityVersion, t time.Time, branchID string) bool {
	if v.validFrom.After(t) {
		return false
	}
	if v.validTo != nil && !v.validTo.After(t) {
		return false
	}
	// 分支可见性：main 快照不含未合并的假设分支实体；分支快照含
	// main（分支前时刻的基线）+ 本分支写入。
	if branchID == "main" {
		return v.branchID == "main"
	}
	return v.branchID == branchID || v.branchID == "main"
}

func copyAttrs(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
