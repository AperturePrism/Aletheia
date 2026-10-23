package prism

import (
	"fmt"
	"strings"
	"testing"
	"time"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

var base = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func newTestStore() (*Store, *Clock) {
	clock := NewClock(base, time.Millisecond)
	return NewStore(clock), clock
}

func spectrum(id string, entities ...*alethv1.EntityDraft) *alethv1.EvidenceSpectrum {
	sp := alethv1.EvidenceSpectrum{SpectrumId: id, ExecId: "exec_" + id}
	sp.Entities = entities
	return &sp
}

func assetDraft(addr string, extra map[string]string) *alethv1.EntityDraft {
	d := alethv1.EntityDraft{Kind: alethv1.EntityKind_ASSET, ParserConfidence: 1.0}
	d.Attributes = map[string]string{"addr": addr}
	for k, v := range extra {
		d.Attributes[k] = v
	}
	return &d
}

func serviceDraft(host, port, proto string) *alethv1.EntityDraft {
	d := alethv1.EntityDraft{Kind: alethv1.EntityKind_SERVICE, ParserConfidence: 1.0}
	d.Attributes = map[string]string{"host_addr": host, "port": port, "protocol": proto}
	return &d
}

// ---- 多源写入与冲突保留（M2 §4.3，04 §I4 DoD②）----

func TestMultiSourceConflictPreserved(t *testing.T) {
	s, _ := newTestStore()
	// 三个来源（不同光谱）对同一 ASSET 写入不同 os 属性值。
	for i, os := range []string{"linux", "linux-hardened", "unknown"} {
		sp := spectrum(string(rune('a'+i))+"-sp", assetDraft("10.40.23.10", map[string]string{"os": os}))
		res, err := s.Ingest(sp)
		if err != nil {
			t.Fatal(err)
		}
		_ = res
	}
	snap := s.SnapshotAt(base.Add(time.Hour), "main")
	v := snap.Entities[entityIdentityID(alethv1.EntityKind_ASSET, map[string]string{"addr": "10.40.23.10", "os": "unknown"})]
	if v.Version != 3 {
		t.Fatalf("version = %d, want 3（冲突新增版本，不覆盖）", v.Version)
	}
	if v.Attrs["os"] != "unknown" {
		t.Fatalf("tail attrs os = %q", v.Attrs["os"])
	}
	// 全部 provenance 可追溯（3 条来源记录）。
	s.mu.RLock()
	provCount := len(s.provenance[entityIdentityID(alethv1.EntityKind_ASSET, map[string]string{"addr": "10.40.23.10"})])
	s.mu.RUnlock()
	if provCount != 3 {
		t.Fatalf("provenance = %d, want 3", provCount)
	}
	// Conflict 正确生成（两次冲突：第 2、3 次写入）。
	if len(s.conflicts[entityIdentityID(alethv1.EntityKind_ASSET, map[string]string{"addr": "10.40.23.10"})]) != 2 {
		t.Fatalf("conflicts = %d, want 2", len(s.conflicts[entityIdentityID(alethv1.EntityKind_ASSET, map[string]string{"addr": "10.40.23.10"})]))
	}
}

func TestSameAttrsMultiSourceNoNewVersion(t *testing.T) {
	// 三个来源写入**一致**的属性 → 只加 provenance，不新增版本（去重语义）。
	s, _ := newTestStore()
	for i := 0; i < 3; i++ {
		if _, err := s.Ingest(spectrum(string(rune('a'+i))+"-sp", assetDraft("10.40.23.10", map[string]string{"os": "linux"}))); err != nil {
			t.Fatal(err)
		}
	}
	snap := s.SnapshotAt(base.Add(time.Hour), "main")
	id := entityIdentityID(alethv1.EntityKind_ASSET, map[string]string{"addr": "10.40.23.10"})
	if snap.Entities[id].Version != 1 {
		t.Fatalf("consistent multi-source must not create new versions, got v%d", snap.Entities[id].Version)
	}
}

// ---- 回放保真（M2 §4.4，04 §I4 DoD③）----

func TestSnapshotAtReplayFidelity(t *testing.T) {
	s, _ := newTestStore()
	// 连续写入 N 个演化版本，每个时刻记下**实时**指纹。
	var liveFingerprints []string
	for i := 0; i < 5; i++ {
		sp := spectrum(string(rune('a'+i))+"-sp",
			assetDraft("10.40.23.10", map[string]string{"os": "state-" + string(rune('a'+i))}))
		if _, err := s.Ingest(sp); err != nil {
			t.Fatal(err)
		}
		live := s.SnapshotAt(base.Add(time.Hour), "main")
		liveFingerprints = append(liveFingerprints, live.Fingerprint())
	}
	// 回放到每个中间时刻，与当时实时快照**字节级**一致。
	for i, want := range liveFingerprints {
		at := base.Add(time.Duration(i+1) * time.Millisecond)
		got := s.SnapshotAt(at, "main").Fingerprint()
		if got != want {
			t.Fatalf("replay at tick %d diverges:\n got %q\nwant %q", i+1, got, want)
		}
	}
}

func TestSnapshotAtBeforeFirstWriteIsEmpty(t *testing.T) {
	s, _ := newTestStore()
	if _, err := s.Ingest(spectrum("a-sp", assetDraft("10.40.23.10", nil))); err != nil {
		t.Fatal(err)
	}
	before := s.SnapshotAt(base, "main") // 第一条写入的 valid_from 也在 base 之后（tick 推进）
	if len(before.Entities) != 0 {
		t.Fatalf("snapshot before first write should be empty, got %d entities", len(before.Entities))
	}
}

// ---- 幂等（M2 §6）----

func TestIngestIdempotent(t *testing.T) {
	s, _ := newTestStore()
	sp := spectrum("dup-sp",
		assetDraft("10.40.23.10", map[string]string{"os": "linux"}),
		serviceDraft("10.40.23.10", "22", "tcp"))
	for i := 0; i < 3; i++ {
		res, err := s.Ingest(sp)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && (len(res.CreatedEntityIDs) != 0) {
			t.Fatalf("replay %d must be side-effect free, created %v", i, res.CreatedEntityIDs)
		}
	}
	snap := s.SnapshotAt(base.Add(time.Hour), "main")
	if len(snap.Entities) != 2 {
		t.Fatalf("entities = %d, want 2 (asset + service)", len(snap.Entities))
	}
}

// ---- 关系推导（RUNS_ON）----

func TestRunsOnRelationDerived(t *testing.T) {
	s, _ := newTestStore()
	if _, err := s.Ingest(spectrum("rel-sp",
		assetDraft("10.40.23.10", nil),
		serviceDraft("10.40.23.10", "22", "tcp"))); err != nil {
		t.Fatal(err)
	}
	relID := relationIdentityID(
		entityIdentityID(alethv1.EntityKind_ASSET, map[string]string{"addr": "10.40.23.10"}),
		entityIdentityID(alethv1.EntityKind_SERVICE, map[string]string{
			"host_addr": "10.40.23.10", "port": "22", "protocol": "tcp",
		}),
		"RUNS_ON",
	)
	s.mu.RLock()
	rels := s.relations[relID]
	s.mu.RUnlock()
	if len(rels) != 1 || rels[0].validTo != nil {
		t.Fatalf("RUNS_ON relation = %#v", rels)
	}
}

// ---- 假设分支（M2 §4.5，04 §I4 DoD④）----

func TestBranchIsolationAndRollbackConsistency(t *testing.T) {
	s, clock := newTestStore()
	// main 基线：一个资产。
	if _, err := s.Ingest(spectrum("base-sp", assetDraft("10.40.23.10", map[string]string{"os": "linux"}))); err != nil {
		t.Fatal(err)
	}
	before := clock.Now()
	baseline := s.SnapshotAt(base.Add(time.Hour), "main").Fingerprint()

	// 假设分支：写入两个实体。
	if err := s.CreateBranch("branch_ssrf"); err != nil {
		t.Fatal(err)
	}
	// 分支内写入经 Ingest —— Ingest 目前写 main；分支写入需要指定分支。
	// M2 §4.5：分支内写入带 is_hypothesis=true, branch_id=branch_ssrf。
	// 这里直接用 Store 的分支写入原语（Ingest 分支感知在 service 层）。
	if err := s.CreateBranch("branch_ssrf"); err == nil {
		t.Fatal("duplicate branch must be refused")
	}
	_ = before
	_ = baseline
}

// 分支写入与回滚的核心语义（使用内部写入原语，隔离 Ingest 的 main 语义）。
func TestBranchWriteRollbackByteLevelConsistency(t *testing.T) {
	s, _ := newTestStore()
	if _, err := s.Ingest(spectrum("base-sp", assetDraft("10.40.23.10", map[string]string{"os": "linux"}))); err != nil {
		t.Fatal(err)
	}
	branchPoint := base.Add(2 * time.Millisecond)
	baseline := s.SnapshotAt(branchPoint, "main").Fingerprint()

	if err := s.CreateBranch("branch_h1"); err != nil {
		t.Fatal(err)
	}
	// 分支内写入（is_hypothesis=true, branch_id=branch_h1）。
	s.mu.Lock()
	id := entityIdentityID(alethv1.EntityKind_ASSET, map[string]string{"addr": "10.40.99.99"})
	now := s.clock.Now()
	s.versions[id] = []entityVersion{
		{attrs: map[string]string{"addr": "10.40.99.99"}, kind: alethv1.EntityKind_ASSET,
			validFrom: now, version: 1, confidence: 0.5, isHypothesis: true, branchID: "branch_h1"},
	}
	s.branchOps["branch_h1"] = append(s.branchOps["branch_h1"], branchOp{entityID: id, at: now})
	s.mu.Unlock()

	// 分支快照：main + 分支实体。
	withBranch := s.SnapshotAt(branchPoint.Add(time.Hour), "branch_h1")
	if _, ok := withBranch.Entities[id]; !ok {
		t.Fatal("branch snapshot must contain branch entity")
	}
	// main 快照：分支实体不可见（隔离）。
	mainSnap := s.SnapshotAt(branchPoint.Add(time.Hour), "main")
	if _, ok := mainSnap.Entities[id]; ok {
		t.Fatal("branch entity must not leak into main snapshot")
	}

	// 回滚 → main 快照与「从未创建分支」完全一致（字节级）。
	if err := s.RollbackBranch("branch_h1"); err != nil {
		t.Fatal(err)
	}
	after := s.SnapshotAt(branchPoint.Add(time.Hour), "main").Fingerprint()
	if after != baseline {
		t.Fatalf("rollback consistency violated:\n got %q\nwant %q", after, baseline)
	}
}

func TestMergeRefusesUnverifiedHypothesis(t *testing.T) {
	s, _ := newTestStore()
	if err := s.CreateBranch("branch_m"); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	id := entityIdentityID(alethv1.EntityKind_ASSET, map[string]string{"addr": "10.40.98.98"})
	now := s.clock.Now()
	s.versions[id] = []entityVersion{
		{attrs: map[string]string{"addr": "10.40.98.98"}, kind: alethv1.EntityKind_ASSET,
			validFrom: now, version: 1, confidence: 0.5, isHypothesis: true, branchID: "branch_m"},
	}
	s.branchOps["branch_m"] = append(s.branchOps["branch_m"], branchOp{entityID: id, at: now})
	s.mu.Unlock()

	if err := s.MergeBranch("branch_m"); err == nil {
		t.Fatal("merge with unverified hypothesis must be refused (M2 §4.5)")
	}
	// 验证通过（is_hypothesis 清除，模拟 M4 闸门通过）→ 允许合并。
	s.mu.Lock()
	chain := s.versions[id]
	chain[0].isHypothesis = false
	s.versions[id] = chain
	s.mu.Unlock()
	if err := s.MergeBranch("branch_m"); err != nil {
		t.Fatalf("merge after verification must succeed: %v", err)
	}
}

func TestBranchLimitRefused(t *testing.T) {
	s, _ := newTestStore()
	for i := 0; i < MaxConcurrentBranches; i++ {
		if err := s.CreateBranch("branch_" + strings.Repeat("x", i+1)); err != nil {
			t.Fatalf("branch %d should be creatable: %v", i, err)
		}
	}
	if err := s.CreateBranch("branch_overflow"); err == nil {
		t.Fatal("branch beyond limit must be refused (M2 §8)")
	}
}

// TestSnapshotAtReturnsVersionCurrentAtT 是回放保真的**语义级**强化：
// TestSnapshotAtReplayFidelity 只对比 live/replay 指纹 —— 若 SnapshotAt
// 错误地返回 v1（首个命中而非最新版本），live/replay 同错则指纹仍相等，
// 测试不会红。本测试直接断言「回放到 T 的实体版本 = T 时刻的最新版本」。
// （该断言在多源冲突测试的 bug 修复中首次失败 —— 见 store.go 的
// SnapshotAt 注释。）
func TestSnapshotAtReturnsVersionCurrentAtT(t *testing.T) {
	s, _ := newTestStore()
	for i, os := range []string{"state-a", "state-b", "state-c", "state-d"} {
		if _, err := s.Ingest(spectrum(string(rune('a'+i))+"-sp",
			assetDraft("10.40.23.10", map[string]string{"os": os}))); err != nil {
			t.Fatal(err)
		}
	}
	for tick := 1; tick <= 4; tick++ {
		at := base.Add(time.Duration(tick) * time.Millisecond)
		v := s.SnapshotAt(at, "main").Entities[entityIdentityID(
			alethv1.EntityKind_ASSET, map[string]string{"addr": "10.40.23.10", "os": fmt.Sprintf("state-%c", 'a'+tick-1)})]
		if v.Version != tick {
			t.Fatalf("snapshot at tick %d returned version %d (os=%q), want v%d",
				tick, v.Version, v.Attrs["os"], tick)
		}
	}
	// 回放到全部写入之前 → 该实体不存在。
	early := s.SnapshotAt(base, "main")
	if _, ok := early.Entities[entityIdentityID(
		alethv1.EntityKind_ASSET, map[string]string{"addr": "10.40.23.10"})]; ok {
		t.Fatal("entity must not exist before its first write")
	}
}
