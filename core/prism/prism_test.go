package prism

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// 测试基础设施：可控时钟 + 内存库。
//
// 时间是本模块的关键输入（版本推进、回放），因此测试必须能精确
// 推进时钟 —— 用真实 time.Now 会让"回放到 T 时刻"不可复现。

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestStore(t *testing.T) (*Store, *testClock) {
	t.Helper()
	clk := &testClock{t: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
	s, err := Open(Options{
		DSN:       filepath.Join(t.TempDir(), "map.db"),
		SessionID: "sess_test",
		Clock:     clk.now,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, clk
}

// spectrum 构造一条含指定实体草稿的光谱。
func spectrum(id string, drafts ...*alethv1.EntityDraft) *alethv1.EvidenceSpectrum {
	return &alethv1.EvidenceSpectrum{
		SpectrumId: id,
		ExecId:     "ex_" + id,
		Entities:   drafts,
		ObservedAt: timestamppb.New(time.Date(2026, 9, 27, 11, 0, 0, 0, time.UTC)),
	}
}

func assetDraft(addr string, conf float64) *alethv1.EntityDraft {
	return &alethv1.EntityDraft{
		Kind:             alethv1.EntityKind_ASSET,
		Attributes:       map[string]string{"addr": addr},
		ParserConfidence: conf,
		SourceLine:       1,
	}
}

func serviceDraft(addr, port, name string, conf float64) *alethv1.EntityDraft {
	return &alethv1.EntityDraft{
		Kind: alethv1.EntityKind_SERVICE,
		Attributes: map[string]string{
			"addr": addr, "port": port, "protocol": "tcp", "service": name,
		},
		ParserConfidence: conf,
		SourceLine:       2,
	}
}

// ---- T2.1 / T2.2：分解与身份确定性 ----

func TestDecomposeProducesStableIDs(t *testing.T) {
	sp := spectrum("sp_1", assetDraft("10.40.23.5", 0.9), serviceDraft("10.40.23.5", "80", "http", 0.9))

	a := Decompose(sp)
	b := Decompose(sp)
	if len(a.Entities) != 2 {
		t.Fatalf("entities = %d, want 2", len(a.Entities))
	}
	for i := range a.Entities {
		if a.Entities[i].GetEntityId() != b.Entities[i].GetEntityId() {
			t.Fatalf("entity IDs not deterministic: %s vs %s",
				a.Entities[i].GetEntityId(), b.Entities[i].GetEntityId())
		}
	}
	// 前缀契约（05 §1.1 风格）。
	if a.Entities[0].GetEntityId()[:3] != prefixAsset &&
		a.Entities[0].GetEntityId()[:3] != prefixService {
		t.Fatalf("unexpected ID prefix: %s", a.Entities[0].GetEntityId())
	}
}

func TestDecomposeSameHostAcrossSourcesYieldsSameID(t *testing.T) {
	// 关键：nmap 与 httpx 各自发现同一主机时，必须得到**同一个** entity_id，
	// 否则多源关联无从谈起（M2 §4.3）。
	nmapStyle := &alethv1.EntityDraft{
		Kind:             alethv1.EntityKind_ASSET,
		Attributes:       map[string]string{"addr": "10.40.23.5"},
		ParserConfidence: 0.95,
	}
	httpxStyle := &alethv1.EntityDraft{
		Kind:             alethv1.EntityKind_ASSET,
		Attributes:       map[string]string{"addr": "10.40.23.5"},
		ParserConfidence: 0.80,
	}
	idA, okA := EntityID(nmapStyle.GetKind(), nmapStyle.GetAttributes())
	idB, okB := EntityID(httpxStyle.GetKind(), httpxStyle.GetAttributes())
	if !okA || !okB {
		t.Fatal("both drafts must yield an ID")
	}
	if idA != idB {
		t.Fatalf("same host from two sources got different IDs: %s vs %s", idA, idB)
	}
}

func TestDecomposeSkipsDraftWithoutIdentity(t *testing.T) {
	// 缺必要属性的草稿必须**拒绝**而不是用随机值兜底。
	sp := spectrum("sp_bad", &alethv1.EntityDraft{
		Kind:       alethv1.EntityKind_SERVICE,
		Attributes: map[string]string{"service": "http"}, // 无 addr/port
	})
	res := Decompose(sp)
	if len(res.Entities) != 0 {
		t.Fatalf("draft without identity must be skipped, got %d entities", len(res.Entities))
	}
	if res.SkippedDrafts != 1 {
		t.Fatalf("SkippedDrafts = %d, want 1 (auditable, not silent)", res.SkippedDrafts)
	}
}

func TestDecomposeExtractsRunsOnRelation(t *testing.T) {
	sp := spectrum("sp_rel",
		assetDraft("10.40.23.5", 0.9),
		serviceDraft("10.40.23.5", "80", "http", 0.9))
	res := Decompose(sp)
	if len(res.Relations) != 1 {
		t.Fatalf("relations = %d, want 1 (SERVICE RUNS_ON ASSET)", len(res.Relations))
	}
	r := res.Relations[0]
	if r.GetType() != alethv1.RelationType_RUNS_ON {
		t.Fatalf("relation type = %s, want RUNS_ON", r.GetType())
	}
	// from 必须是 SERVICE，to 必须是 ASSET。
	var svcID, assetID string
	for _, e := range res.Entities {
		if e.GetKind() == alethv1.EntityKind_SERVICE {
			svcID = e.GetEntityId()
		}
		if e.GetKind() == alethv1.EntityKind_ASSET {
			assetID = e.GetEntityId()
		}
	}
	if r.GetFromEntity() != svcID || r.GetToEntity() != assetID {
		t.Fatalf("relation endpoints wrong: %s → %s (want %s → %s)",
			r.GetFromEntity(), r.GetToEntity(), svcID, assetID)
	}
}

// ---- T2.3：多源写入与冲突保留 ----

func TestMultiSourcePreservesAllVersions(t *testing.T) {
	s, clk := newTestStore(t)
	ctx := context.Background()

	// 源 A：端口 80 是 nginx。
	res1, err := s.Ingest(ctx, spectrum("sp_a", assetDraft("10.40.23.5", 0.9),
		&alethv1.EntityDraft{
			Kind:             alethv1.EntityKind_SERVICE,
			Attributes:       map[string]string{"addr": "10.40.23.5", "port": "80", "protocol": "tcp", "service": "nginx"},
			ParserConfidence: 0.9,
		}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res1.GetCreatedEntityIds()) != 2 {
		t.Fatalf("first ingest created %d, want 2", len(res1.GetCreatedEntityIds()))
	}

	clk.advance(time.Minute)

	// 源 B：同一端口是 apache（值冲突）。
	res2, err := s.Ingest(ctx, spectrum("sp_b",
		&alethv1.EntityDraft{
			Kind:             alethv1.EntityKind_SERVICE,
			Attributes:       map[string]string{"addr": "10.40.23.5", "port": "80", "protocol": "tcp", "service": "apache"},
			ParserConfidence: 0.7,
		}))
	if err != nil {
		t.Fatal(err)
	}
	// 关键：冲突被登记，而不是被覆盖。
	if len(res2.GetConflicts()) != 1 {
		t.Fatalf("conflicts = %d, want 1 (VALUE_MISMATCH)", len(res2.GetConflicts()))
	}
	if res2.GetConflicts()[0].GetConflictType() != "VALUE_MISMATCH" {
		t.Fatalf("conflict type = %s", res2.GetConflicts()[0].GetConflictType())
	}
	if len(res2.GetUpdatedEntityIds()) != 1 {
		t.Fatalf("updated = %d, want 1 (new version)", len(res2.GetUpdatedEntityIds()))
	}

	// 两个版本都必须保留（旧版本 valid_to 已翻转，但仍可查）。
	svcID, _ := EntityID(alethv1.EntityKind_SERVICE, map[string]string{
		"addr": "10.40.23.5", "port": "80", "protocol": "tcp"})
	sub, err := s.Project(ctx, MainBranchID, "", 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	var current *alethv1.Entity
	for _, e := range sub.GetEntities() {
		if e.GetEntityId() == svcID {
			current = e
		}
	}
	if current == nil {
		t.Fatal("service entity missing from projection")
	}
	// 当前有效版本应是后写入的 apache。
	if current.GetAttributes()["service"] != "apache" {
		t.Fatalf("current version service = %q, want apache", current.GetAttributes()["service"])
	}
	if current.GetVersion() != 2 {
		t.Fatalf("version = %d, want 2", current.GetVersion())
	}
}

func TestMultiSourceSameValueAddsProvenanceNotVersion(t *testing.T) {
	// 重复观测同一事实不是冲突 —— 否则每次扫描版本号都膨胀。
	// 但来源必须全部留痕（多源审计要求）。
	s, _ := newTestStore(t)
	ctx := context.Background()
	d := assetDraft("10.40.23.5", 0.9)

	if _, err := s.Ingest(ctx, spectrum("sp_1", d)); err != nil {
		t.Fatal(err)
	}
	res, err := s.Ingest(ctx, spectrum("sp_2", assetDraft("10.40.23.5", 0.8)))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GetConflicts()) != 0 {
		t.Fatalf("identical value must not be a conflict, got %d", len(res.GetConflicts()))
	}

	id, _ := EntityID(alethv1.EntityKind_ASSET, map[string]string{"addr": "10.40.23.5"})
	sub, _ := s.Project(ctx, MainBranchID, "", 0, 0, nil)
	for _, e := range sub.GetEntities() {
		if e.GetEntityId() == id && e.GetVersion() != 1 {
			t.Fatalf("version = %d, want 1 (identical value must not bump version)", e.GetVersion())
		}
	}

	// provenance 应有两条（两个证据）。
	var n int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM provenance WHERE entity_id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("provenance rows = %d, want 2 (all sources traceable)", n)
	}
}

func TestIngestIsIdempotent(t *testing.T) {
	// M2 §6：相同 spectrum_id 重复 Ingest 无副作用。
	s, _ := newTestStore(t)
	ctx := context.Background()
	sp := spectrum("sp_same", assetDraft("10.40.23.5", 0.9))

	if _, err := s.Ingest(ctx, sp); err != nil {
		t.Fatal(err)
	}
	before, err := s.StateHash(ctx, MainBranchID)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Ingest(ctx, sp) // 重复投递
	if err != nil {
		t.Fatal(err)
	}
	if len(res.GetCreatedEntityIds()) != 0 || len(res.GetUpdatedEntityIds()) != 0 {
		t.Fatal("re-ingest must have zero side effects")
	}
	after, _ := s.StateHash(ctx, MainBranchID)
	if before != after {
		t.Fatalf("state changed on re-ingest:\n before=%s\n after =%s", before, after)
	}
}

// ---- T2.4：时间版本与回放保真（DoD②）----

func TestSnapshotAtReplaysHistoricalState(t *testing.T) {
	s, clk := newTestStore(t)
	ctx := context.Background()

	// T1：只有资产。
	if _, err := s.Ingest(ctx, spectrum("sp_1", assetDraft("10.40.23.5", 0.9))); err != nil {
		t.Fatal(err)
	}
	t1 := clk.t
	hashAtT1, err := s.StateHash(ctx, MainBranchID)
	if err != nil {
		t.Fatal(err)
	}

	clk.advance(time.Hour)

	// T2：加一个服务（新实体）。
	if _, err := s.Ingest(ctx, spectrum("sp_2", serviceDraft("10.40.23.5", "80", "http", 0.9))); err != nil {
		t.Fatal(err)
	}
	t2 := clk.t

	// 回放到 T2：应看到 2 个实体。
	sub2, err := s.SnapshotAt(ctx, MainBranchID, t2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(sub2.GetEntities()) != 2 {
		t.Fatalf("at T2 entities = %d, want 2", len(sub2.GetEntities()))
	}

	// 回放到 T1：应只看到 1 个实体（服务尚未写入）。
	sub1, err := s.SnapshotAt(ctx, MainBranchID, t1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(sub1.GetEntities()) != 1 {
		t.Fatalf("at T1 entities = %d, want 1 (service did not exist yet)", len(sub1.GetEntities()))
	}
	if sub1.GetEntities()[0].GetKind() != alethv1.EntityKind_ASSET {
		t.Fatalf("at T1 kind = %s, want ASSET", sub1.GetEntities()[0].GetKind())
	}

	// **回放保真**（DoD②）：T1 的 hash 必须与当时实时计算的一致。
	sub1.SnapshotId = ""
	replayHash := HashCanonical(sub1.GetEntities(), sub1.GetRelations())
	if replayHash != hashAtT1 {
		t.Fatalf("replay not faithful:\n live(T1)   =%s\n replay(T1) =%s",
			hashAtT1, replayHash)
	}
}

func TestSnapshotAtReplaysOldVersionOfChangedEntity(t *testing.T) {
	// 同一实体的**属性变化**也要能回放到旧值 —— 这是时间版本的核心价值。
	s, clk := newTestStore(t)
	ctx := context.Background()

	mk := func(svc string) *alethv1.EntityDraft {
		return &alethv1.EntityDraft{
			Kind: alethv1.EntityKind_SERVICE,
			Attributes: map[string]string{
				"addr": "10.40.23.5", "port": "80", "protocol": "tcp", "service": svc,
			},
			ParserConfidence: 0.9,
		}
	}
	if _, err := s.Ingest(ctx, spectrum("sp_1", mk("nginx"))); err != nil {
		t.Fatal(err)
	}
	tNginx := clk.t
	clk.advance(time.Hour)
	if _, err := s.Ingest(ctx, spectrum("sp_2", mk("apache"))); err != nil {
		t.Fatal(err)
	}

	// 回放到 nginx 时刻 → service 应为 nginx。
	sub, err := s.SnapshotAt(ctx, MainBranchID, tNginx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.GetEntities()) != 1 {
		t.Fatalf("entities = %d, want 1", len(sub.GetEntities()))
	}
	got := sub.GetEntities()[0].GetAttributes()["service"]
	if got != "nginx" {
		t.Fatalf("replayed service = %q, want nginx (old version lost?)", got)
	}
	if v := sub.GetEntities()[0].GetVersion(); v != 1 {
		t.Fatalf("replayed version = %d, want 1", v)
	}
}

func TestSnapshotIDIsDeterministic(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

	a, err := s.SnapshotAt(ctx, MainBranchID, at, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.SnapshotAt(ctx, MainBranchID, at, 0)
	if err != nil {
		t.Fatal(err)
	}
	if a.GetSnapshotId() != b.GetSnapshotId() {
		t.Fatalf("snapshot_id not deterministic: %s vs %s", a.GetSnapshotId(), b.GetSnapshotId())
	}
}

// ---- T2.5：假设分支（DoD③ 回滚字节级一致）----

func TestBranchIsolation(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Ingest(ctx, spectrum("sp_main", assetDraft("10.40.23.5", 0.9))); err != nil {
		t.Fatal(err)
	}
	mainHashBefore, _ := s.StateHash(ctx, MainBranchID)

	br, err := s.CreateBranch(ctx, "hypothesis-ssrf", MainBranchID, "test SSRF hypothesis")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestInto(ctx,
		spectrum("sp_br", serviceDraft("10.40.23.5", "8080", "tomcat", 0.6)),
		br.GetBranchId()); err != nil {
		t.Fatal(err)
	}

	// 主分支不受影响（分支隔离契约）。
	mainHashAfter, _ := s.StateHash(ctx, MainBranchID)
	if mainHashBefore != mainHashAfter {
		t.Fatal("branch write leaked into main branch")
	}
	// 分支内软标记为假设。
	sub, err := s.Project(ctx, br.GetBranchId(), "", 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range sub.GetEntities() {
		if e.GetKind() == alethv1.EntityKind_SERVICE {
			found = true
			if !e.GetIsHypothesis() {
				t.Fatal("entity written to a branch must be marked is_hypothesis")
			}
		}
	}
	if !found {
		t.Fatal("branch entity missing")
	}
}

func TestRollbackBranchByteIdentical(t *testing.T) {
	// DoD③：回滚后图状态与"从未创建该分支"字节级一致。
	s, _ := newTestStore(t)
	ctx := context.Background()

	if _, err := s.Ingest(ctx, spectrum("sp_main", assetDraft("10.40.23.5", 0.9))); err != nil {
		t.Fatal(err)
	}
	before, _ := s.StateHash(ctx, MainBranchID)

	br, err := s.CreateBranch(ctx, "h1", MainBranchID, "rationale")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestInto(ctx,
		spectrum("sp_br1", serviceDraft("10.40.23.5", "8080", "tomcat", 0.6)),
		br.GetBranchId()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestInto(ctx,
		spectrum("sp_br2", assetDraft("10.40.23.99", 0.6)),
		br.GetBranchId()); err != nil {
		t.Fatal(err)
	}

	res, err := s.RollbackBranch(ctx, br.GetBranchId(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.GetByteIdentical() {
		t.Fatalf("rollback not byte-identical:\n before=%s\n after =%s",
			res.GetStateHashBefore(), res.GetStateHashAfter())
	}
	if res.GetStateHashBefore() != before {
		t.Fatalf("rollback baseline mismatch with pre-branch state")
	}
	if res.GetRolledBackEntityCount() == 0 {
		t.Fatal("rollback must report affected entity count")
	}

	// 回滚后主分支 hash 与分支前一致。
	after, _ := s.StateHash(ctx, MainBranchID)
	if after != before {
		t.Fatalf("main branch changed after rollback:\n before=%s\n after =%s", before, after)
	}
	// 分支内实体不可见（软删除生效）。
	sub, _ := s.Project(ctx, br.GetBranchId(), "", 0, 0, nil)
	if len(sub.GetEntities()) != 0 {
		t.Fatalf("rolled-back branch still exposes %d entities", len(sub.GetEntities()))
	}
}

func TestMergeRejectsUnverifiedHypotheses(t *testing.T) {
	// M2 §4.5：仅当分支实体全部通过 M4 闸门（非 Hypothesis）才允许合并。
	s, _ := newTestStore(t)
	ctx := context.Background()

	br, err := s.CreateBranch(ctx, "h1", MainBranchID, "rationale")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.IngestInto(ctx,
		spectrum("sp_br", assetDraft("10.40.23.77", 0.5)), br.GetBranchId()); err != nil {
		t.Fatal(err)
	}

	res, err := s.MergeBranch(ctx, br.GetBranchId(), MainBranchID)
	if err != nil {
		t.Fatal(err)
	}
	if res.GetMerged() {
		t.Fatal("merge must be rejected while branch contains unverified hypotheses")
	}
	if res.GetError() == nil {
		t.Fatal("rejection must carry an explicit error (not silent)")
	}

	// 把分支实体标记为已验证后，合并应成功。
	if _, err := s.db.Exec(
		`UPDATE entity SET is_hypothesis = 0 WHERE branch_id = ?`, br.GetBranchId()); err != nil {
		t.Fatal(err)
	}
	res2, err := s.MergeBranch(ctx, br.GetBranchId(), MainBranchID)
	if err != nil {
		t.Fatal(err)
	}
	if !res2.GetMerged() {
		t.Fatalf("merge should succeed after verification: %v", res2.GetError())
	}
	// 实体确实并入主分支。
	sub, _ := s.Project(ctx, MainBranchID, "", 0, 0, nil)
	if len(sub.GetEntities()) == 0 {
		t.Fatal("merged entity missing from main branch")
	}
}

func TestBranchLimitEnforced(t *testing.T) {
	// M2 §8：超限**拒绝创建**，不静默降级。
	s, _ := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < MaxConcurrentBranches; i++ {
		if _, err := s.CreateBranch(ctx, fmt.Sprintf("h%d", i), MainBranchID, "r"); err != nil {
			t.Fatalf("branch %d: %v", i, err)
		}
	}
	_, err := s.CreateBranch(ctx, "one-too-many", MainBranchID, "r")
	if err == nil {
		t.Fatal("creating beyond the branch limit must be refused")
	}
}

func TestMainBranchCannotBeRolledBack(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.RollbackBranch(context.Background(), MainBranchID, 0); err == nil {
		t.Fatal("rolling back the main branch must be refused")
	}
}

// ---- T2.6：七视图投影 ----

func TestProjectByKindFilter(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if _, err := s.Ingest(ctx, spectrum("sp_1",
		assetDraft("10.40.23.5", 0.9),
		serviceDraft("10.40.23.5", "80", "http", 0.9))); err != nil {
		t.Fatal(err)
	}

	sub, err := s.Project(ctx, MainBranchID, "", 0, 0,
		[]alethv1.EntityKind{alethv1.EntityKind_SERVICE})
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.GetEntities()) != 1 {
		t.Fatalf("filtered entities = %d, want 1", len(sub.GetEntities()))
	}
	if sub.GetEntities()[0].GetKind() != alethv1.EntityKind_SERVICE {
		t.Fatalf("kind filter not applied: %s", sub.GetEntities()[0].GetKind())
	}
}

func TestProjectFocusSubgraph(t *testing.T) {
	// 焦点投影：从资产出发 1 跳应带出该资产上的服务。
	s, _ := newTestStore(t)
	ctx := context.Background()
	if _, err := s.Ingest(ctx, spectrum("sp_1",
		assetDraft("10.40.23.5", 0.9),
		serviceDraft("10.40.23.5", "80", "http", 0.9),
		assetDraft("10.40.23.99", 0.9))); err != nil {
		t.Fatal(err)
	}
	assetID, _ := EntityID(alethv1.EntityKind_ASSET, map[string]string{"addr": "10.40.23.5"})

	sub, err := s.Project(ctx, MainBranchID, assetID, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 应含资产 + 其上的服务，不含无关资产。
	if len(sub.GetEntities()) != 2 {
		t.Fatalf("focused entities = %d, want 2 (asset + its service)", len(sub.GetEntities()))
	}
	for _, e := range sub.GetEntities() {
		if e.GetEntityId() == "" {
			t.Fatal("empty entity id")
		}
		if e.GetAttributes()["addr"] == "10.40.23.99" {
			t.Fatal("unrelated asset leaked into focused projection")
		}
	}
}

func TestProjectMaxEntitiesIsDeterministic(t *testing.T) {
	// 截断必须确定性（不依赖 map 顺序）—— 否则同一查询两次结果不同。
	s, _ := newTestStore(t)
	ctx := context.Background()
	var drafts []*alethv1.EntityDraft
	for i := 0; i < 10; i++ {
		drafts = append(drafts, assetDraft(fmt.Sprintf("10.40.23.%d", i+1), 0.9))
	}
	if _, err := s.Ingest(ctx, spectrum("sp_many", drafts...)); err != nil {
		t.Fatal(err)
	}
	a, _ := s.Project(ctx, MainBranchID, "", 0, 3, nil)
	b, _ := s.Project(ctx, MainBranchID, "", 0, 3, nil)
	if len(a.GetEntities()) != 3 {
		t.Fatalf("entities = %d, want 3", len(a.GetEntities()))
	}
	for i := range a.GetEntities() {
		if a.GetEntities()[i].GetEntityId() != b.GetEntities()[i].GetEntityId() {
			t.Fatal("truncation is not deterministic")
		}
	}
}

// ---- 凭据安全（M2 §6：Q5 类别）----

func TestCannotIngestEmptySpectrumID(t *testing.T) {
	s, _ := newTestStore(t)
	if _, err := s.Ingest(context.Background(),
		spectrum("", assetDraft("10.40.23.5", 0.9))); err == nil {
		t.Fatal("spectrum_id is the idempotency key; empty must be refused")
	}
}

func TestIngestIntoUnknownBranchRefused(t *testing.T) {
	s, _ := newTestStore(t)
	_, err := s.IngestInto(context.Background(),
		spectrum("sp_x", assetDraft("10.40.23.5", 0.9)), "br_does_not_exist")
	if err == nil {
		t.Fatal("ingest into a nonexistent branch must fail (not silently fall back to main)")
	}
}
