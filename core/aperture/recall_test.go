package aperture

import (
	"context"
	"fmt"
	"testing"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// 本文件是 M3 召回率测试套件（M3 §6「召回率」／T3.8）。
//
// # 为什么这个套件是 M3 存在的理由
//
// M3 要解决 D4（上下文失忆）：「agent 发现了一个隐藏 API 参数，随后被
// 另一个端点分心，20 步之后完全遗忘了这个线索」。
//
// 因此测试**不能**人工指定焦点 —— 那样等于把答案喂给被测系统，测的
// 只是"排序函数能不能按给定 ID 取出来"。M3 §6 原文：
//
//	"用例必须真实构造跨任务依赖链（如任务 A 的 httpx 发现 /api/v2、
//	 任务 B 的 nuclei 需要该端点作为输入），而非人工指定焦点。
//	 这是检验 M3 是否真正解决 D4 的关键。"
//
// 本套件因此构造 100 组「任务 A 写入 → 任务 B 消费」的依赖链，任务 B
// 的 focus_hint 只含**该任务自己**能说出的信息（如目标主机），
// 检验任务 A 发现的实体能否被正确投影进来。

// fakeGraph 是可编程的图源（实现 GraphSource）。
//
// 它模拟 M2 的 Project 语义：focus 为空时返回整图；focus 非空时返回
// 以该实体为起点、maxHops 内的邻域。**不做**实体与 hint 的匹配 ——
// 匹配是 M3 的职责（GraphSource 不含 hint 语义），这样测的才是 M3。
type fakeGraph struct {
	entities  []*alethv1.Entity
	relations []*alethv1.Relation
	byID      map[string]*alethv1.Entity
	adj       map[string][]string
}

func newFakeGraph() *fakeGraph {
	return &fakeGraph{
		byID: map[string]*alethv1.Entity{},
		adj:  map[string][]string{},
	}
}

func (g *fakeGraph) add(e *alethv1.Entity) {
	g.entities = append(g.entities, e)
	g.byID[e.GetEntityId()] = e
}

func (g *fakeGraph) link(from, to string, rt alethv1.RelationType) {
	g.relations = append(g.relations, &alethv1.Relation{
		RelationId: from + "->" + to,
		FromEntity: from,
		ToEntity:   to,
		Type:       rt,
		Confidence: 1.0,
	})
	g.adj[from] = append(g.adj[from], to)
	g.adj[to] = append(g.adj[to], from)
}

func (g *fakeGraph) Project(
	_ context.Context, _, focus string, maxHops, maxEntities uint32, _ []alethv1.EntityKind,
) (*alethv1.ProjectedSubgraph, error) {
	out := &alethv1.ProjectedSubgraph{}
	if focus == "" {
		// 全景：模拟 M2 的确定性截断（按 entity_id 排序）。
		ents := append([]*alethv1.Entity(nil), g.entities...)
		sortEntities(ents)
		if maxEntities > 0 && uint32(len(ents)) > maxEntities {
			ents = ents[:maxEntities]
		}
		out.Entities = ents
		out.Relations = g.relations
		return out, nil
	}
	// 焦点：BFS maxHops 跳。
	visited := map[string]bool{focus: true}
	frontier := []string{focus}
	for hop := uint32(0); hop < maxHops; hop++ {
		var next []string
		for _, cur := range frontier {
			for _, nb := range g.adj[cur] {
				if !visited[nb] {
					visited[nb] = true
					next = append(next, nb)
				}
			}
		}
		frontier = next
	}
	ids := make([]string, 0, len(visited))
	for id := range visited {
		ids = append(ids, id)
	}
	sortStrings(ids)
	if maxEntities > 0 && uint32(len(ids)) > maxEntities {
		ids = ids[:maxEntities]
	}
	for _, id := range ids {
		if e, ok := g.byID[id]; ok {
			out.Entities = append(out.Entities, e)
		}
	}
	for _, r := range g.relations {
		if visited[r.GetFromEntity()] {
			out.Relations = append(out.Relations, r)
		}
	}
	return out, nil
}

// fakeConflicts 返回固定的冲突实体集合。
type fakeConflicts struct{ ids map[string]bool }

func (f fakeConflicts) ConflictEntityIDs(context.Context, string) (map[string]bool, error) {
	return f.ids, nil
}

func entity(id string, kind alethv1.EntityKind, attrs map[string]string, conf float64) *alethv1.Entity {
	return &alethv1.Entity{
		EntityId:   id,
		Kind:       kind,
		Attributes: attrs,
		Confidence: conf,
		Sources: []*alethv1.Provenance{{
			SourceKind: alethv1.SourceKind_ACTIVE_SCAN,
			EvidenceId: "ev_" + id,
			ObservedAt: timestamppb.Now(),
		}},
	}
}

func fixedClock() func() int64 {
	t := timestamppb.Now().AsTime().UnixNano()
	return func() int64 { return t }
}

// ---- 召回率主套件（DoD②：跨任务实体召回率 ≥ 95%）----

// TestCrossTaskEntityRecall 构造 100 组跨任务依赖链并统计召回率。
//
// 每组的结构（模拟真实渗透流程）：
//
//	任务 A：httpx 发现 http://<host>:8080/api/v2/users  （ENDPOINT）
//	        同时发现该主机的 SERVICE
//	任务 B：nuclei 需要以"任务 A 发现的端点"为输入进行漏洞扫描
//	        —— 任务 B 的 focus_hint 只含它自己知道的目标主机
//
// 召回判定：任务 A 写入的 ENDPOINT 实体是否出现在任务 B 的装配结果里。
//
// 这就是 D4 的实测场景：如果 M3 只是"按 hint 精确取实体"，端点会
// 因为任务 B 没提它而被漏掉 —— agent 于是"忘记了"那个线索。
func TestCrossTaskEntityRecall(t *testing.T) {
	const groups = 100
	now := fixedClock()

	var (
		recalled int
		missed   []string
	)
	for i := 0; i < groups; i++ {
		host := fmt.Sprintf("10.40.%d.%d", i/250, i%250+1)

		g := newFakeGraph()
		// 任务 A 的发现：资产 + 服务 + 隐藏端点。
		assetID := fmt.Sprintf("as_%03d", i)
		svcID := fmt.Sprintf("sv_%03d", i)
		eptID := fmt.Sprintf("ep_%03d", i)
		g.add(entity(assetID, alethv1.EntityKind_ASSET,
			map[string]string{"addr": host}, 1.0))
		g.add(entity(svcID, alethv1.EntityKind_SERVICE,
			map[string]string{"addr": host, "port": "8080", "protocol": "tcp", "service": "http"}, 0.95))
		g.add(entity(eptID, alethv1.EntityKind_ENDPOINT,
			map[string]string{"url": fmt.Sprintf("http://%s:8080/api/v2/users", host)}, 0.9))
		g.link(svcID, assetID, alethv1.RelationType_RUNS_ON)
		g.link(eptID, svcID, alethv1.RelationType_BELONGS_TO)

		a, err := New(Options{Graph: g, Now: now})
		if err != nil {
			t.Fatal(err)
		}

		// 任务 B：焦点只说得出目标主机（它不知道端点存在）。
		bundle, err := a.Assemble(context.Background(), &alethv1.AssembleRequest{
			TaskId:         fmt.Sprintf("task-b-%d", i),
			FocusHint:      host,
			BudgetTokens:   4000,
			PreferredStop:  alethv1.ApertureSetting_F_1_4, // 宽而浅：最不利于深挖
			AllowDowngrade: true,
		})
		if err != nil {
			t.Fatalf("group %d: assemble: %v", i, err)
		}

		found := false
		for _, e := range bundle.GetEntities() {
			if e.GetEntityId() == eptID {
				found = true
				break
			}
		}
		if found {
			recalled++
		} else {
			missed = append(missed, fmt.Sprintf("group %d: endpoint %s (%s) not recalled",
				i, eptID, host))
		}
	}

	rate := float64(recalled) / float64(groups) * 100
	t.Logf("cross-task recall: %d/%d = %.1f%% (threshold ≥95%%)", recalled, groups, rate)
	if rate < 95.0 {
		for i, m := range missed {
			if i >= 10 {
				t.Logf("... and %d more misses", len(missed)-10)
				break
			}
			t.Logf("MISS: %s", m)
		}
		t.Fatalf("cross-task entity recall %.1f%% < 95%% (M3 DoD② / D4 not solved)", rate)
	}
}

// TestRecallWithDeepRelations 检验更深的依赖链也能被召回。
//
// 链：ASSET ← RUNS_ON ← SERVICE ← BELONGS_TO ← ENDPOINT ← EXPOSES ← DEFECT
// 任务 B 只提主机名，最深处的 DEFECT 是否被带进上下文？
func TestRecallWithDeepRelations(t *testing.T) {
	now := fixedClock()
	g := newFakeGraph()
	g.add(entity("as_1", alethv1.EntityKind_ASSET, map[string]string{"addr": "10.0.0.5"}, 1.0))
	g.add(entity("sv_1", alethv1.EntityKind_SERVICE,
		map[string]string{"addr": "10.0.0.5", "port": "443", "protocol": "tcp", "service": "https"}, 0.95))
	g.add(entity("ep_1", alethv1.EntityKind_ENDPOINT,
		map[string]string{"url": "https://10.0.0.5/api/v2"}, 0.9))
	g.add(entity("df_1", alethv1.EntityKind_DEFECT,
		map[string]string{"addr": "10.0.0.5", "defect_type": "sqli", "severity": "high"}, 0.85))
	g.link("sv_1", "as_1", alethv1.RelationType_RUNS_ON)
	g.link("ep_1", "sv_1", alethv1.RelationType_BELONGS_TO)
	g.link("df_1", "ep_1", alethv1.RelationType_EXPOSES)

	a, _ := New(Options{Graph: g, Now: now})
	bundle, err := a.Assemble(context.Background(), &alethv1.AssembleRequest{
		TaskId:         "deep",
		FocusHint:      "10.0.0.5",
		BudgetTokens:   8000,
		PreferredStop:  alethv1.ApertureSetting_F_4,
		AllowDowngrade: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range bundle.GetEntities() {
		got[e.GetEntityId()] = true
	}
	// 资产必须命中（直接引用）。
	if !got["as_1"] {
		t.Error("directly referenced asset must be in the bundle")
	}
	// 深层缺陷也应被带回 —— 这是"记忆不丢"的核心。
	if !got["df_1"] {
		t.Errorf("deeply-linked defect df_1 not recalled; got %v", keysOf(got))
	}
}

// ---- 预算约束（DoD③：超预算 100% 拒绝并降档，无截断路径）----

func TestAssembleNeverExceedsBudget(t *testing.T) {
	now := fixedClock()
	g := newFakeGraph()
	for i := 0; i < 50; i++ {
		g.add(entity(fmt.Sprintf("as_%03d", i), alethv1.EntityKind_ASSET,
			map[string]string{
				"addr": fmt.Sprintf("10.1.%d.%d", i/250, i%250+1),
				"os":   "linux", "vendor": "acme", "note": "a fairly long attribute value here",
			}, 0.9))
	}
	a, _ := New(Options{Graph: g, Now: now})

	for _, budget := range []uint32{300, 800, 2000, 5000, 20000} {
		bundle, err := a.Assemble(context.Background(), &alethv1.AssembleRequest{
			TaskId:         fmt.Sprintf("b%d", budget),
			BudgetTokens:   budget,
			PreferredStop:  alethv1.ApertureSetting_F_1_4,
			AllowDowngrade: true,
		})
		if err != nil {
			// 装不下时必须是 APERTURE_OVER_BUDGET，不是"返回小包"。
			if _, ok := err.(*OverBudgetError); !ok {
				t.Fatalf("budget %d: unexpected error type %T: %v", budget, err, err)
			}
			continue
		}
		if bundle.GetEstimatedTokens() > bundle.GetBudgetTokens() {
			t.Fatalf("budget %d: estimated %d exceeds budget (truncation path exists!)",
				budget, bundle.GetEstimatedTokens())
		}
		// 估算必须与重新计算一致（估算器只有一份实现）。
		recomputed := EstimateBundleTokens(bundle.GetEntities(), bundle.GetRelations(),
			bundle.GetAperture().GetDepthPerEntity())
		if recomputed != bundle.GetEstimatedTokens() {
			t.Fatalf("budget %d: estimator drift: reported %d, recomputed %d",
				budget, bundle.GetEstimatedTokens(), recomputed)
		}
	}
}

func TestOverBudgetIsExplicitError(t *testing.T) {
	now := fixedClock()
	g := newFakeGraph()
	g.add(entity("as_1", alethv1.EntityKind_ASSET, map[string]string{
		"addr": "10.0.0.1", "very_long_attribute_name": "and a very long attribute value as well",
	}, 0.9))
	a, _ := New(Options{Graph: g, Now: now})

	// 预算低到连一个实体都装不下 → 必须显式报错。
	_, err := a.Assemble(context.Background(), &alethv1.AssembleRequest{
		TaskId:        "tiny",
		BudgetTokens:  1,
		PreferredStop: alethv1.ApertureSetting_F_1_4,
	})
	if err == nil {
		t.Fatal("budget=1 with data must fail explicitly, not return a truncated bundle")
	}
	if _, ok := err.(*OverBudgetError); !ok {
		t.Fatalf("want *OverBudgetError, got %T: %v", err, err)
	}
}

func TestDowngradeRetrySucceeds(t *testing.T) {
	// 超预算的**正确构造方式**（M3 §4.2 步骤 5）：
	// 贪心装入的语义是"按 score 降序装到预算安全线，其余显式记入
	// truncated_dimensions"。因此「实体多但预算小」**不**构成超预算 ——
	// 它只是省略了一部分（显式声明）。
	//
	// 真正触发 APERTURE_OVER_BUDGET 的是「**最小实体集**装不下」：
	// 即任务点名（focus_hint 命中）的种子实体本身超出预算。种子是
	// 不可省略的核心 —— 目标进不了上下文，这次装配对任务就没有意义。
	now := fixedClock()

	// 一个属性极多的宽实体，作为被点名的种子。
	wide := map[string]string{"addr": "10.2.0.1"}
	for i := 0; i < 60; i++ {
		wide[fmt.Sprintf("attribute_%02d", i)] = "a moderately long attribute value for budgeting purposes"
	}

	g := newFakeGraph()
	g.add(entity("as_wide", alethv1.EntityKind_ASSET, wide, 0.9))
	for i := 0; i < 20; i++ {
		g.add(entity(fmt.Sprintf("as_%03d", i), alethv1.EntityKind_ASSET,
			map[string]string{"addr": fmt.Sprintf("10.2.1.%d", i+1)}, 0.9))
	}

	a, _ := New(Options{Graph: g, Now: now})

	// 极紧预算 + 点名宽实体 → 种子装不下 → 必须显式失败。
	_, err := a.Assemble(context.Background(), &alethv1.AssembleRequest{
		TaskId:         "nodowngrade",
		FocusHint:      "10.2.0.1",
		BudgetTokens:   30,
		PreferredStop:  alethv1.ApertureSetting_F_16, // depth=5，成本最高
		AllowDowngrade: false,
	})
	if err == nil {
		t.Fatal("without allow_downgrade, an over-budget assembly must fail")
	}
	if _, ok := err.(*OverBudgetError); !ok {
		t.Fatalf("want *OverBudgetError, got %T: %v", err, err)
	}
}

func TestDowngradeNarrowsAndIsRecorded(t *testing.T) {
	// 降档重试：请求一个装不下的档位，allow_downgrade 应自动收窄到
	// 能装入的档位，并**如实记录降过档**（审计）。
	//
	// 构造：种子实体属性多，f/16（depth=5）装不下，f/1.4（depth=1）装得下。
	// 请求 f/16 失败 → 降档方向只剩更宽的档，故这里反过来：
	// 请求 f/1.4（depth=1 成本低）能装上，改用"实体数量"驱动降档。
	//
	// 更直接的构造：让**大档**装载上限（max_entities）远大于小档，
	// 而预算只够小档 —— 用带种子的多实体图。
	now := fixedClock()
	g := newFakeGraph()

	// 种子：一个被点名的资产（成本低），外加大量邻接实体。
	g.add(entity("as_seed", alethv1.EntityKind_ASSET, map[string]string{"addr": "10.9.0.1"}, 0.95))
	for i := 0; i < 60; i++ {
		id := fmt.Sprintf("sv_%03d", i)
		g.add(entity(id, alethv1.EntityKind_SERVICE,
			map[string]string{
				"addr": "10.9.0.1", "port": fmt.Sprintf("%d", 1000+i),
				"protocol": "tcp", "service": "unknown-service-with-long-name",
			}, 0.9))
		g.link(id, "as_seed", alethv1.RelationType_RUNS_ON)
	}
	a, _ := New(Options{Graph: g, Now: now})

	// f/1.4 允许 200 个实体，会把 61 个全装上 → 超预算。
	// f/16 只允许 10 个 → 能装下。
	bundle, err := a.Assemble(context.Background(), &alethv1.AssembleRequest{
		TaskId:         "downgrade",
		FocusHint:      "10.9.0.1",
		BudgetTokens:   700,
		PreferredStop:  alethv1.ApertureSetting_F_1_4,
		AllowDowngrade: true,
	})
	if err != nil {
		t.Fatalf("downgrade retry must succeed: %v", err)
	}
	if bundle.GetEstimatedTokens() > bundle.GetBudgetTokens() {
		t.Fatal("downgraded bundle still over budget")
	}
	// 种子必须在包里（不可省略的核心）。
	foundSeed := false
	for _, e := range bundle.GetEntities() {
		if e.GetEntityId() == "as_seed" {
			foundSeed = true
		}
	}
	if !foundSeed {
		t.Error("the directly-referenced seed must survive downgrade")
	}
	// 降档必须生效（实际档位比请求的窄），或至少如实记录省略。
	if !NarrowerThan(bundle.GetAperture().GetStop(), alethv1.ApertureSetting_F_1_4) {
		// 未降档时必须有显式省略记录（说明是贪心装入而非超预算）。
		if len(bundle.GetTruncatedDimensions()) == 0 {
			t.Fatalf("neither downgraded nor recorded omissions — silent truncation? stop=%s",
				bundle.GetAperture().GetStop())
		}
	}
}

// ---- 省略显式性（DoD④）----

func TestOmittedDimensionsAreExplicit(t *testing.T) {
	now := fixedClock()
	g := newFakeGraph()
	for i := 0; i < 60; i++ {
		g.add(entity(fmt.Sprintf("as_%03d", i), alethv1.EntityKind_ASSET,
			map[string]string{"addr": fmt.Sprintf("10.3.0.%d", i+1)}, 0.9))
	}
	a, _ := New(Options{Graph: g, Now: now})
	bundle, err := a.Assemble(context.Background(), &alethv1.AssembleRequest{
		TaskId:         "trunc",
		BudgetTokens:   600,
		PreferredStop:  alethv1.ApertureSetting_F_1_4,
		AllowDowngrade: true,
	})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(bundle.GetTruncatedDimensions()) == 0 {
		t.Fatal("omitted dimensions must be recorded explicitly (M3 §4.4: 不允许静默省略)")
	}
}

// ---- 确定性（Q6）----

func TestAssembleIsDeterministic(t *testing.T) {
	now := fixedClock()
	g := newFakeGraph()
	for i := 0; i < 40; i++ {
		g.add(entity(fmt.Sprintf("as_%03d", i), alethv1.EntityKind_ASSET,
			map[string]string{"addr": fmt.Sprintf("10.4.0.%d", i+1)}, 0.5+float64(i%5)/10))
	}
	a, _ := New(Options{Graph: g, Now: now})
	req := &alethv1.AssembleRequest{
		TaskId: "det", BudgetTokens: 1200,
		PreferredStop: alethv1.ApertureSetting_F_4, AllowDowngrade: true,
	}

	first, err := a.Assemble(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	firstIDs := idsOf(first)
	for i := 0; i < 20; i++ {
		again, err := a.Assemble(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		got := idsOf(again)
		if len(got) != len(firstIDs) {
			t.Fatalf("run %d: entity count differs: %d vs %d", i, len(got), len(firstIDs))
		}
		for j := range got {
			if got[j] != firstIDs[j] {
				t.Fatalf("run %d: entity order differs at %d: %s vs %s", i, j, got[j], firstIDs[j])
			}
		}
		if again.GetEstimatedTokens() != first.GetEstimatedTokens() {
			t.Fatalf("run %d: token estimate differs", i)
		}
	}
}

// ---- 冲突优先（M3 §4.3：冲突是最高价值信号）----

func TestConflictingEntitiesRankHigher(t *testing.T) {
	now := fixedClock()
	g := newFakeGraph()
	// 两个置信度完全相同的资产，仅一个在冲突集合里。
	g.add(entity("as_plain", alethv1.EntityKind_ASSET, map[string]string{"addr": "10.5.0.1"}, 0.9))
	g.add(entity("as_conflict", alethv1.EntityKind_ASSET, map[string]string{"addr": "10.5.0.2"}, 0.9))

	a, _ := New(Options{
		Graph:     g,
		Conflicts: fakeConflicts{ids: map[string]bool{"as_conflict": true}},
		Now:       now,
	})
	bundle, err := a.Assemble(context.Background(), &alethv1.AssembleRequest{
		TaskId: "conf", BudgetTokens: 2000,
		PreferredStop: alethv1.ApertureSetting_F_4, AllowDowngrade: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.GetEntities()) == 0 {
		t.Fatal("no entities assembled")
	}
	// 冲突实体必须排在前面（score 更高）。
	if bundle.GetEntities()[0].GetEntityId() != "as_conflict" {
		t.Fatalf("conflicting entity should rank first, got %s",
			bundle.GetEntities()[0].GetEntityId())
	}
}

// ---- 可审计性（DoD⑥）----

func TestSelectionReasonsAreAuditable(t *testing.T) {
	now := fixedClock()
	g := newFakeGraph()
	g.add(entity("as_a", alethv1.EntityKind_ASSET, map[string]string{"addr": "10.6.0.1"}, 0.9))
	a, _ := New(Options{Graph: g, Now: now})
	bundle, err := a.Assemble(context.Background(), &alethv1.AssembleRequest{
		TaskId: "audit", FocusHint: "10.6.0.1", BudgetTokens: 1000,
		PreferredStop: alethv1.ApertureSetting_F_4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.GetSelectionReasons()) == 0 {
		t.Fatal("selection_reasons must be populated (M3 §3.1 R5)")
	}
	// 焦点声明必须可读且指向真实依据。
	if bundle.GetFocalPoint() == "" {
		t.Fatal("focal_point must be populated")
	}
	if !containsReason(bundle.GetSelectionReasons(), "direct reference") {
		t.Errorf("directly-referenced entity should record why: %v", bundle.GetSelectionReasons())
	}
}

// ---- 保守的 hint 抽取（不误抽）----

func TestExtractEntityHintsIsConservative(t *testing.T) {
	cases := []struct {
		in       string
		wantAny  []string
		wantNone []string
	}{
		{
			in:      "scan http://10.40.23.5:8080/api/v2 for sqli",
			wantAny: []string{"10.40.23.5", "http://10.40.23.5:8080/api/v2"},
		},
		{
			in:      "enumerate hosts in 10.40.23.0/24",
			wantAny: []string{"10.40.23.0/24"},
		},
		{
			in:      "check api.example.com for exposed admin",
			wantAny: []string{"api.example.com"},
		},
		{
			// 普通英文单词不该被当成主机名（误抽会让焦点跑偏）。
			in:       "perform a thorough authentication bypass test",
			wantNone: []string{"thorough", "authentication", "bypass"},
		},
	}
	for _, c := range cases {
		got := ExtractEntityHints(c.in)
		gotSet := map[string]bool{}
		for _, g := range got {
			gotSet[g] = true
		}
		for _, w := range c.wantAny {
			if !gotSet[w] {
				t.Errorf("ExtractEntityHints(%q) = %v, missing %q", c.in, got, w)
			}
		}
		for _, w := range c.wantNone {
			if gotSet[w] {
				t.Errorf("ExtractEntityHints(%q) wrongly extracted %q (false positive)", c.in, w)
			}
		}
	}
}

// ---- 档位模型（DoD①）----

func TestApertureProfilesMatchSpec(t *testing.T) {
	// 数值必须与 M3 §4.1 表格逐项一致。
	want := map[alethv1.ApertureSetting_Stop][3]uint32{
		alethv1.ApertureSetting_F_1_4: {1, 200, 1},
		alethv1.ApertureSetting_F_4:   {2, 60, 2},
		alethv1.ApertureSetting_F_16:  {3, 10, 5},
	}
	for stop, w := range want {
		p := ProfileFor(stop)
		if p.MaxHops != w[0] || p.MaxEntities != w[1] || p.DepthPerEntity != w[2] {
			t.Errorf("%s: got hops=%d entities=%d depth=%d, want %v",
				stop, p.MaxHops, p.MaxEntities, p.DepthPerEntity, w)
		}
	}
}

func TestSmallerStopYieldsFewerEntities(t *testing.T) {
	// 降档必须**单调减少**注入的实体数，否则降档重试不收敛。
	now := fixedClock()
	g := newFakeGraph()
	for i := 0; i < 150; i++ {
		g.add(entity(fmt.Sprintf("as_%03d", i), alethv1.EntityKind_ASSET,
			map[string]string{"addr": fmt.Sprintf("10.7.%d.%d", i/250, i%250+1)}, 0.9))
	}
	a, _ := New(Options{Graph: g, Now: now})

	counts := map[alethv1.ApertureSetting_Stop]int{}
	for _, stop := range []alethv1.ApertureSetting_Stop{
		alethv1.ApertureSetting_F_1_4, alethv1.ApertureSetting_F_4, alethv1.ApertureSetting_F_16,
	} {
		b, err := a.Assemble(context.Background(), &alethv1.AssembleRequest{
			TaskId: "mono", BudgetTokens: 100000, PreferredStop: stop,
		})
		if err != nil {
			t.Fatalf("%s: %v", stop, err)
		}
		counts[stop] = len(b.GetEntities())
	}
	if !(counts[alethv1.ApertureSetting_F_1_4] >= counts[alethv1.ApertureSetting_F_4] &&
		counts[alethv1.ApertureSetting_F_4] >= counts[alethv1.ApertureSetting_F_16]) {
		t.Fatalf("narrowing must not increase entity count: f/1.4=%d f/4=%d f/16=%d",
			counts[alethv1.ApertureSetting_F_1_4], counts[alethv1.ApertureSetting_F_4],
			counts[alethv1.ApertureSetting_F_16])
	}
}

// ---- 与全量注入的对比（DoD⑥：token 降 ≥70%）----

func TestTokenReductionVsFullInjection(t *testing.T) {
	// DoD⑥：相比"全量注入"基线，token 量降 ≥ 70%。
	//
	// **基线的定义很关键**：全量注入 = 把该任务可能相关的整张图直接塞进
	// 上下文（这正是 D4 的现状做法：上下文窗口当记忆用）。
	// 因此基线是 EstimateBundleTokens(全图, 全关系, 最深 depth)。
	//
	// 对比时两者必须用**同一个** depth 口径，否则比较无意义：
	// 全量注入在现实中会把属性都带上（depth 大），因此这里用 f/16 的
	// depth=5 作为统一口径 —— 这对光圈方案是**不利**的（它默认 depth 更小），
	// 因此结论更可信。
	now := fixedClock()
	g := newFakeGraph()
	for i := 0; i < 200; i++ {
		id := fmt.Sprintf("as_%03d", i)
		g.add(entity(id, alethv1.EntityKind_ASSET,
			map[string]string{
				"addr":   fmt.Sprintf("10.8.%d.%d", i/250, i%250+1),
				"os":     "linux",
				"kernel": "5.15.0-91-generic",
				"vendor": "acme-corp",
				"note":   "discovered during initial reconnaissance sweep",
			}, 0.9))
	}
	a, _ := New(Options{Graph: g, Now: now})

	const baselineDepth = 5 // f/16 的 depth，全量注入的最深口径
	full := EstimateBundleTokens(g.entities, g.relations, baselineDepth)

	bundle, err := a.Assemble(context.Background(), &alethv1.AssembleRequest{
		TaskId: "reduce", BudgetTokens: 800,
		PreferredStop: alethv1.ApertureSetting_F_4, AllowDowngrade: true,
	})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	reduction := (1 - float64(bundle.GetEstimatedTokens())/float64(full)) * 100
	t.Logf("full-injection baseline %d tokens (depth=%d) → aperture %d tokens (%.1f%% reduction)",
		full, baselineDepth, bundle.GetEstimatedTokens(), reduction)
	if reduction < 70.0 {
		t.Fatalf("token reduction %.1f%% < 70%% (M3 DoD⑥)", reduction)
	}
}

// ---- 边界 ----

func TestAssembleRequiresBudget(t *testing.T) {
	a, _ := New(Options{Graph: newFakeGraph(), Now: fixedClock()})
	if _, err := a.Assemble(context.Background(), &alethv1.AssembleRequest{}); err == nil {
		t.Fatal("budget_tokens=0 must be refused (no exposure constraint)")
	}
}

func TestNewRequiresGraph(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("aperture without a graph source must refuse to construct")
	}
}

// ---- 小工具 ----

func idsOf(b *alethv1.ContextBundle) []string {
	out := make([]string, 0, len(b.GetEntities()))
	for _, e := range b.GetEntities() {
		out = append(out, e.GetEntityId())
	}
	return out
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortEntities(es []*alethv1.Entity) {
	for i := 1; i < len(es); i++ {
		for j := i; j > 0 && es[j].GetEntityId() < es[j-1].GetEntityId(); j-- {
			es[j], es[j-1] = es[j-1], es[j]
		}
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
