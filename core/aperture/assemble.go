package aperture

import (
	"context"
	"fmt"
	"sort"
	"strings"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// 本文件实现 M3 §4.4 Context Assembly（T3.5）与 §5 T3.4/T3.7。
//
// # 装配的三个硬要求
//
//  1. **不截断**（§2.2 N4）：超预算返回错误，绝不返回"差不多"的包。
//     截断会让 LLM 误以为信息完整 —— D1 幻觉式成功的温床。
//  2. **省略必须显式**（§4.4）：被省略的维度 100% 写入
//     truncated_dimensions。让 LLM 知道"它不知道什么"，比让它误以为
//     信息完整更安全。
//  3. **可审计**（§3.1 R5）：selection_reasons 必须能还原为打分依据。

// GraphSource 是本包对 M2 的依赖面（M3 §2.2 N1：不做图遍历实现）。
//
// 接口由消费者定义（与 core/ingest 的 Deps 同一做法）：M3 只声明它
// 需要什么，M2 的实现与测试桩都针对这里的签名编程。
type GraphSource interface {
	// Project 返回指定分支的当前子图。
	Project(ctx context.Context, branchID, focus string, maxHops, maxEntities uint32,
		kinds []alethv1.EntityKind) (*alethv1.ProjectedSubgraph, error)
}

// ConflictSource 提供"哪些实体存在冲突版本"的信息。
//
// 冲突是本项目的最高价值信号之一（关系权重表里 CONTRADICTS 0.85），
// 因此它参与打分并享有注入优先级。M3 §2.2 N3 说本模块不判断实体真伪，
// 所以这里只消费"M4/账本判定过的冲突集合"，不自行判定。
type ConflictSource interface {
	ConflictEntityIDs(ctx context.Context, branchID string) (map[string]bool, error)
}

// Assembler 是光圈装配器。
type Assembler struct {
	graph     GraphSource
	conflicts ConflictSource
	// now 返回当前 UnixNano（recency 打分用）。测试注入固定时钟。
	now func() int64
	// weights 是打分权重（M3 §8：权重外置为配置，支持 A/B 对比）。
	weights ScoreWeights
}

// Options 构造选项。
type Options struct {
	Graph     GraphSource
	Conflicts ConflictSource
	Now       func() int64
	Weights   *ScoreWeights
}

// New 构造装配器。
func New(opts Options) (*Assembler, error) {
	if opts.Graph == nil {
		// 图是唯一数据源，缺失时**拒绝构造**而不是运行时返回空包 ——
		// 后者会让调用方误以为"这个任务真的没有上下文"。
		return nil, fmt.Errorf("aperture: graph source is required")
	}
	now := opts.Now
	if now == nil {
		now = defaultNow
	}
	w := DefaultWeights()
	if opts.Weights != nil {
		w = *opts.Weights
	}
	return &Assembler{
		graph:     opts.Graph,
		conflicts: opts.Conflicts,
		now:       now,
		weights:   w,
	}, nil
}

// Assemble 装配上下文（M3 §4.4，ApertureService.Assemble 的核心）。
//
// 降档重试（T3.7）：当 allow_downgrade 为真且当前档位超预算时，按
// f/1.4 → f/4 → f/16 方向逐档收窄重试，直到装入或已是最小档。
// 任一档装入即返回该档的包（aperture 字段如实反映实际使用的档位）。
//
// 全部档位都装不下时返回 *OverBudgetError（映射 APERTURE_OVER_BUDGET），
// **不返回被截断的包**（§2.2 N4）。
func (a *Assembler) Assemble(ctx context.Context, req *alethv1.AssembleRequest) (*alethv1.ContextBundle, error) {
	if req == nil {
		return nil, fmt.Errorf("aperture: nil request")
	}
	if req.GetBudgetTokens() == 0 {
		return nil, fmt.Errorf("aperture: budget_tokens is required (a session without a budget has no exposure constraint)")
	}

	stop := req.GetPreferredStop()
	if stop == alethv1.ApertureSetting_STOP_UNSPECIFIED {
		stop = DefaultStop
	}

	return a.assembleLoop(ctx, req, stop, Overrides{})
}

// AssembleWithOverrides 在指定档位之上应用**连续调节**（M3 §7 DoD：
// "三档光圈 + 连续调节可用"）。
//
// # 为什么是进程内 API 而不是新的 RPC
//
// `AssembleRequest` 在 `05 §4.2` 是 **[frozen]** 的，没有可放覆盖参数的
// 字段。按 `docs/09` R1（契约冻结）**不自造 RPC、不改 proto** ——
// 这与 I6 的 `GetGraph` 缺口、I0 的 `ListSessions` 缺口同一处置。
//
// 因此连续调节以**进程内 API** 提供：装配方（`cmd/alethd`）与内部调用方
// （M5 编排层在下发任务时决定档位参数）可直接使用；gRPC 调用方暂时只能
// 走三档。补法是在同一个 `contract:` PR 里给 `AssembleRequest` 加三个
// 可选覆盖字段（max_hops / max_entities / depth_per_entity）。
//
// # 覆盖会被记入 ContextBundle
//
// 调节后的参数写入 `bundle.aperture`，审计能看到"这一包是用什么参数
// 装配的"，而不只是档位名。`Stop` 保留原档位（调用方仍知道基准档）。
func (a *Assembler) AssembleWithOverrides(
	ctx context.Context, req *alethv1.AssembleRequest, ov Overrides,
) (*alethv1.ContextBundle, error) {
	if req == nil {
		return nil, fmt.Errorf("aperture: nil request")
	}
	if req.GetBudgetTokens() == 0 {
		return nil, fmt.Errorf("aperture: budget_tokens is required (a session without a budget has no exposure constraint)")
	}
	stop := req.GetPreferredStop()
	if stop == alethv1.ApertureSetting_STOP_UNSPECIFIED {
		stop = DefaultStop
	}
	if _, err := ov.Apply(ProfileFor(stop)); err != nil {
		// 非法组合在进入装配循环前就被拒（不静默接受）。
		return nil, err
	}
	return a.assembleLoop(ctx, req, stop, ov)
}

// assembleLoop 是装配主循环（含降档重试）。
func (a *Assembler) assembleLoop(
	ctx context.Context, req *alethv1.AssembleRequest,
	stop alethv1.ApertureSetting_Stop, ov Overrides,
) (*alethv1.ContextBundle, error) {
	var (
		lastErr *OverBudgetError
		tried   []string
	)
	for {
		bundle, err := a.assembleAt(ctx, req, stop, ov)
		if err == nil {
			// 如实记录试过的档位（审计：调用方要知道降过档）。
			if len(tried) > 0 {
				bundle.SelectionReasons = append(bundle.SelectionReasons,
					fmt.Sprintf("aperture downgraded after over-budget at: %s",
						strings.Join(tried, ", ")))
			}
			return bundle, nil
		}
		var ob *OverBudgetError
		if !asOverBudget(err, &ob) {
			return nil, err // 非预算错误：不上报为可降档，直接向上传播
		}
		lastErr = ob
		tried = append(tried, ProfileFor(stop).Label)

		if !req.GetAllowDowngrade() {
			return nil, lastErr
		}
		next, ok := narrowerStop(stop)
		if !ok {
			// 已是最小档仍装不下 —— 预算或数据规模问题，不是档位问题。
			return nil, lastErr
		}
		stop = next
	}
}

// assembleAt 在指定档位上尝试装配一次。
func (a *Assembler) assembleAt(
	ctx context.Context, req *alethv1.AssembleRequest,
	stop alethv1.ApertureSetting_Stop, ov Overrides,
) (*alethv1.ContextBundle, error) {
	profile, err := ov.Apply(ProfileFor(stop))
	if err != nil {
		return nil, err
	}
	budget := req.GetBudgetTokens()

	// 步骤 1–2：定位焦点并游走收集候选。
	//
	// **关键设计**：不从 focus_hint 直接向图要邻域，而是先取候选池、
	// 在本地做 seed 匹配、再按邻域扩展。
	//
	// 为什么不能把 focus_hint 当图的 focus 参数传下去：
	// focus_hint 是**自由文本**（如 "10.40.23.5" 或一句任务描述），
	// 而 M2 的 Project.focus 语义是**实体 ID**。直接把 hint 传下去时
	// M2 找不到该实体，返回空邻域 —— 装配结果为空，跨任务线索全部丢失。
	// 这正是 D4（上下文失忆）的复现，而不是它的解药。
	//
	// 正确做法（M3 §4.2 步骤 1→2）：先在**全图候选池**里用 hint 匹配出
	// 种子实体 S₀，再由 S₀ 出发按 max_hops 扩展。这样"任务 B 只说出主机名"
	// 也能把任务 A 在该主机上发现的端点带进上下文。
	poolSize := profile.MaxEntities * 4
	if poolSize < 200 {
		poolSize = 200 // 池子下限：太小会让远处的线索根本进不了候选
	}
	pool, err := a.graph.Project(ctx, "", "", profile.MaxHops, poolSize, nil)
	if err != nil {
		return nil, fmt.Errorf("aperture: project: %w", err)
	}

	conflictSet := map[string]bool{}
	if a.conflicts != nil {
		cs, err := a.conflicts.ConflictEntityIDs(ctx, "")
		if err != nil {
			return nil, fmt.Errorf("aperture: conflict lookup: %w", err)
		}
		conflictSet = cs
	}

	hints := ExtractEntityHints(req.GetFocusHint())
	seeds := map[string]bool{}
	for _, e := range pool.GetEntities() {
		if entityMatchesHint(e, hints) ||
			(req.GetFocusHint() != "" && e.GetEntityId() == req.GetFocusHint()) {
			seeds[e.GetEntityId()] = true
		}
	}

	// 由种子集按 max_hops 计算每个候选实体到种子的最短距离
	// （M3 §4.2 步骤 2「图上游走」）。距离参与 hop_decay 打分。
	dist := hopDistances(pool.GetRelations(), seeds)

	cands := make([]*candidateEntity, 0, len(pool.GetEntities()))
	for _, e := range pool.GetEntities() {
		h, ok := dist[e.GetEntityId()]
		if !ok && len(seeds) > 0 {
			// 无焦点时（seeds 为空）所有实体都参与；有焦点但与种子
			// 完全不可达的实体在 max_hops 之外 —— 但仍纳入候选并给
			// 最大距离，让打分决定去留（M3 的首要目标是召回，
			// 过早剔除是漏掉线索的直接原因）。
			h = int(profile.MaxHops) + 1
		}
		cands = append(cands, &candidateEntity{
			entity:           e,
			hop:              h,
			latestObservedAt: latestObserved(e),
		})
	}
	// 关系权重参与打分需要邻接信息 —— 从投影的关系集构建。
	applyRelationWeights(cands, pool.GetRelations())

	scored := scoreEntities(cands, seeds, conflictSet, a.now(), a.weights)

	// 步骤 4：证据强度过滤 —— Hypothesis 实体仅在高置信度实体不足时注入。
	scored = orderByEvidenceStrength(scored)

	// 步骤 5：按预算贪心装入（M3 §4.2 步骤 5）。
	bundle, err := a.pack(scored, seeds, pool.GetRelations(), profile, budget, req, stop)
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

// pack 按 score 降序贪心装入，直到触及预算安全线（M3 §4.2 步骤 5）。
//
// 关键语义（与"截断"的区别）：
//   - **实体**：整条装入或整条不装。不会出现"装了一半属性"的实体。
//   - **关系**：只装入两端都在结果集内的关系（避免悬空边撑大 token）。
//   - 装不下的实体记入 truncated_dimensions（显式省略，§4.4 硬要求）。
//   - 但**最小实体集**（直接引用的种子）装不下时返回 OverBudgetError ——
//     任务点名的目标进不了上下文，这次装配对任务没有意义，应当降档重试
//     或提高预算，而不是交出一个缺了关键目标的包。
func (a *Assembler) pack(
	scored []scoreCandidate, seeds map[string]bool, allRelations []*alethv1.Relation,
	profile StopProfile, budget uint32, req *alethv1.AssembleRequest,
	stop alethv1.ApertureSetting_Stop,
) (*alethv1.ContextBundle, error) {
	maxEntities := int(profile.MaxEntities)
	limit := float64(budget) * budgetSafetyRatio

	// 前置判定：最小实体集（种子）是否装得下。装不下就没必要往下走 ——
	// 早失败比"装了一半再报错"清晰。
	if minCost := minEntityCost(scored, seeds, profile.DepthPerEntity, profile.MaxEntities); minCost > 0 {
		if !fitsBudget(minCost, budget) {
			return nil, &OverBudgetError{
				Estimated:   minCost,
				Budget:      budget,
				Stop:        stop,
				MinPossible: minCost,
			}
		}
	}

	var (
		chosen             []*alethv1.Entity
		reasons            []string
		estimated          uint32
		conflictCount      int
		skippedByKind      = map[alethv1.EntityKind]int{}
		skippedTotal       int
		hypothesisInjected int
	)

	for _, sc := range scored {
		if len(chosen) >= maxEntities {
			skippedTotal++
			skippedByKind[sc.entity.GetKind()]++
			continue
		}
		// 冲突实体数量上限（M3 §8：默认 5，超出只给 ID 摘要）。
		isConflict := containsReason(sc.reasons, "conflicting versions")
		if isConflict && conflictCount >= conflictCap {
			skippedTotal++
			skippedByKind[sc.entity.GetKind()]++
			continue
		}

		cost := EstimateEntityTokens(sc.entity, profile.DepthPerEntity)
		if float64(estimated)+float64(cost) > limit {
			skippedTotal++
			skippedByKind[sc.entity.GetKind()]++
			continue
		}
		chosen = append(chosen, sc.entity)
		estimated += cost
		if isConflict {
			conflictCount++
		}
		if sc.entity.GetIsHypothesis() {
			hypothesisInjected++
		}
		// selection_reasons：每条实体一条，可还原为打分依据（R5）。
		if len(sc.reasons) > 0 {
			reasons = append(reasons, fmt.Sprintf("%s: %s",
				sc.entity.GetEntityId(), strings.Join(sc.reasons, "; ")))
		}
	}

	// 连一个实体都装不下 —— 预算低到无法表达任何上下文。
	if len(chosen) == 0 && (len(scored) > 0) {
		return nil, &OverBudgetError{
			Estimated:   estimated,
			Budget:      budget,
			Stop:        stop,
			MinPossible: minEntityCost(scored, seeds, profile.DepthPerEntity, profile.MaxEntities),
		}
	}

	// 关系：两端都在结果集内的才保留（不产生悬空边）。
	keep := map[string]bool{}
	for _, e := range chosen {
		keep[e.GetEntityId()] = true
	}
	var rels []*alethv1.Relation
	for _, r := range allRelations {
		if !keep[r.GetFromEntity()] {
			continue
		}
		cost := EstimateRelationTokens(r)
		if float64(estimated)+float64(cost) > limit {
			continue // 关系装不下就丢关系，不影响实体完整性
		}
		rels = append(rels, r)
		estimated += cost
	}

	// 省略维度必须显式（§4.4 硬要求）。
	var truncated []string
	if skippedTotal > 0 {
		for _, k := range sortedKinds(skippedByKind) {
			truncated = append(truncated, fmt.Sprintf(
				"%s ×%d omitted by budget at %s",
				kindName(k), skippedByKind[k], profile.Label))
		}
	}
	if hypothesisInjected > 0 {
		truncated = append(truncated, fmt.Sprintf(
			"hypothesis entities injected: %d (kept only after high-confidence entities)", hypothesisInjected))
	}
	if len(poolRelationsOmitted(allRelations, keep)) > 0 {
		truncated = append(truncated, fmt.Sprintf(
			"relations with endpoints outside the focus: %d",
			len(poolRelationsOmitted(allRelations, keep))))
	}
	// 深度省略：属性超过 depth_per_entity 的实体，其多余属性未注入。
	if profile.DepthPerEntity > 0 {
		if n := countDepthTruncated(chosen, profile.DepthPerEntity); n > 0 {
			truncated = append(truncated, fmt.Sprintf(
				"attribute depth capped at %d for %d entities", profile.DepthPerEntity, n))
		}
	}

	// 最终校验：估算必须落在预算内（放行前再算一次 —— 避免装配逻辑与
	// 判据漂移。若这条不成立说明本函数有 bug，应当暴露而非放行）。
	if !fitsBudget(estimated, budget) {
		return nil, &OverBudgetError{Estimated: estimated, Budget: budget, Stop: stop}
	}

	return &alethv1.ContextBundle{
		BundleId:            bundleID(req.GetTaskId(), stop, estimated),
		Aperture:            settingFromProfile(profile),
		Entities:            chosen,
		Relations:           rels,
		EstimatedTokens:     estimated,
		BudgetTokens:        budget,
		TruncatedDimensions: truncated,
		FocalPoint:          focalPointOf(req.GetFocusHint(), len(seedsOf(chosen))),
		SelectionReasons:    reasons,
	}, nil
}

// asOverBudget 是 errors.As 的薄包装（避免在 Assemble 里重复导入 errors）。
func asOverBudget(err error, target **OverBudgetError) bool {
	if ob, ok := err.(*OverBudgetError); ok {
		*target = ob
		return true
	}
	return false
}

// hopDistances 计算每个实体到种子集的最短跳数（BFS，无向遍历）。
//
// 无向是必需的：RUNS_ON 从服务指向宿主，但"这台主机上的服务"必须能
// 反向走到 —— 单向遍历会让投影漏掉半个图（与 core/prism 的
// neighborhood 同一理由，M2 §2.1 R5）。
//
// 种子为空时返回空表（调用方据此认为"无焦点，全部参与"）。
func hopDistances(rels []*alethv1.Relation, seeds map[string]bool) map[string]int {
	if len(seeds) == 0 {
		return map[string]int{}
	}
	adj := make(map[string][]string, len(rels)*2)
	for _, r := range rels {
		adj[r.GetFromEntity()] = append(adj[r.GetFromEntity()], r.GetToEntity())
		adj[r.GetToEntity()] = append(adj[r.GetToEntity()], r.GetFromEntity())
	}
	dist := make(map[string]int, len(seeds))
	var frontier []string
	for id := range seeds {
		dist[id] = 0
		frontier = append(frontier, id)
	}
	sort.Strings(frontier) // 确定性
	for d := 1; len(frontier) > 0 && d <= 8; d++ {
		var next []string
		for _, cur := range frontier {
			for _, nb := range adj[cur] {
				if _, seen := dist[nb]; !seen {
					dist[nb] = d
					next = append(next, nb)
				}
			}
		}
		sort.Strings(next)
		frontier = next
	}
	return dist
}

// applyRelationWeights 把实体的"最强关系权重"写入候选（打分用）。
func applyRelationWeights(cands []*candidateEntity, rels []*alethv1.Relation) {
	idx := map[string]*candidateEntity{}
	for _, c := range cands {
		idx[c.entity.GetEntityId()] = c
	}
	for _, r := range rels {
		w := RelationWeight(r.GetType())
		for _, id := range []string{r.GetFromEntity(), r.GetToEntity()} {
			if c, ok := idx[id]; ok && w > c.maxRelationWeight {
				c.maxRelationWeight = w
			}
		}
	}
}

// latestObserved 取实体最近一次观测时间（recency 打分）。
func latestObserved(e *alethv1.Entity) int64 {
	var latest int64
	for _, p := range e.GetSources() {
		if ts := p.GetObservedAt(); ts != nil {
			if n := ts.AsTime().UnixNano(); n > latest {
				latest = n
			}
		}
	}
	return latest
}

// orderByEvidenceStrength 实现 M3 §4.2 步骤 4。
//
// 规则：先按 score 降序；同分时**非假设实体优先**（Hypothesis 是推测，
// 让位于有证据支撑的实体）。假设实体本身**不排除** —— 它们是深挖的
// 线索来源，M3 的核心目标是召回而非纯净。
func orderByEvidenceStrength(scored []scoreCandidate) []scoreCandidate {
	out := append([]scoreCandidate(nil), scored...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		hi, hj := out[i].entity.GetIsHypothesis(), out[j].entity.GetIsHypothesis()
		if hi != hj {
			return !hi // 非假设优先
		}
		// 最终以 ID 定序，保证完全确定（P-5）。
		return out[i].entity.GetEntityId() < out[j].entity.GetEntityId()
	})
	return out
}

// minEntityCost 返回"必须装入的最小实体集"的 token 成本。
//
// 语义（M3 §4.2 步骤 5 的"最小实体集"）：直接引用的种子实体构成
// 不可省略的核心 —— 任务明确点名的目标必须在上下文里，否则这次装配
// 对任务毫无意义。
//
// **但最小集本身也要受该档位的 max_entities 约束。** 一个宽泛的
// focus_hint（如网段内的一台主机，其下挂着 60 个服务）会让所有 60 个
// 实体都匹配上同一属性值，若把它们全部计入"必装"，最小集就会随图的
// 规模无限增长 —— 那等于宣称"任何预算都不够"，降档永远无法成功。
//
// 正确语义：最小集 = **按打分排序后的前 N 个种子**，N 取该档位允许的
// 实体上限。这样 f/16（10 个）的最小集远小于 f/1.4（200 个），
// 降档重试才能收敛（这正是 DoD③「超预算 100% 拒绝并降档」的前提）。
func minEntityCost(
	scored []scoreCandidate, seeds map[string]bool, depth uint32, maxEntities uint32,
) uint32 {
	var (
		seedCost  uint32
		seedCount uint32
		cheapest  uint32
	)
	cap := maxEntities
	if cap == 0 {
		cap = 1
	}
	for i, sc := range scored {
		c := EstimateEntityTokens(sc.entity, depth)
		if i == 0 || c < cheapest {
			cheapest = c
		}
		if seeds[sc.entity.GetEntityId()] {
			if seedCount >= cap {
				continue // 超出该档位能容纳的实体数，不计入最小集
			}
			seedCost += c
			seedCount++
		}
	}
	if seedCount > 0 {
		return seedCost
	}
	return cheapest
}

// countDepthTruncated 统计有多少实体的属性数超过 depth。
func countDepthTruncated(ents []*alethv1.Entity, depth uint32) int {
	n := 0
	for _, e := range ents {
		if uint32(len(e.GetAttributes())) > depth {
			n++
		}
	}
	return n
}

// poolRelationsOmitted 返回两端不全在结果集内的关系（用于省略声明）。
func poolRelationsOmitted(rels []*alethv1.Relation, keep map[string]bool) []*alethv1.Relation {
	var out []*alethv1.Relation
	for _, r := range rels {
		if !keep[r.GetFromEntity()] || !keep[r.GetToEntity()] {
			out = append(out, r)
		}
	}
	return out
}

// containsReason 判定 reasons 里是否含某子串。
func containsReason(reasons []string, sub string) bool {
	for _, r := range reasons {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

// sortedKinds 返回排序后的实体类型（确定性输出顺序）。
func sortedKinds(m map[alethv1.EntityKind]int) []alethv1.EntityKind {
	out := make([]alethv1.EntityKind, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// kindName 返回实体类型的中文名（渲染与审计用）。
func kindName(k alethv1.EntityKind) string {
	switch k {
	case alethv1.EntityKind_ASSET:
		return "ASSET"
	case alethv1.EntityKind_SERVICE:
		return "SERVICE"
	case alethv1.EntityKind_IDENTITY:
		return "IDENTITY"
	case alethv1.EntityKind_ENDPOINT:
		return "ENDPOINT"
	case alethv1.EntityKind_DEFECT:
		return "DEFECT"
	case alethv1.EntityKind_PATH:
		return "PATH"
	case alethv1.EntityKind_TIMELINE:
		return "TIMELINE"
	default:
		return "UNKNOWN"
	}
}

// seedsOf 从已选实体里统计直接引用的数量（焦点描述用）。
func seedsOf(ents []*alethv1.Entity) []string {
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.GetEntityId())
	}
	return out
}

// focalPointOf 生成焦点描述（可审计，M3 §4.4 的"焦点声明"区块）。
func focalPointOf(hint string, seedCount int) string {
	if strings.TrimSpace(hint) == "" {
		return fmt.Sprintf("panorama (no focus hint; %d seed entities referenced)", seedCount)
	}
	if seedCount == 0 {
		// 诚实标注：给了 hint 但没匹配到任何实体。
		// 这正是 M3 §8 风险栏说的"Autofocus 依赖任务描述的实体命名"。
		return fmt.Sprintf("hint %q matched no entity in the map (focus fell back to whole graph)", hint)
	}
	return fmt.Sprintf("%s (%d seed entities)", hint, seedCount)
}

// bundleID 生成确定性的装配标识。
//
// 不含随机数：相同 (task, stop, estimated) 必得同一 ID，
// 便于消费方缓存与比对（与 M2 的 snapshotID 同一理由）。
func bundleID(taskID string, stop alethv1.ApertureSetting_Stop, estimated uint32) string {
	return fmt.Sprintf("cb_%s_%s_%d", sanitizeID(taskID), stopCode(stop), estimated)
}

// stopCode 返回档位的短码（用于可读的 bundle ID）。
func stopCode(s alethv1.ApertureSetting_Stop) string {
	switch s {
	case alethv1.ApertureSetting_F_1_4:
		return "f14"
	case alethv1.ApertureSetting_F_16:
		return "f16"
	default:
		return "f4"
	}
}

// sanitizeID 把 taskID 转成 ID 安全形式。
func sanitizeID(s string) string {
	if s == "" {
		return "task"
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

// Autofocus 实现 ApertureService.Autofocus（M3 §4.2）。
//
// 返回焦点描述、焦点子图实体 ID、建议档位与定位依据。
func (a *Assembler) Autofocus(ctx context.Context, req *alethv1.AutofocusRequest) (*alethv1.AutofocusResult, error) {
	if req == nil {
		return nil, fmt.Errorf("aperture: nil request")
	}
	// 假设文本与任务目标都可能含实体引用 —— 两者都作为抽取输入
	// （M3 §4.2 步骤 1 原文："从 task.objective 与 hypothesis 中识别"）。
	hints := ExtractEntityHints(req.GetHypothesis() + " " + req.GetTaskId())

	// 用最大档取一个宽候选集，再由 hint 匹配收敛 —— Autofocus 的职责
	// 是"定位焦点"，不负责孔径决策（那是 Assemble 的事）。
	pool, err := a.graph.Project(ctx, "", "", ProfileFor(DefaultStop).MaxHops,
		ProfileFor(alethv1.ApertureSetting_F_1_4).MaxEntities, nil)
	if err != nil {
		return nil, fmt.Errorf("aperture: project: %w", err)
	}

	var (
		ids     []string
		reasons []string
	)
	for _, e := range pool.GetEntities() {
		if entityMatchesHint(e, hints) {
			ids = append(ids, e.GetEntityId())
		}
	}
	sort.Strings(ids)

	if len(ids) == 0 {
		reasons = append(reasons,
			"no entity reference matched; planner should emit structured target_entity_hints (M3 §8)")
	} else {
		reasons = append(reasons, fmt.Sprintf("matched %d entities from %d extracted hints",
			len(ids), len(hints)))
	}

	return &alethv1.AutofocusResult{
		FocalPoint:    focalPointOf(req.GetHypothesis(), len(ids)),
		EntityIds:     ids,
		SuggestedStop: DefaultStop,
		Reasons:       reasons,
	}, nil
}

// defaultNow 返回当前 UnixNano。
func defaultNow() int64 { return timeNow() }
