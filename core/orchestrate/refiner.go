package orchestrate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// 本文件实现 M5 §4.2 的 Refiner（T5.7）与 §4.3 的检查点/rewind/fork（T5.8）。

// ---- Refiner：失败模式驱动的指令改写（M5 §4.2）----

// Refinement 是一次改写决策的结果。
type Refinement struct {
	// FailureType 是本次改写的依据。
	FailureType FailureType
	// Guidance 是给 agent 的改写后的指令。
	Guidance string
	// ApertureHint 是建议的光圈调整方向（M3 §4.1 的档位），
	// 空表示不调整。CONTEXT_MISSING 会要求提高档位（更宽）。
	ApertureHint alethv1.ApertureSetting_Stop
	// Replan 表示需要重规划整张图（而非只重试该任务）。
	Replan bool
	// Abandon 表示该方向应放弃（而非重试）。
	Abandon bool
}

// Refine 依据结构化失败类型生成改写建议（M5 §4.2 的核心）。
//
// **与简单重试的区别**（规格原文）：简单重试会重复同样的失败；
// Refiner 依据**结构化的失败类型**改写指令。因此本函数对每种类型给出
// **不同的**动作，而不是统一的"再试一次"：
//
//	CONTEXT_MISSING   → 提高光圈档位重新装配上下文（不是重试！）
//	TOOL_MISUSE       → 换工具或修参数
//	WRONG_HYPOTHESIS  → 回滚假设分支并重规划
//	TIMEOUT           → 收窄任务范围（拆小）
//	PREMATURE_STOP    → 继续深挖，**不**换方向
//	HALLUCINATION     → 终止该 agent，要求重新取证
//
// 未知失败类型返回错误而非默认动作：错误的缓解动作可能比不动作更糟
// （如把 HALLUCINATION 当成 TIMEOUT 去"缩小范围重试"，会继续产生幻觉）。
func Refine(rec *alethv1.FailureRecord, currentStop alethv1.ApertureSetting_Stop) (Refinement, error) {
	if rec == nil {
		return Refinement{}, fmt.Errorf("orchestrate: nil failure record")
	}
	ft, ok := ParseFailureType(rec.GetFailureType())
	if !ok {
		return Refinement{}, fmt.Errorf(
			"orchestrate: unknown failure_type %q; refusing to guess a remediation "+
				"(a wrong remediation can be worse than none)", rec.GetFailureType())
	}

	r := Refinement{FailureType: ft}
	switch ft {
	case FailContextMissing:
		// 上下文缺关键实体 —— 提高光圈档位（更宽）重新装配。
		// 这是 M3 与 M5 的联动点：M3 §8 的风险缓解正是"要求 Planner 输出
		// 结构化 target_entity_hints"，而这里给出互补的另一半 ——
		// 当上下文确实缺实体时，放宽光圈把它们包进来。
		r.ApertureHint = widenStop(currentStop)
		r.Guidance = fmt.Sprintf(
			"context was missing key entities (aperture was %s). Re-assemble at %s "+
				"before retrying; do not repeat the same call with the same context.",
			ProfileLabel(currentStop), ProfileLabel(r.ApertureHint))

	case FailToolMisuse:
		r.Guidance = "the tool or its parameters were wrong. Re-check the adapter schema " +
			"(ListAdapters) and fix the argument, or switch to a tool suited to this step."

	case FailWrongHypothesis:
		r.Replan = true
		r.Abandon = true
		r.Guidance = "the working hypothesis was wrong. Roll back the hypothesis branch " +
			"(PrismService.RollbackBranch) and re-plan the graph instead of retrying this path."

	case FailTimeout:
		r.Guidance = "the step timed out. Narrow the task scope (split into smaller tasks " +
			"with explicit sub-targets) rather than re-running the same broad task."

	case FailPrematureStop:
		r.Guidance = "stopped before exhausting the search space. Continue enumerating " +
			"within the same direction — do NOT switch approach."

	case FailHallucination:
		r.Abandon = true
		r.Guidance = "an unsupported claim was produced. Stop this agent, require fresh " +
			"evidence (G-1 execution binding) and re-derive the conclusion from raw output."
	}
	if g := rec.GetRefinerGuidance(); g != "" && !r.Abandon {
		// 外部 Refiner 给出了具体建议时叠加（但不覆盖上述定向动作）。
		r.Guidance += " | refiner note: " + g
	}
	return r, nil
}

// widenStop 返回更宽的一档光圈（CONTEXT_MISSING 的缓解方向）。
//
// 与 M3 的 narrowerStop 相反：这里需要**看到更多**实体，
// 因此朝 f/1.4 方向走。
func widenStop(s alethv1.ApertureSetting_Stop) alethv1.ApertureSetting_Stop {
	switch s {
	case alethv1.ApertureSetting_F_16:
		return alethv1.ApertureSetting_F_4
	case alethv1.ApertureSetting_F_4:
		return alethv1.ApertureSetting_F_1_4
	default:
		return alethv1.ApertureSetting_F_1_4
	}
}

// ProfileLabel 返回档位的可读名（与 core/aperture 的标签一致）。
func ProfileLabel(s alethv1.ApertureSetting_Stop) string {
	switch s {
	case alethv1.ApertureSetting_F_1_4:
		return "f/1.4"
	case alethv1.ApertureSetting_F_16:
		return "f/16"
	default:
		return "f/4"
	}
}

// ---- 检查点 / rewind / fork（M5 §4.3）----

// Checkpoint 是一次检查点快照。
//
// 组成（M5 §4.3）：心智地图版本号、证据账本水位、预算状态快照、
// TaskGraph 版本。**账本不回滚** —— 证据是历史事实，"探索过但失败"
// 本身是有价值的信息（规格原文）。因此这里记的是**水位**（watermark），
// 用于界定"本分支新证据"，而不是可回滚的副本。
type Checkpoint struct {
	ID           string
	SessionID    string
	Label        string
	PlanRevision string
	GraphVersion string // 心智地图版本（M2 的 SnapshotAt 时刻）
	BudgetHash   string
	// LedgerWatermark 是账本水位（该时刻已确认的 evidence_id 集合的哈希）。
	//
	// 为什么不存完整 ID 列表：账本只增不改，水位只需要能判定
	// "某条证据早于/晚于该检查点"，哈希即可承担这一判定（配合账本的
	// append-only 顺序）。
	LedgerWatermark string
	// Graph 是 TaskGraph 在该检查点的完整快照（用于 rewind 恢复）。
	Graph *alethv1.TaskGraph
	// Warnings 记录快照不完整的原因（如未注入跨模块状态来源）。
	//
	// 存在的理由：`GraphVersion` / `BudgetHash` 为空有两种可能 ——
	// "来源确实没有版本概念"与"根本没接线"。两者的处置完全不同，
	// 因此不能只留空字段，必须带上原因（docs/10 §0）。
	Warnings []string
	// createdAt 是创建时刻（内部字段 —— proto 的 CreatedAt 由 server 层
	// 在返回 CheckpointInfo 时填充，本结构不依赖 proto 类型）。
	createdAt time.Time
}

// CheckpointStore 保存检查点（M5 §8：仅保留最近 N 个 + 每个里程碑一个）。
type CheckpointStore struct {
	max int
	// items 按插入顺序保存。
	items []*Checkpoint
	// pinned 是里程碑检查点（不参与容量淘汰）。
	pinned map[string]bool
}

// DefaultMaxCheckpoints 是检查点保留上限（M5 §8 风险缓解）。
const DefaultMaxCheckpoints = 20

// NewCheckpointStore 建立检查点存储。max <= 0 时使用默认上限。
func NewCheckpointStore(max int) *CheckpointStore {
	if max <= 0 {
		max = DefaultMaxCheckpoints
	}
	return &CheckpointStore{max: max, pinned: map[string]bool{}}
}

// Save 保存检查点；超出容量时淘汰最旧的**非里程碑**检查点。
func (s *CheckpointStore) Save(cp *Checkpoint, milestone bool) error {
	if cp == nil || cp.ID == "" {
		return fmt.Errorf("orchestrate: checkpoint requires an id")
	}
	// 同 ID 覆盖（重跑同一标签）。
	for i, existing := range s.items {
		if existing.ID == cp.ID {
			s.items[i] = cp
			if milestone {
				s.pinned[cp.ID] = true
			}
			return nil
		}
	}
	s.items = append(s.items, cp)
	if milestone {
		s.pinned[cp.ID] = true
	}
	s.evict()
	return nil
}

// evict 淘汰最旧的非里程碑检查点，直到不超过上限。
func (s *CheckpointStore) evict() {
	for len(s.items) > s.max {
		idx := -1
		for i, cp := range s.items {
			if !s.pinned[cp.ID] {
				idx = i
				break
			}
		}
		if idx < 0 {
			// 全部是里程碑 —— 不淘汰（里程碑是人工标记的重要节点，
			// 静默丢弃它们会让"回不去那个已知good状态"）。
			return
		}
		s.items = append(s.items[:idx], s.items[idx+1:]...)
	}
}

// Get 按 ID 取检查点。
func (s *CheckpointStore) Get(id string) (*Checkpoint, bool) {
	for _, cp := range s.items {
		if cp.ID == id {
			return cp, true
		}
	}
	return nil, false
}

// Latest 返回最近一个检查点。
func (s *CheckpointStore) Latest() (*Checkpoint, bool) {
	if len(s.items) == 0 {
		return nil, false
	}
	return s.items[len(s.items)-1], true
}

// Len 返回当前检查点数量。
func (s *CheckpointStore) Len() int { return len(s.items) }

// Rewind 从检查点恢复图状态。
//
// 契约（05 §6.2 RewindResult.evidence_consistent）：rewind 到任一检查点后
// 重跑，**证据一致性校验必须通过** —— 含义是：已 CONFIRMED 的证据在
// rewind 后必须**保持不变**（账本不回滚，见 M5 §4.3）。
//
// 本方法因此把"恢复的图"与"账本水位"一并交回，并显式声明
// 账本未被回滚（LedgerNotRolledBack 恒为 true —— 这是设计事实，
// 不是可变状态；保留该字段是为了让消费方无法忽视它）。
func (s *CheckpointStore) Rewind(id string) (*RewindOutcome, error) {
	cp, ok := s.Get(id)
	if !ok {
		return nil, fmt.Errorf("orchestrate: checkpoint %q not found", id)
	}
	g, err := NewGraph(cp.Graph)
	if err != nil {
		return nil, fmt.Errorf("orchestrate: restore graph from checkpoint %q: %w", id, err)
	}
	// 恢复运行时状态：检查点记录的是"该时刻的图"，其中 RUNNING 的任务
	// 在恢复后应回到 READY（进程已不在，任务没有在跑）。
	for _, t := range g.Tasks {
		if t.Status == alethv1.TaskStatus_RUNNING {
			t.Status = alethv1.TaskStatus_READY
		}
	}
	return &RewindOutcome{
		CheckpointID:        cp.ID,
		Graph:               g,
		GraphVersion:        cp.GraphVersion,
		LedgerWatermark:     cp.LedgerWatermark,
		LedgerNotRolledBack: true,
	}, nil
}

// RewindOutcome 是 rewind 的结果。
type RewindOutcome struct {
	CheckpointID    string
	Graph           *Graph
	GraphVersion    string
	LedgerWatermark string
	// LedgerNotRolledBack 恒为 true —— 证据账本是历史事实，不回滚
	// （M5 §4.3）。保留为字段以便消费方显式看到这条约束。
	LedgerNotRolledBack bool
}

// Fork 从检查点派生一个平行探索分支。
//
// 契约（M5 §4.3 / 05 §6.2 ForkResult）：创建平行分支探索备选路径，
// 共享已 CONFIRMED 的证据，隔离探索性假设（is_hypothesis=true）。
//
// 实现要点：fork 出的图**继承已完成任务的状态**（那些证据是共享的），
// 但把 FAILED / RUNNING 重置为 PENDING —— 平行分支要重新走这些路径。
func (s *CheckpointStore) Fork(id, forkName string) (*ForkOutcome, error) {
	cp, ok := s.Get(id)
	if !ok {
		return nil, fmt.Errorf("orchestrate: checkpoint %q not found", id)
	}
	if strings.TrimSpace(forkName) == "" {
		return nil, fmt.Errorf("orchestrate: fork requires a name (for audit)")
	}
	g, err := NewGraph(cp.Graph)
	if err != nil {
		return nil, fmt.Errorf("orchestrate: fork from checkpoint %q: %w", id, err)
	}
	// DONE 保持（共享已确认的证据）；其余重置以便平行探索。
	for _, t := range g.Tasks {
		switch t.Status {
		case alethv1.TaskStatus_DONE:
			// 保留 —— 已确认的证据是共享的。
		default:
			t.Status = alethv1.TaskStatus_PENDING
			// 失败记录保留（规格 §4.3：失败记录保留 → 供 Refiner 学习）。
		}
	}
	newID := cp.SessionID + "/" + forkName
	return &ForkOutcome{
		NewSessionID:     newID,
		ParentSessionID:  cp.SessionID,
		RootCheckpointID: cp.ID,
		Graph:            g,
		SharedConfirmed:  countDone(g),
	}, nil
}

// ForkOutcome 是 fork 的结果。
type ForkOutcome struct {
	NewSessionID     string
	ParentSessionID  string
	RootCheckpointID string
	// SharedConfirmed 是继承的已完成任务数（已确认证据的共享面）。
	SharedConfirmed int
	Graph           *Graph
}

// countDone 统计已完成任务数。
func countDone(g *Graph) int {
	n := 0
	for _, t := range g.Tasks {
		if t.Status == alethv1.TaskStatus_DONE {
			n++
		}
	}
	return n
}

// SortedFailureTypes 返回排序后的失败类型（测试与文档生成用）。
func SortedFailureTypes() []string {
	out := make([]string, 0, len(AllFailureTypes()))
	for _, t := range AllFailureTypes() {
		out = append(out, string(t))
	}
	sort.Strings(out)
	return out
}
