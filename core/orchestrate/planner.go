package orchestrate

import (
	"fmt"
	"sort"
	"strings"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// 本文件实现 M5 §4.2 的确定性规划器（T5.3）与调度状态流转（T5.4）。
//
// **零 LLM**：本文件（以及整个包）不引入任何 LLM 客户端。契约
// （05 §6.2）明确 "NextReady 的实现不得调用 LLM —— 它是拓扑排序 +
// 资源约束求解"，模块规格 §6 要求 CI 静态检查确认这一点。

// Graph 是一张可在内存中求解的任务图。
type Graph struct {
	ID           string
	SessionID    string
	PlanRevision string
	Rationale    string
	Tasks        map[string]*TaskState
	// order 保留任务在原始图中的声明顺序，用于确定性 tie-break。
	order []string
}

// NewGraph 从 proto 的 TaskGraph 建立可求解的图。
//
// 校验（fail-fast，不静默修正）：
//   - 任务 ID 非空且唯一；
//   - depends_on 指向已存在的任务；
//   - 无环（有环的图无法求解，返回错误而不是"尽力而为"）。
//
// 为什么把校验放在构造而非求解时：一张有环或有悬空依赖的图是**规划错误**，
// 应当在进入调度之前就被拒绝。等到 NextReady 才失败会让"任务永远不 ready"
// 伪装成"暂时没有可做的任务"。
func NewGraph(src *alethv1.TaskGraph) (*Graph, error) {
	if src == nil {
		return nil, fmt.Errorf("orchestrate: nil task graph")
	}
	g := &Graph{
		ID:           src.GetGraphId(),
		SessionID:    src.GetSessionId(),
		PlanRevision: src.GetPlanRevision(),
		Rationale:    src.GetPlanRationale(),
		Tasks:        make(map[string]*TaskState, len(src.GetTasks())),
	}
	for _, t := range src.GetTasks() {
		id := t.GetTaskId()
		if strings.TrimSpace(id) == "" {
			return nil, fmt.Errorf("orchestrate: task with empty task_id")
		}
		if _, dup := g.Tasks[id]; dup {
			return nil, fmt.Errorf("orchestrate: duplicate task_id %q", id)
		}
		st := &TaskState{
			ID:        id,
			Title:     t.GetTitle(),
			Objective: t.GetObjective(),
			Role:      t.GetRequiredRole(),
			DependsOn: append([]string(nil), t.GetDependsOn()...),
			Status:    t.GetStatus(),
			Budget:    t.GetBudgetTokens(),
			Attempt:   t.GetAttempt(),
			Failures:  append([]*alethv1.FailureRecord(nil), t.GetFailures()...),
		}
		// 未指定状态的任务视为 PENDING（而不是 READY —— 依赖尚未评估）。
		if st.Status == alethv1.TaskStatus_TASK_STATUS_UNSPECIFIED {
			st.Status = alethv1.TaskStatus_PENDING
		}
		sort.Strings(st.DependsOn) // 确定性
		g.Tasks[id] = st
		g.order = append(g.order, id)
	}
	// 依赖存在性校验。
	for _, id := range g.order {
		for _, dep := range g.Tasks[id].DependsOn {
			if _, ok := g.Tasks[dep]; !ok {
				return nil, fmt.Errorf(
					"orchestrate: task %q depends on unknown task %q (dangling dependency)",
					id, dep)
			}
		}
	}
	// 环检测：拓扑排序能完成即无环。
	if _, err := g.topologicalOrder(); err != nil {
		return nil, err
	}
	return g, nil
}

// topologicalOrder 返回确定性的拓扑序（Kahn 算法 + 声明序 tie-break）。
//
// 确定性来源（P-5 / Q6）：
//   - 就绪集合每次按**原始声明序**排序后取；
//   - 因此相同输入必得相同序列（M5 §6「规划器确定性」要求）。
//
// 纯 map 迭代 + 任意取点会让同一张图产出不同序列，那会让"可复现"失效。
func (g *Graph) topologicalOrder() ([]string, error) {
	// 入度 = 未完成的前置任务数。
	// 注意：只统计**未完成**的前置 —— 已 DONE 的任务不阻塞后继。
	indeg := make(map[string]int, len(g.Tasks))
	for id, t := range g.Tasks {
		n := 0
		for _, dep := range t.DependsOn {
			if !isTerminalSuccess(g.Tasks[dep].Status) {
				n++
			}
		}
		indeg[id] = n
	}

	// 就绪队列按声明序维护。
	var ready []string
	for _, id := range g.order {
		if indeg[id] == 0 {
			ready = append(ready, id)
		}
	}
	pos := map[string]int{}
	for i, id := range g.order {
		pos[id] = i
	}

	var out []string
	// dependents：反查表，避免每轮扫描全图。
	dependents := map[string][]string{}
	for _, id := range g.order {
		for _, dep := range g.Tasks[id].DependsOn {
			dependents[dep] = append(dependents[dep], id)
		}
	}

	for len(ready) > 0 {
		sort.Slice(ready, func(i, j int) bool { return pos[ready[i]] < pos[ready[j]] })
		cur := ready[0]
		ready = ready[1:]
		out = append(out, cur)
		for _, d := range dependents[cur] {
			indeg[d]--
			if indeg[d] == 0 {
				ready = append(ready, d)
			}
		}
	}

	// 有环时拓扑序不完整 —— 显式报错并指出环路成员。
	if len(out) != len(g.Tasks) {
		var stuck []string
		for _, id := range g.order {
			if !containsStr(out, id) {
				stuck = append(stuck, id)
			}
		}
		return nil, fmt.Errorf(
			"orchestrate: task graph has a dependency cycle involving %v "+
				"(a cyclic graph cannot be scheduled)", stuck)
	}
	return out, nil
}

// NextReady 是确定性调度决策（OrchestratorService.NextReady 的核心）。
//
// 语义（05 §6.2）：返回当前**可执行**的任务 ID 列表，受可用并发槽位约束。
//
// **零 LLM**：纯拓扑 + 资源约束求解。
//
// availableSlots 是资源约束：最多返回这么多个任务。这与 M5 §4.4 的
// "并发上限"是同一约束的两个视角（此处按调用方给的槽位数裁剪）。
func (g *Graph) NextReady(availableSlots uint32) ([]string, map[string]string) {
	order, err := g.topologicalOrder()
	if err != nil {
		// 图有环 —— 在构造时已校验过，这里只可能在运行期被改坏。
		return nil, map[string]string{"__graph__": err.Error()}
	}

	blocked := map[string]string{}
	var ready []string
	for _, id := range order {
		t := g.Tasks[id]
		switch t.Status {
		case alethv1.TaskStatus_PENDING, alethv1.TaskStatus_READY:
			// 检查全部前置是否成功完成。
			var pending []string
			for _, dep := range t.DependsOn {
				d := g.Tasks[dep]
				if !isTerminalSuccess(d.Status) {
					pending = append(pending, dep)
				}
			}
			if len(pending) > 0 {
				blocked[id] = "waiting for dependencies: " + strings.Join(pending, ", ")
				continue
			}
			ready = append(ready, id)
		case alethv1.TaskStatus_RUNNING:
			blocked[id] = "already running"
		case alethv1.TaskStatus_FAILED:
			blocked[id] = "failed; requires Refine before retry"
		case alethv1.TaskStatus_SKIPPED:
			blocked[id] = "skipped"
		case alethv1.TaskStatus_CIRCUIT_BROKEN:
			blocked[id] = "circuit broken"
		case alethv1.TaskStatus_DONE:
			blocked[id] = "done"
		}
	}

	// 资源约束：按可用槽位裁剪（ready 已是拓扑序，直接取前 N 个）。
	if availableSlots > 0 && uint32(len(ready)) > availableSlots {
		for _, id := range ready[availableSlots:] {
			blocked[id] = "ready but no available execution slot (resource constraint)"
		}
		ready = ready[:availableSlots]
	}
	return ready, blocked
}

// CriticalPath 返回关键路径（长度最大的依赖链）。
//
// 用途（M5 §4.2）：关键路径识别是确定性规划器的职责之一 —— 调度器据此
// 优先分配资源。路径长度按任务数计（每个任务视为单位成本）。
//
// 无依赖关系时返回最长的单任务路径（仍是有意义的答案：没有关键链，
// 任何任务都是"关键"的）。
func (g *Graph) CriticalPath() []string {
	order, err := g.topologicalOrder()
	if err != nil {
		return nil
	}
	// 动态规划：dist[id] = 以 id 结尾的最长链长度。
	dist := map[string]int{}
	prev := map[string]string{}
	for _, id := range order {
		best, from := 0, ""
		for _, dep := range g.Tasks[id].DependsOn {
			if dist[dep] > best {
				best = dist[dep]
				from = dep
			}
		}
		dist[id] = best + 1
		prev[id] = from
	}
	// 找最长终点；平局按声明序取先者（确定性）。
	end, bestLen := "", 0
	for _, id := range g.order {
		if dist[id] > bestLen {
			bestLen, end = dist[id], id
		}
	}
	if end == "" {
		return nil
	}
	// 回溯。
	var path []string
	for cur := end; cur != ""; cur = prev[cur] {
		path = append(path, cur)
	}
	// 反转成从起点到终点。
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path
}

// ApplyResult 把一次任务执行结果写回图（状态流转，T5.4）。
//
// 语义：调用方（Scheduler）报告某任务的终态；本方法更新状态、
// 追加失败记录、累加 attempt。
//
// 拒绝非法流转（M5 §6「终止唯一性」的镜像要求）：
//   - 未知任务 ID → 报错（不静默忽略）；
//   - DONE/CIRCUIT_BROKEN 是终态，不允许再次流转（除非显式 rewind）；
//   - FAILED 必须带至少一条 FailureRecord（Refiner 依据它改写指令，
//     没有失败记录的 FAILED 无法驱动改进）。
func (g *Graph) ApplyResult(
	taskID string, status alethv1.TaskStatus, failures []*alethv1.FailureRecord,
) error {
	t, ok := g.Tasks[taskID]
	if !ok {
		return fmt.Errorf("orchestrate: unknown task %q", taskID)
	}
	if isTerminalSuccess(t.Status) {
		return fmt.Errorf(
			"orchestrate: task %q is already DONE (terminal); use Rewind to reopen it", taskID)
	}
	if status == alethv1.TaskStatus_FAILED && len(failures) == 0 {
		return fmt.Errorf(
			"orchestrate: FAILED task %q requires at least one FailureRecord "+
				"(the Refiner needs a structured failure type to rewrite the instruction)", taskID)
	}
	t.Status = status
	t.Attempt++
	if len(failures) > 0 {
		t.Failures = append(t.Failures, failures...)
	}
	return nil
}

// AddFailure 给任务追加一条失败记录（Refiner 重试路径）。
func (g *Graph) AddFailure(taskID string, rec *alethv1.FailureRecord) error {
	t, ok := g.Tasks[taskID]
	if !ok {
		return fmt.Errorf("orchestrate: unknown task %q", taskID)
	}
	t.Failures = append(t.Failures, rec)
	return nil
}

// ToProto 把图导出为契约消息（可序列化、可人工编辑后重新求解）。
//
// 顺序：按声明的拓扑序输出，保证序列化结果确定（M5 §6：
// "任务图可审阅 —— 序列化后可人工编辑，编辑后仍能正确求解"）。
func (g *Graph) ToProto() *alethv1.TaskGraph {
	order, err := g.topologicalOrder()
	if err != nil {
		order = append([]string(nil), g.order...) // 有环时退回声明序
	}
	out := &alethv1.TaskGraph{
		GraphId:       g.ID,
		SessionId:     g.SessionID,
		PlanRevision:  g.PlanRevision,
		PlanRationale: g.Rationale,
	}
	for _, id := range order {
		t := g.Tasks[id]
		out.Tasks = append(out.Tasks, &alethv1.Task{
			TaskId:       t.ID,
			Title:        t.Title,
			Objective:    t.Objective,
			RequiredRole: t.Role,
			DependsOn:    append([]string(nil), t.DependsOn...),
			Status:       t.Status,
			BudgetTokens: t.Budget,
			Attempt:      t.Attempt,
			Failures:     append([]*alethv1.FailureRecord(nil), t.Failures...),
		})
	}
	return out
}

// Tasks 返回按拓扑序排列的任务状态（只读视图）。
func (g *Graph) TasksInOrder() []*TaskState {
	order, err := g.topologicalOrder()
	if err != nil {
		order = append([]string(nil), g.order...)
	}
	out := make([]*TaskState, 0, len(order))
	for _, id := range order {
		out = append(out, g.Tasks[id])
	}
	return out
}

// ---- 小工具 ----

// isTerminalSuccess 报告状态是否为"成功终态"（其后继可解除阻塞）。
func isTerminalSuccess(s alethv1.TaskStatus) bool {
	return s == alethv1.TaskStatus_DONE
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// sortedKeys 返回排序后的 map 键（确定性遍历）。
func sortedKeys(m map[string]uint32) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
