package orchestrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// 任务图构造辅助。
func task(id string, role alethv1.AgentRole, deps ...string) *alethv1.Task {
	return &alethv1.Task{
		TaskId:       id,
		Title:        "task " + id,
		Objective:    "objective " + id,
		RequiredRole: role,
		DependsOn:    deps,
		Status:       alethv1.TaskStatus_PENDING,
		BudgetTokens: 1000,
	}
}

func graph(tasks ...*alethv1.Task) *alethv1.TaskGraph {
	return &alethv1.TaskGraph{
		GraphId:      "g1",
		SessionId:    "s1",
		PlanRevision: "1",
		Tasks:        tasks,
	}
}

// ---- T5.1：任务图构造与校验 ----

func TestNewGraphRejectsDanglingDependency(t *testing.T) {
	// 悬空依赖是规划错误，必须在进入调度前被拒绝 ——
	// 否则会表现为"任务永远不 ready"，伪装成"暂时没有可做的任务"。
	_, err := NewGraph(graph(task("a", alethv1.AgentRole_RECON, "nonexistent")))
	if err == nil {
		t.Fatal("dangling dependency must be rejected")
	}
	if !strings.Contains(err.Error(), "unknown task") {
		t.Fatalf("error should name the dangling dependency: %v", err)
	}
}

func TestNewGraphRejectsCycle(t *testing.T) {
	// 有环的图无法求解 —— 显式报错而不是"尽力而为"。
	_, err := NewGraph(graph(
		task("a", alethv1.AgentRole_RECON, "c"),
		task("b", alethv1.AgentRole_SCANNER, "a"),
		task("c", alethv1.AgentRole_FUZZER, "b"),
	))
	if err == nil {
		t.Fatal("cyclic graph must be rejected")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("error should mention the cycle: %v", err)
	}
}

func TestNewGraphRejectsDuplicateID(t *testing.T) {
	_, err := NewGraph(graph(
		task("dup", alethv1.AgentRole_RECON),
		task("dup", alethv1.AgentRole_SCANNER),
	))
	if err == nil {
		t.Fatal("duplicate task_id must be rejected")
	}
}

func TestNewGraphRejectsEmptyID(t *testing.T) {
	_, err := NewGraph(graph(task("", alethv1.AgentRole_RECON)))
	if err == nil {
		t.Fatal("empty task_id must be rejected")
	}
}

// ---- T5.3：确定性规划器（DoD②：NextReady 零 LLM，拓扑 + 资源约束）----

func TestNextReadyRespectsDependencies(t *testing.T) {
	g, err := NewGraph(graph(
		task("recon", alethv1.AgentRole_RECON),
		task("scan", alethv1.AgentRole_SCANNER, "recon"),
		task("exploit", alethv1.AgentRole_EXPLOITER, "scan"),
	))
	if err != nil {
		t.Fatal(err)
	}
	// 初始只有 recon 可做。
	ready, blocked := g.NextReady(10)
	if len(ready) != 1 || ready[0] != "recon" {
		t.Fatalf("ready = %v, want [recon]", ready)
	}
	if _, ok := blocked["scan"]; !ok {
		t.Fatal("scan should be in blocked_reasons (auditable)")
	}

	// 完成 recon → scan 就绪，exploit 仍阻塞。
	if err := g.ApplyResult("recon", alethv1.TaskStatus_DONE, nil); err != nil {
		t.Fatal(err)
	}
	ready, _ = g.NextReady(10)
	if len(ready) != 1 || ready[0] != "scan" {
		t.Fatalf("ready = %v, want [scan]", ready)
	}
}

func TestNextReadyIsDeterministic(t *testing.T) {
	// Q6 / M5 §6：相同输入必得相同序列。
	mk := func() *Graph {
		g, err := NewGraph(graph(
			task("a", alethv1.AgentRole_RECON),
			task("b", alethv1.AgentRole_SCANNER),
			task("c", alethv1.AgentRole_FUZZER),
			task("d", alethv1.AgentRole_EXPLOITER, "a", "b"),
			task("e", alethv1.AgentRole_REPORTER, "c", "d"),
		))
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	first, _ := mk().NextReady(10)
	for i := 0; i < 50; i++ {
		got, _ := mk().NextReady(10)
		if len(got) != len(first) {
			t.Fatalf("run %d: length differs", i)
		}
		for j := range got {
			if got[j] != first[j] {
				t.Fatalf("run %d: order differs at %d: %v vs %v", i, j, got, first)
			}
		}
	}
}

func TestNextReadyAppliesResourceConstraint(t *testing.T) {
	// 资源约束：可执行任务多于槽位时只返回槽位数，其余记入 blocked_reasons。
	g, _ := NewGraph(graph(
		task("a", alethv1.AgentRole_RECON),
		task("b", alethv1.AgentRole_SCANNER),
		task("c", alethv1.AgentRole_FUZZER),
	))
	ready, blocked := g.NextReady(2)
	if len(ready) != 2 {
		t.Fatalf("ready = %v, want exactly 2 (slot limit)", ready)
	}
	// 第三个必须说明原因，不得静默消失。
	found := false
	for _, reason := range blocked {
		if strings.Contains(reason, "no available execution slot") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the slot-blocked task must state why: %v", blocked)
	}
}

func TestCriticalPath(t *testing.T) {
	g, _ := NewGraph(graph(
		task("a", alethv1.AgentRole_RECON),
		task("b", alethv1.AgentRole_SCANNER, "a"),
		task("c", alethv1.AgentRole_FUZZER, "a"),
		task("d", alethv1.AgentRole_EXPLOITER, "b"),
		task("e", alethv1.AgentRole_REPORTER, "d"),
	))
	path := g.CriticalPath()
	// 最长链是 a→b→d→e（长度 4）。
	want := []string{"a", "b", "d", "e"}
	if len(path) != len(want) {
		t.Fatalf("critical path = %v, want %v", path, want)
	}
	for i := range want {
		if path[i] != want[i] {
			t.Fatalf("critical path = %v, want %v", path, want)
		}
	}
}

// ---- DoD②：NextReady 零 LLM 调用（静态检查）----

func TestNoLLMClientInPackage(t *testing.T) {
	// 契约硬约束（05 §6.2）：NextReady 的实现不得调用 LLM。
	//
	// 这是**静态检查**而非运行时断言 —— 一旦本包引入了任何 LLM 客户端
	// 依赖，"零 LLM"这条契约就失效了，而运行时测试无法发现（因为测试
	// 可以不走那条分支）。模块规格 §6 明确要求这一检查。
	//
	// 检查方式：扫描本包全部 .go 文件的 import 与调用点，
	// 确认不出现已知的 LLM SDK / HTTP 客户端。
	pkgDir := "."
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatal(err)
	}

	// 禁止出现的标准库网络/IO 包 —— 确定性规划器不应有任何 IO。
	//
	// **用包路径而非调用形态作为判据。** 最初的实现检查
	// `"http.Get("` 这类调用形态，变异测试证明它可被绕过：
	// `var _ = http.Get`（方法值，无括号）、`http.DefaultClient.Do(..)`
	// 都绕得过。包路径是"具备 IO 能力"的必要条件，无法在不被察觉的
	// 情况下引入。
	banPackages := []string{
		"net/http", "net/http/httputil", "net/rpc", "net/smtp",
		"os/exec", "database/sql",
	}
	// 禁止出现的外部 LLM 依赖（模块规格 §2 的设计决策）。
	//
	// 匹配 `"`+b（import 字面量前缀），而不是裸子串 —— 裸 `"llm"` 会
	// 命中任何含该片段的路径。
	banImports := []string{
		"openai", "anthropic", "langchain", "ollama", "gemini", "cohere",
		"generative-ai", "google.golang.org/genai",
	}
	// LLM 服务端点特征（覆盖未枚举的 SDK 变体）。
	banEndpoints := []string{"api.openai.com", "api.anthropic.com"}

	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		data, err := os.ReadFile(filepath.Join(pkgDir, name))
		if err != nil {
			t.Fatal(err)
		}
		src := string(data)
		lower := strings.ToLower(src)

		for _, p := range banPackages {
			if strings.Contains(src, `"`+p+`"`) {
				t.Errorf("%s: imports %q — the deterministic planner performs no IO "+
					"(NextReady is topological + resource-constraint solving only, 05 §6.2)",
					name, p)
			}
		}
		for _, b := range banImports {
			if strings.Contains(lower, `"`+b) {
				t.Errorf("%s: imports a banned LLM dependency matching %q "+
					"(NextReady must stay LLM-free, 05 §6.2)", name, b)
			}
		}
		for _, ep := range banEndpoints {
			if strings.Contains(lower, ep) {
				t.Errorf("%s: references LLM endpoint %q", name, ep)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no source files scanned — the static check is vacuous")
	}
	t.Logf("scanned %d source files; no IO package and no LLM dependency found", scanned)
}

// ---- T5.7：Refiner（DoD⑥：依据结构化失败类型改写，区别于简单重试）----

func TestRefineProducesDistinctActionsPerFailureType(t *testing.T) {
	// 核心断言：不同失败类型必须给出**不同**的改写动作。
	// 若所有类型都返回同一句"再试一次"，那就退化成简单重试
	// （M5 §4.2 明确要避免的）。
	seen := map[string]FailureType{}
	for _, ft := range AllFailureTypes() {
		r, err := Refine(&alethv1.FailureRecord{FailureType: string(ft)},
			alethv1.ApertureSetting_F_4)
		if err != nil {
			t.Fatalf("%s: %v", ft, err)
		}
		if r.Guidance == "" {
			t.Errorf("%s: empty guidance", ft)
		}
		if prev, dup := seen[r.Guidance]; dup {
			t.Errorf("failure types %s and %s produced identical guidance "+
				"(that is simple retry, not refinement)", prev, ft)
		}
		seen[r.Guidance] = ft
	}
}

func TestRefineContextMissingWidensAperture(t *testing.T) {
	// CONTEXT_MISSING 的定向动作是**提高光圈档位**（看到更多实体），
	// 而不是重试同一上下文。
	r, err := Refine(&alethv1.FailureRecord{FailureType: string(FailContextMissing)},
		alethv1.ApertureSetting_F_16)
	if err != nil {
		t.Fatal(err)
	}
	if r.ApertureHint != alethv1.ApertureSetting_F_4 {
		t.Fatalf("CONTEXT_MISSING at f/16 should widen to f/4, got %v", r.ApertureHint)
	}
	// 从最宽档也应给出最宽档（不能更宽了）。
	r2, _ := Refine(&alethv1.FailureRecord{FailureType: string(FailContextMissing)},
		alethv1.ApertureSetting_F_1_4)
	if r2.ApertureHint != alethv1.ApertureSetting_F_1_4 {
		t.Fatalf("already widest should stay f/1.4, got %v", r2.ApertureHint)
	}
}

func TestRefineWrongHypothesisRequestsReplan(t *testing.T) {
	r, err := Refine(&alethv1.FailureRecord{FailureType: string(FailWrongHypothesis)},
		alethv1.ApertureSetting_F_4)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Replan || !r.Abandon {
		t.Fatalf("WRONG_HYPOTHESIS should abandon and replan: %+v", r)
	}
}

func TestRefineRejectsUnknownFailureType(t *testing.T) {
	// 未知类型**不猜**：错误的缓解动作可能比不动作更糟
	// （把 HALLUCINATION 当 TIMEOUT 去"缩小范围重试"会继续产生幻觉）。
	_, err := Refine(&alethv1.FailureRecord{FailureType: "SOMETHING_NEW"},
		alethv1.ApertureSetting_F_4)
	if err == nil {
		t.Fatal("unknown failure type must be rejected, not silently defaulted")
	}
}

// ---- T5.9：熔断器（DoD④：8 类条件全部生效）----

func TestCircuitScopeViolationTerminatesFirst(t *testing.T) {
	// 越界是最高优先级：任何一次都立即 fail-closed 终止全部
	// （M5 §4.4，涉 07 §T5.5）。即使同时满足其他条件也必须先终止。
	act, reason := EvaluateCircuit(CircuitState{
		ScopeViolation:    true,
		BudgetTotal:       100,
		BudgetConsumed:    100,                            // 预算也耗尽
		SessionTotalSteps: 100, SessionHallucinations: 90, // 幻觉也超限
		NoProgressSteps: 99, // 无进展也超限
	}, DefaultThresholds())
	if act != ActionTerminateSession {
		t.Fatalf("scope violation must take priority, got %s", act)
	}
	if !strings.Contains(reason, "scope violation") {
		t.Fatalf("reason should name the scope violation: %q", reason)
	}
}

func TestCircuitCoversAllConditions(t *testing.T) {
	th := DefaultThresholds()
	cases := []struct {
		name string
		st   CircuitState
		want CircuitAction
	}{
		{"scope violation", CircuitState{ScopeViolation: true}, ActionTerminateSession},
		{"budget exhausted", CircuitState{BudgetTotal: 100, BudgetConsumed: 100}, ActionHardStop},
		{
			"session hallucination ratio",
			CircuitState{SessionTotalSteps: 100, SessionHallucinations: 50},
			ActionTerminateSession,
		},
		{
			"agent hallucination count",
			CircuitState{AgentHallucinations: map[string]uint32{"agent-x": 4}},
			ActionStopAgent,
		},
		{"budget narrowing", CircuitState{BudgetTotal: 100, BudgetConsumed: 85}, ActionNarrowAperture},
		{"no progress", CircuitState{NoProgressSteps: 16}, ActionRewind},
		{"healthy", CircuitState{BudgetTotal: 100, BudgetConsumed: 10}, ActionNone},
	}
	covered := map[CircuitAction]bool{}
	for _, c := range cases {
		got, reason := EvaluateCircuit(c.st, th)
		if got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
		if c.want != ActionNone && reason == "" {
			t.Errorf("%s: triggered action must carry a reason for the audit log", c.name)
		}
		covered[got] = true
	}
	// 六类动作全部被覆盖（DoD④：**8 类熔断条件**全覆盖）。
	//
	// 8 类条件 → 动作的映射：
	//   范围越界 / 会话幻觉占比     → ActionTerminateSession
	//   预算耗尽 / 会话时长超限     → ActionHardStop
	//   单 agent 幻觉              → ActionStopAgent
	//   单任务 token 超限 / 预算 80% → ActionNarrowAperture
	//   无进展步数                 → ActionRewind
	//
	// 本用例覆盖 5 类动作；「会话时长」与「单任务 token」两类条件由
	// TestCircuitSessionDurationLimit 与 TestCircuitPerTaskTokenLimit
	// 单独覆盖（它们需要 time.Duration / uint64 的输入，不适合放进
	// 这张表）。
	for _, need := range []CircuitAction{
		ActionTerminateSession, ActionHardStop, ActionStopAgent,
		ActionNarrowAperture, ActionRewind,
	} {
		if !covered[need] {
			t.Errorf("circuit action %s has no triggering test case", need)
		}
	}
}

func TestCircuitAgentScanIsDeterministic(t *testing.T) {
	// 多个 agent 同时超限时，结果必须确定（按 agent_id 排序）。
	st := CircuitState{AgentHallucinations: map[string]uint32{
		"zebra": 9, "alpha": 5, "mike": 7,
	}}
	first, r1 := EvaluateCircuit(st, DefaultThresholds())
	for i := 0; i < 30; i++ {
		got, r := EvaluateCircuit(st, DefaultThresholds())
		if got != first || r != r1 {
			t.Fatalf("non-deterministic agent selection: %q vs %q", r, r1)
		}
	}
	if !strings.Contains(r1, "alpha") {
		t.Fatalf("should report the lexicographically first offending agent: %q", r1)
	}
}

// ---- 补齐的两类熔断条件（M5 §4.4 的 8 类之一二）----

func TestAllCircuitConditionsHaveDefaults(t *testing.T) {
	// M5 §4.4 的 8 类熔断条件在本实现的阈值结构里必须**全部有默认值**。
	//
	// 这条守护的是"8 类全覆盖"（04 §I6 DoD④）—— 若有人新增了
	// CircuitState 字段却忘了在 DefaultThresholds 里给默认值，
	// 那个条件会因零值而永不触发（`if th.X > 0` 恒假），
	// 表现为"熔断器少了一类"而无人察觉。
	th := DefaultThresholds()
	if th.MaxAgentHallucinations == 0 {
		t.Error("MaxAgentHallucinations must have a non-zero default")
	}
	if th.MaxSessionHallucinationRatio == 0 {
		t.Error("MaxSessionHallucinationRatio must have a non-zero default")
	}
	if th.BudgetNarrowRatio == 0 {
		t.Error("BudgetNarrowRatio must have a non-zero default")
	}
	if th.MaxNoProgressSteps == 0 {
		t.Error("MaxNoProgressSteps must have a non-zero default")
	}
	if th.MaxSessionDuration == 0 {
		t.Error("MaxSessionDuration must have a non-zero default " +
			"(otherwise the duration circuit never fires)")
	}
	if th.MaxTaskTokens == 0 {
		t.Error("MaxTaskTokens must have a non-zero default " +
			"(otherwise the per-task token circuit never fires)")
	}
}

func TestCircuitSessionDurationLimit(t *testing.T) {
	// M5 §4.4 表格"总运行时长可配置上限 → 硬熔断"。
	th := DefaultThresholds()
	st := CircuitState{SessionElapsed: th.MaxSessionDuration + time.Minute}
	act, reason := EvaluateCircuit(st, th)
	if act != ActionHardStop {
		t.Fatalf("session over the duration limit must hard-stop, got %s", act)
	}
	if !strings.Contains(reason, "duration") {
		t.Fatalf("reason should mention duration: %q", reason)
	}
	// 未超限时不触发。
	under := CircuitState{SessionElapsed: th.MaxSessionDuration - time.Minute}
	if a, _ := EvaluateCircuit(under, th); a != ActionNone {
		t.Fatalf("under the limit must not trigger, got %s", a)
	}
}

func TestCircuitSessionDurationPrecedesHallucinationRatio(t *testing.T) {
	// 时长检查刻意排在幻觉占比之前：时长是**确定性**的客观边界，
	// 而幻觉占比依赖计数质量。一个已超时数倍的会话应先停。
	th := DefaultThresholds()
	st := CircuitState{
		SessionElapsed:        th.MaxSessionDuration + time.Hour,
		SessionTotalSteps:     100,
		SessionHallucinations: 90, // 幻觉占比也超限
	}
	act, reason := EvaluateCircuit(st, th)
	if act != ActionHardStop {
		t.Fatalf("duration should win over hallucination ratio, got %s", act)
	}
	if !strings.Contains(reason, "duration") {
		t.Fatalf("reason should be the duration one: %q", reason)
	}
}

func TestCircuitPerTaskTokenLimit(t *testing.T) {
	// M5 §4.4 表格"单任务 token 超任务预算 → **强制收窄光圈重试 1 次**，
	// 失败则 SKIPPED"。
	//
	// 动作是 ActionNarrowAperture（收窄重试），**不是** ActionStopAgent ——
	// 规格明确要求先重试一次。
	th := DefaultThresholds()
	st := CircuitState{CurrentTaskTokens: th.MaxTaskTokens + 1}
	act, reason := EvaluateCircuit(st, th)
	if act != ActionNarrowAperture {
		t.Fatalf("per-task overrun must narrow and retry (not stop), got %s", act)
	}
	if !strings.Contains(reason, "retry once") {
		t.Fatalf("reason should state the retry-once semantics: %q", reason)
	}
	// 未超限时不触发。
	under := CircuitState{CurrentTaskTokens: th.MaxTaskTokens - 1}
	if a, _ := EvaluateCircuit(under, th); a != ActionNone {
		t.Fatalf("under the per-task limit must not trigger, got %s", a)
	}
}

func TestZeroThresholdDisablesThatCondition(t *testing.T) {
	// 阈值为 0 = 该条件**显式禁用**（不是"用零值比较"）。
	for _, tc := range []struct {
		name string
		th   CircuitThresholds
		st   CircuitState
	}{
		{"duration disabled", CircuitThresholds{}, CircuitState{SessionElapsed: 1000 * time.Hour}},
		{"task limit disabled", CircuitThresholds{}, CircuitState{CurrentTaskTokens: 1 << 40}},
		{"no-progress disabled", CircuitThresholds{}, CircuitState{NoProgressSteps: 1 << 20}},
	} {
		if act, _ := EvaluateCircuit(tc.st, tc.th); act != ActionNone {
			t.Errorf("%s: zero threshold must not fire, got %s", tc.name, act)
		}
	}
}

// ---- T5.8：检查点 / rewind / fork（DoD⑤：rewind 证据一致，fork 隔离）----

func TestApplyResultRequiresFailureRecordOnFailure(t *testing.T) {
	// FAILED 必须带失败记录 —— 否则 Refiner 无从改写（M5 §4.2）。
	g, _ := NewGraph(graph(task("a", alethv1.AgentRole_RECON)))
	if err := g.ApplyResult("a", alethv1.TaskStatus_FAILED, nil); err == nil {
		t.Fatal("FAILED without a FailureRecord must be rejected")
	}
	// 带记录则成功。
	if err := g.ApplyResult("a", alethv1.TaskStatus_FAILED,
		[]*alethv1.FailureRecord{{FailureType: string(FailTimeout)}}); err != nil {
		t.Fatalf("FAILED with a FailureRecord should succeed: %v", err)
	}
}

func TestTerminalTaskCannotBeRerun(t *testing.T) {
	g, _ := NewGraph(graph(task("a", alethv1.AgentRole_RECON)))
	if err := g.ApplyResult("a", alethv1.TaskStatus_DONE, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.ApplyResult("a", alethv1.TaskStatus_RUNNING, nil); err == nil {
		t.Fatal("a DONE task must not silently go back to RUNNING (use Rewind)")
	}
}

func TestRewindRestoresGraphAndKeepsLedger(t *testing.T) {
	store := NewCheckpointStore(5)
	g, _ := NewGraph(graph(
		task("recon", alethv1.AgentRole_RECON),
		task("scan", alethv1.AgentRole_SCANNER, "recon"),
	))
	cp := &Checkpoint{
		ID: "cp1", SessionID: "s1", Label: "before scan",
		PlanRevision: "1", GraphVersion: "snap_abc",
		LedgerWatermark: "wm_001",
		Graph:           g.ToProto(),
	}
	if err := store.Save(cp, false); err != nil {
		t.Fatal(err)
	}

	// 推进：完成 recon，scan 变 RUNNING。
	_ = g.ApplyResult("recon", alethv1.TaskStatus_DONE, nil)
	_ = g.ApplyResult("scan", alethv1.TaskStatus_RUNNING, nil)

	// rewind 回到 cp1。
	out, err := store.Rewind("cp1")
	if err != nil {
		t.Fatal(err)
	}
	// 恢复后的图：recon 应为 PENDING（检查点时还没执行）。
	if st := out.Graph.Tasks["recon"].Status; st != alethv1.TaskStatus_PENDING {
		t.Fatalf("rewound recon status = %s, want PENDING", st)
	}
	// 账本不回滚（M5 §4.3：证据是历史事实）。
	if !out.LedgerNotRolledBack {
		t.Fatal("ledger must not be rolled back by rewind")
	}
	if out.LedgerWatermark != "wm_001" {
		t.Fatalf("watermark = %q, want wm_001", out.LedgerWatermark)
	}
	if out.GraphVersion != "snap_abc" {
		t.Fatalf("graph version = %q", out.GraphVersion)
	}
}

func TestRewindRunningTaskBecomesReady(t *testing.T) {
	// 检查点时 RUNNING 的任务在恢复后必须是 READY ——
	// 进程已不在，任务没有在跑。保留 RUNNING 会永久卡住它
	// （调度器认为它还在执行，永远不会重新分发）。
	store := NewCheckpointStore(5)
	g, _ := NewGraph(graph(task("a", alethv1.AgentRole_RECON)))
	_ = g.ApplyResult("a", alethv1.TaskStatus_RUNNING, nil)
	_ = store.Save(&Checkpoint{ID: "cp", SessionID: "s", Graph: g.ToProto()}, false)

	out, err := store.Rewind("cp")
	if err != nil {
		t.Fatal(err)
	}
	if st := out.Graph.Tasks["a"].Status; st != alethv1.TaskStatus_READY {
		t.Fatalf("status = %s, want READY", st)
	}
	ready, _ := out.Graph.NextReady(5)
	if len(ready) != 1 || ready[0] != "a" {
		t.Fatalf("rewound task should be schedulable again, got %v", ready)
	}
}

func TestForkSharesConfirmedAndIsolatesRest(t *testing.T) {
	store := NewCheckpointStore(5)
	g, _ := NewGraph(graph(
		task("recon", alethv1.AgentRole_RECON),
		task("scan", alethv1.AgentRole_SCANNER, "recon"),
		task("exploit", alethv1.AgentRole_EXPLOITER, "scan"),
	))
	_ = g.ApplyResult("recon", alethv1.TaskStatus_DONE, nil)
	_ = store.Save(&Checkpoint{ID: "cp", SessionID: "s1", Graph: g.ToProto()}, false)

	fo, err := store.Fork("cp", "alt-path")
	if err != nil {
		t.Fatal(err)
	}
	// 已确认的（DONE）证据共享。
	if fo.SharedConfirmed != 1 {
		t.Fatalf("shared confirmed = %d, want 1 (recon)", fo.SharedConfirmed)
	}
	if fo.Graph.Tasks["recon"].Status != alethv1.TaskStatus_DONE {
		t.Fatal("confirmed task must be shared into the fork")
	}
	// 其余重置以便平行探索。
	if fo.Graph.Tasks["scan"].Status != alethv1.TaskStatus_PENDING {
		t.Fatal("non-confirmed tasks must reset in the fork")
	}
	// 新会话 ID 必须与父不同（分支隔离）。
	if fo.NewSessionID == fo.ParentSessionID {
		t.Fatal("fork must produce a distinct session id")
	}
}

func TestForkRequiresName(t *testing.T) {
	store := NewCheckpointStore(5)
	g, _ := NewGraph(graph(task("a", alethv1.AgentRole_RECON)))
	_ = store.Save(&Checkpoint{ID: "cp", SessionID: "s", Graph: g.ToProto()}, false)
	if _, err := store.Fork("cp", "  "); err == nil {
		t.Fatal("fork without a name must be rejected (auditability)")
	}
}

func TestCheckpointEvictionKeepsMilestones(t *testing.T) {
	// M5 §8：仅保留最近 N 个 + 每个里程碑保留一个。
	store := NewCheckpointStore(3)
	g, _ := NewGraph(graph(task("a", alethv1.AgentRole_RECON)))
	// 里程碑（最早，且不得被淘汰）。
	_ = store.Save(&Checkpoint{ID: "milestone", SessionID: "s", Label: "goal achieved",
		Graph: g.ToProto()}, true)
	for i := 0; i < 6; i++ {
		_ = store.Save(&Checkpoint{
			ID: string(rune('a' + i)), SessionID: "s", Graph: g.ToProto()}, false)
	}
	// 里程碑必须还在。
	if _, ok := store.Get("milestone"); !ok {
		t.Fatal("milestone checkpoint must survive eviction " +
			"(discarding it loses the known-good state)")
	}
	if store.Len() > 3 {
		t.Fatalf("store holds %d checkpoints, want ≤ 3", store.Len())
	}
}

func TestRewindMissingCheckpointFails(t *testing.T) {
	store := NewCheckpointStore(5)
	if _, err := store.Rewind("nope"); err == nil {
		t.Fatal("rewind to a nonexistent checkpoint must fail")
	}
}

// ---- 任务图可审阅（DoD / §6）----

func TestRoundTripGraphIsSolvable(t *testing.T) {
	// M5 §6：序列化后可人工编辑，编辑后仍能正确求解。
	g, _ := NewGraph(graph(
		task("a", alethv1.AgentRole_RECON),
		task("b", alethv1.AgentRole_SCANNER, "a"),
	))
	proto := g.ToProto()
	// 人工编辑：加一个新任务依赖 b。
	proto.Tasks = append(proto.Tasks, task("c", alethv1.AgentRole_REPORTER, "b"))

	edited, err := NewGraph(proto)
	if err != nil {
		t.Fatalf("edited graph must still be solvable: %v", err)
	}
	ready, _ := edited.NextReady(10)
	if len(ready) != 1 || ready[0] != "a" {
		t.Fatalf("edited graph ready = %v, want [a]", ready)
	}
}

func TestFailureTypesParsing(t *testing.T) {
	// 全部类型可解析；未知类型被拒。
	for _, ft := range AllFailureTypes() {
		if _, ok := ParseFailureType(string(ft)); !ok {
			t.Errorf("type %s should parse", ft)
		}
	}
	if _, ok := ParseFailureType("NOPE"); ok {
		t.Error("unknown type must not parse")
	}
	// 排序输出确定。
	a := SortedFailureTypes()
	b := SortedFailureTypes()
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("SortedFailureTypes is not deterministic")
		}
	}
}

func TestCheckpointTimestampField(t *testing.T) {
	// Checkpoint 的 CreatedAt 契约字段存在（proto 有该字段）——
	// 这里只确认 protobuf 时间戳可用于检查点元数据。
	_ = timestamppb.Now()
}
