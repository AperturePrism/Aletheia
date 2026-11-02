"""执行循环：规划 → 派发 → 回写，直到无就绪任务或触发终止。

# 这个循环在整个系统里的位置

`docs/04` §I6 的 Agent 池此前**不存在**：Go 侧 `core/orchestrate` 是确定性的
（`NextReady` 零 LLM，有静态检查守护），Python 侧有 Provider 却无人调用，
于是系统只能"被外部喂任务图"，不能自己跑完一场渗透。

本模块把两侧接起来，同时**不破坏**原有的确定性分工：

    LLM（Planner）   → 只产出「有哪些任务、依赖关系」
    Go（Orchestrator）→ 确定性拓扑 + 资源约束，回答「现在该跑哪些」
    Agent（本模块）  → 执行一个任务，产出证据引用或失败记录
    LLM（Agent 内部）→ 只在任务内部做判断，不影响全局序列

关键点：**循环本身不含任何 LLM 调用**。它只做四件事 —— 问就绪集合、
派发、回写、判断是否该停。这样"序列"始终可复现（P-2/P-5）。

# 为什么循环里必须有"停"的硬判据

编排层最容易出的故障不是报错，而是**安静地卡住**：
`NextReady` 返回空集，但还有任务不是 DONE —— 此时若无判据，
循环会永远转下去（或干脆退出并让人以为"做完了"）。

本模块把"空就绪但未完成"当作**显式的失败终止**，并给出阻塞原因，
而不是：
  · 无限重试（烧预算）
  · 当作成功（虚假完成 —— `docs/10` §0 最反对的那种）

# 与闸门链的关系

本模块**不直接**碰 Scope / Gateway / Ledger / Governor。所有动作都经
`IngestService.Execute`（Go 侧），那道闸门内部已按
Scope → Gateway → Sandbox → Ledger 的顺序执行（见 `core/ingest/service.go`）。
Agent 拿到的任务上下文也由 `ApertureService.Assemble` 产出（L2 装配，
非 LLM 拼装 —— `05` §6.1 的 `context` 字段注释即此意）。

换句话说：**执行侧不拥有任何特权路径**（`07` §T7 的要求：MCP 路径与
CLI/WebUI 走同一套校验，不得有特权路径）。这条同样适用于 Agent 池。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from aletheia.execution.planner import PlanDraft, PlannerLLM


class ExecutionError(RuntimeError):
    """执行侧不可恢复的错误。"""


class StalledError(ExecutionError):
    """无就绪任务但仍有未完成任务 —— 计划无法推进。

    单独成一个类型：这不是"跑完了"，而是"卡住了"。
    两者混同会让一场失败的渗透看起来像一场成功的渗透。
    """


@dataclass(frozen=True)
class TaskOutcome:
    """一个任务的执行结果（回写给 Orchestrator 的最小集合）。"""

    task_id: str
    #: "DONE" / "FAILED" / "SKIPPED"
    status: str
    produced_evidence: tuple[str, ...] = ()
    #: 失败记录：(failure_type, detail, refiner_guidance)
    failures: tuple[tuple[str, str, str], ...] = ()


class OrchestratorPort(Protocol):
    """编排层端口（真实实现是 gRPC 客户端）。

    刻意只暴露循环需要的三个方法 —— 端口越窄，换成假实现越容易，
    也越不容易在 Agent 侧偷偷绕过闸门。
    """

    def plan(self, session_id: str, draft: PlanDraft, budget_tokens: int) -> str:
        """提交任务图，返回 `graph_id`。"""

    def next_ready(self, session_id: str, graph_id: str, slots: int) -> list[str]:
        """返回当前可执行的任务 id（确定性结果，由 Go 侧求解）。"""

    def report(self, session_id: str, outcome: TaskOutcome) -> None:
        """回写任务结果。"""


class AgentRunner(Protocol):
    """单个任务的执行者（Agent 池的入口）。"""

    def run(self, task: Any) -> TaskOutcome: ...


@dataclass
class RunReport:
    """一次执行循环的结论（用于审计与测试断言）。"""

    session_id: str
    graph_id: str
    #: 已回写的任务数。
    completed: int = 0
    #: 每个任务的结果（按回写顺序）。
    outcomes: list[TaskOutcome] = field(default_factory=list)
    #: 终止原因（人类可读，必须非空 —— 见下方 `stop_reason`）。
    stop_reason: str = ""
    #: 循环轮数（每轮问一次 NextReady）。
    rounds: int = 0

    def status_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for o in self.outcomes:
            out[o.status] = out.get(o.status, 0) + 1
        return out


#: 单个任务的默认并发槽位。
#:
#: 保守取 2：Agent 池的价值在"高价值环节"（04 §I6 决策②），
#: 而不是靠并发堆吞吐；并发越高越难保证证据的可归因性。
DEFAULT_SLOTS = 2

#: 循环轮数上限。这是**防跑飞**的兜底，不是正常终止条件 ——
#: 正常情况下会先因"无就绪"或"全部完成"退出。
#: 取值按 `MAX_TASKS / 最小槽位` 留足余量。
MAX_ROUNDS = 200


@dataclass
class ExecutionLoop:
    """把 Planner / Orchestrator / Agent 池串起来。"""

    planner: PlannerLLM
    orchestrator: OrchestratorPort
    runner: AgentRunner
    slots: int = DEFAULT_SLOTS
    max_rounds: int = MAX_ROUNDS
    #: 可选：每轮回调（用于进度显示与测试观察）。
    on_round: Any = None

    def run(
        self,
        *,
        session_id: str,
        objective: str,
        scope_summary: str = "",
        session_budget: int = 50_000,
        scan: Any = None,
    ) -> RunReport:
        """跑完一场：规划 → 循环派发 → 返回结论。

        `scan` 透传给 Planner 的 Provider 调用（出站扫描，R7）。
        """
        if not session_id.strip():
            raise ExecutionError("session_id 不能为空 —— 审计产物必须能追溯到会话")

        draft = self.planner.propose(
            objective,
            scope_summary=scope_summary,
            session_budget=session_budget,
            scan=scan,
        )
        graph_id = self.orchestrator.plan(session_id, draft, session_budget)
        if not graph_id:
            raise ExecutionError("Orchestrator 未返回 graph_id，无法继续派发")

        report = RunReport(session_id=session_id, graph_id=graph_id)
        planned = {t.task_id for t in draft.tasks}

        for round_no in range(1, self.max_rounds + 1):
            report.rounds = round_no
            ready = self.orchestrator.next_ready(session_id, graph_id, self.slots)

            if not ready:
                # ★ 空就绪有两种含义，必须区分：
                #   (a) 全部完成 → 正常结束
                #   (b) 还有未完成的，但被依赖/资源卡住 → **卡死**
                remaining = planned - {o.task_id for o in report.outcomes}
                if remaining:
                    report.stop_reason = (
                        f"stalled: {len(remaining)} 个任务未完成但无就绪任务 "
                        f"（{sorted(remaining)}）—— 计划无法推进，"
                        "按失败处理而不是当作完成"
                    )
                    raise StalledError(report.stop_reason)
                report.stop_reason = "all tasks completed"
                return report

            # 只处理本轮到位的槽位；`next_ready` 已按资源约束裁剪，
            # 这里再切一次是防御性的（不信任外部实现一定守约）。
            for task_id in ready[: self.slots]:
                if task_id not in planned:
                    # 编排层返回了计划外的 id —— 说明两侧状态不一致，
                    # 此时继续派发会产生无归属的证据。
                    raise ExecutionError(
                        f"Orchestrator 返回了计划外的任务 {task_id!r}"
                        f"（计划中只有 {sorted(planned)}）"
                    )
                outcome = self.runner.run(task_id)
                if outcome.task_id != task_id:
                    raise ExecutionError(
                        f"Agent 回写的 task_id 与派发不符：派出 {task_id!r}，"
                        f"回写 {outcome.task_id!r}（张冠李戴会污染证据归属）"
                    )
                self.orchestrator.report(session_id, outcome)
                report.outcomes.append(outcome)
                report.completed += 1

            if self.on_round is not None:
                self.on_round(report)

            if planned and {o.task_id for o in report.outcomes} >= planned:
                report.stop_reason = "all tasks completed"
                return report

        # 跑到上限仍未结束：这是异常，不能当作成功。
        report.stop_reason = f"round limit {self.max_rounds} reached"
        raise ExecutionError(report.stop_reason)
