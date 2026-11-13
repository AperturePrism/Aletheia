"""执行循环的测试（`docs/04` §I6 的"规划 → 派发 → 回写"闭环）。

# 测试的重点是"停"与"错"，不是"跑通"

循环最容易出的故障不是抛异常，而是**安静地走错**：

· 无就绪任务但还有任务未完成时静默退出 → 看起来像"跑完了"（虚假完成）
· 编排层返回计划外的任务 id → 派发出去，证据归属不明
· Agent 回写的 task_id 与派发的不符 → 张冠李戴，污染证据链
· 无限循环 → 烧预算

因此本文件用**假端口**（不需要 daemon、不需要网络）逐条锁定这些行为。
假端口还有个附带好处：能断言"循环本身零 LLM 调用"——
`FakePlanner` 记录调用次数，循环里若偷偷调了模型会立刻暴露。
"""

from __future__ import annotations

import pytest

from aletheia.execution import (
    ExecutionError,
    ExecutionLoop,
    PlanDraft,
    PlannerLLM,
    StalledError,
    TaskOutcome,
)
from aletheia.execution.planner import DraftTask

# ---------------------------------------------------------------------------
# 假实现
# ---------------------------------------------------------------------------


class FakeRouter:
    """满足 `Router.chat(tier, prompt)` 的假模型。

    `reply` 是模型"输出"的原文；可用 `calls` 断言调用次数与档位。
    """

    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.calls: list[tuple[str, str]] = []

    def chat(self, tier: str, prompt: str, *, scan=None):
        self.calls.append((tier, prompt))

        class _R:
            content = self.reply

        return _R()


class FakeOrchestrator:
    """确定性编排层的最小假实现。

    `ready_script` 指定每轮返回哪些 id；用完后返回空列表。
    """

    def __init__(self, ready_script: list[list[str]], *, graph_id: str = "g1") -> None:
        self.ready_script = list(ready_script)
        self.graph_id = graph_id
        self.planned: PlanDraft | None = None
        self.reported: list[TaskOutcome] = []
        self.next_ready_calls = 0

    def plan(self, session_id: str, draft: PlanDraft, budget_tokens: int) -> str:
        self.planned = draft
        return self.graph_id

    def next_ready(self, session_id: str, graph_id: str, slots: int) -> list[str]:
        self.next_ready_calls += 1
        if self.ready_script:
            return self.ready_script.pop(0)
        return []

    def report(self, session_id: str, outcome: TaskOutcome) -> None:
        self.reported.append(outcome)


class FakeRunner:
    """按 task_id 产出结果的假 Agent 池。"""

    def __init__(self, *, status: str = "DONE", wrong_id: bool = False) -> None:
        self.status = status
        self.wrong_id = wrong_id
        self.dispatched: list[str] = []

    def run(self, task_id: str) -> TaskOutcome:
        self.dispatched.append(task_id)
        return TaskOutcome(
            task_id="someone-else" if self.wrong_id else task_id,
            status=self.status,
            produced_evidence=(f"ev_{task_id}",),
        )


def _plan_reply(ids: list[str]) -> str:
    """构造一段模型"输出"：n 个链式依赖的任务。"""
    import json

    tasks = [
        {
            "id": tid,
            "title": f"任务 {tid}",
            "objective": f"完成 {tid}",
            "role": "RECON",
            "depends_on": [ids[i - 1]] if i > 0 else [],
            "budget_tokens": 512,
        }
        for i, tid in enumerate(ids)
    ]
    return json.dumps({"tasks": tasks, "plan_rationale": "测试用计划"})


def _loop(orch: FakeOrchestrator, runner: FakeRunner, ids: list[str], **kw):
    router = FakeRouter(_plan_reply(ids))
    return (
        ExecutionLoop(
            planner=PlannerLLM(router=router),
            orchestrator=orch,
            runner=runner,
            **kw,
        ),
        router,
    )


# ---------------------------------------------------------------------------
# 正常路径
# ---------------------------------------------------------------------------


def test_runs_all_tasks_to_completion() -> None:
    orch = FakeOrchestrator([["t1"], ["t2"], ["t3"]])
    runner = FakeRunner()
    loop, _ = _loop(orch, runner, ["t1", "t2", "t3"])

    report = loop.run(session_id="s1", objective="扫一遍")

    assert report.stop_reason == "all tasks completed"
    assert report.completed == 3
    assert runner.dispatched == ["t1", "t2", "t3"]
    assert [o.task_id for o in report.outcomes] == ["t1", "t2", "t3"]
    assert orch.reported == report.outcomes
    assert report.status_counts() == {"DONE": 3}


def test_plan_is_submitted_before_dispatch() -> None:
    orch = FakeOrchestrator([["t1"]])
    loop, _ = _loop(orch, FakeRunner(), ["t1"])
    loop.run(session_id="s1", objective="x")
    assert orch.planned is not None
    assert [t.task_id for t in orch.planned.tasks] == ["t1"]


def test_planner_uses_planning_tier() -> None:
    """规划是重推理任务，必须走 "planning" 档（04 §I12 的分级路由）。"""
    orch = FakeOrchestrator([["t1"]])
    loop, router = _loop(orch, FakeRunner(), ["t1"])
    loop.run(session_id="s1", objective="x")
    assert router.calls[0][0] == "planning"


def test_slots_limit_dispatch_per_round() -> None:
    """`next_ready` 给了 3 个，但 slots=2 → 本轮只派发 2 个。"""
    orch = FakeOrchestrator([["t1", "t2", "t3"], ["t3"]])
    runner = FakeRunner()
    loop, _ = _loop(orch, runner, ["t1", "t2", "t3"], slots=2)

    loop.run(session_id="s1", objective="x")
    assert runner.dispatched == ["t1", "t2", "t3"]


def test_loop_itself_never_calls_the_model_twice() -> None:
    """★ 循环零 LLM：整个执行过程只应有一次模型调用（规划）。

    若有人日后把"每步问模型"塞进循环，这条会立刻红 —— 那正是
    `04` §I6 关键决策①明令禁止的"LLM 做逐步决策"。
    """
    orch = FakeOrchestrator([["t1"], ["t2"]])
    loop, router = _loop(orch, FakeRunner(), ["t1", "t2"])
    loop.run(session_id="s1", objective="x")
    assert len(router.calls) == 1, f"循环中出现了额外模型调用：{router.calls}"


# ---------------------------------------------------------------------------
# 失败必须显式（fail-closed）
# ---------------------------------------------------------------------------


def test_stall_raises_instead_of_reporting_success() -> None:
    """★ 无就绪但仍有未完成任务 → 必须抛 StalledError。

    这是本文件最重要的一条：若这里静默返回，一场失败的渗透
    会表现为"正常结束"，而调用方无从分辨。
    """
    orch = FakeOrchestrator([["t1"], []])  # t2 永远不会就绪
    loop, _ = _loop(orch, FakeRunner(), ["t1", "t2"])
    with pytest.raises(StalledError) as exc:
        loop.run(session_id="s1", objective="x")
    assert "stalled" in str(exc.value)
    assert "t2" in str(exc.value)


def test_empty_graph_id_is_rejected() -> None:
    orch = FakeOrchestrator([["t1"]], graph_id="")
    loop, _ = _loop(orch, FakeRunner(), ["t1"])
    with pytest.raises(ExecutionError, match="graph_id"):
        loop.run(session_id="s1", objective="x")


def test_empty_session_id_is_rejected() -> None:
    """审计产物必须能追溯到会话 —— 无 session 的执行没有意义。"""
    orch = FakeOrchestrator([["t1"]])
    loop, _ = _loop(orch, FakeRunner(), ["t1"])
    with pytest.raises(ExecutionError, match="session_id"):
        loop.run(session_id="   ", objective="x")


def test_unplanned_task_from_orchestrator_is_rejected() -> None:
    """编排层返回计划外的 id → 派发出去会产生无归属的证据。"""
    orch = FakeOrchestrator([["ghost"]])
    loop, _ = _loop(orch, FakeRunner(), ["t1"])
    with pytest.raises(ExecutionError, match="计划外"):
        loop.run(session_id="s1", objective="x")


def test_agent_returning_wrong_task_id_is_rejected() -> None:
    """★ 张冠李戴会污染证据归属（T4.2）—— 必须当场失败。"""
    orch = FakeOrchestrator([["t1"]])
    loop, _ = _loop(orch, FakeRunner(wrong_id=True), ["t1"])
    with pytest.raises(ExecutionError, match="张冠李戴"):
        loop.run(session_id="s1", objective="x")


def test_round_limit_is_an_error_not_success() -> None:
    """跑满轮数仍未结束 → 抛错，不能当作完成。"""
    orch = FakeOrchestrator([["t1"]] * 50)
    loop, _ = _loop(orch, FakeRunner(), ["t1", "t2"], max_rounds=3)
    with pytest.raises(ExecutionError, match="round limit"):
        loop.run(session_id="s1", objective="x")


def test_failed_status_is_reported_not_swallowed() -> None:
    """Agent 报 FAILED 时循环照常回写 —— 不掩盖失败，也不因此中断全场。"""
    orch = FakeOrchestrator([["t1"]])
    loop, _ = _loop(orch, FakeRunner(status="FAILED"), ["t1"])
    report = loop.run(session_id="s1", objective="x")
    assert report.status_counts() == {"FAILED": 1}
    assert orch.reported[0].status == "FAILED"


# ---------------------------------------------------------------------------
# 规划失败向上传播（不吞异常）
# ---------------------------------------------------------------------------


def test_invalid_model_output_propagates() -> None:
    """模型给了坏 JSON → 异常必须冒到调用方，而不是"没有任务可做"。"""
    orch = FakeOrchestrator([["t1"]])
    loop = ExecutionLoop(
        planner=PlannerLLM(router=FakeRouter("sorry, I cannot help with that")),
        orchestrator=orch,
        runner=FakeRunner(),
    )
    with pytest.raises(Exception) as exc:
        loop.run(session_id="s1", objective="x")
    assert "JSON" in str(exc.value) or "Plan" in type(exc.value).__name__


def test_plan_over_budget_rejected_before_any_dispatch() -> None:
    """规划阶段就超预算 → 一个任务都不该派发（避免第一步就 Reserve 失败）。"""
    import json

    reply = json.dumps(
        {
            "tasks": [
                {"id": "t1", "title": "a", "objective": "a", "role": "RECON", "budget_tokens": 900},
                {"id": "t2", "title": "b", "objective": "b", "role": "RECON", "budget_tokens": 900},
            ]
        }
    )
    orch = FakeOrchestrator([["t1"]])
    runner = FakeRunner()
    loop = ExecutionLoop(
        planner=PlannerLLM(router=FakeRouter(reply)),
        orchestrator=orch,
        runner=runner,
    )
    with pytest.raises(Exception, match="超过会话预算"):
        loop.run(session_id="s1", objective="x", session_budget=1000)
    assert runner.dispatched == []


# ---------------------------------------------------------------------------
# 计划内任务的完整集合判定
# ---------------------------------------------------------------------------


def test_completion_requires_all_planned_tasks() -> None:
    """只要还有计划内任务没回写，就不能判为完成。"""
    orch = FakeOrchestrator([["t1"]])
    loop, _ = _loop(orch, FakeRunner(), ["t1", "t2"])
    with pytest.raises(StalledError):
        loop.run(session_id="s1", objective="x")


def test_extra_round_after_completion_is_not_needed() -> None:
    """全部完成后不再多问一次 NextReady（省一次 RPC，也避免空转）。"""
    orch = FakeOrchestrator([["t1"]])
    loop, _ = _loop(orch, FakeRunner(), ["t1"])
    loop.run(session_id="s1", objective="x")
    assert orch.next_ready_calls == 1


def test_draft_task_ordering_preserved() -> None:
    """计划提交给编排层时保持模型给出的顺序（便于人工审阅 Diff）。"""
    orch = FakeOrchestrator([["b"], ["a"]])
    loop, _ = _loop(orch, FakeRunner(), ["b", "a"])
    loop.run(session_id="s1", objective="x")
    assert [t.task_id for t in orch.planned.tasks] == ["b", "a"]


def test_outcome_defaults_are_empty_not_none() -> None:
    o = TaskOutcome(task_id="t1", status="DONE")
    assert o.produced_evidence == ()
    assert o.failures == ()


def test_run_report_counts_mixed_statuses() -> None:
    from aletheia.execution.loop import RunReport

    r = RunReport(session_id="s", graph_id="g")
    r.outcomes = [
        TaskOutcome("t1", "DONE"),
        TaskOutcome("t2", "FAILED"),
        TaskOutcome("t3", "DONE"),
    ]
    assert r.status_counts() == {"DONE": 2, "FAILED": 1}


def test_draft_task_is_hashable_shape() -> None:
    d = DraftTask("t1", "T", "O", "RECON", ("t0",), 100)
    assert d.depends_on == ("t0",)
