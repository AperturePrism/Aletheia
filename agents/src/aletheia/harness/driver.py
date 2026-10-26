"""评测驱动器（I11 未竟项「一键复跑」的核心，modules/M9 §5.1/§8）。

职责边界（制度设计，非实现便利）：
  · 适配器（BenchmarkAdapter）只负责靶场生命周期与 ground truth；
  · 被测系统是**注入的回调** —— 适配器不产出结论、不知道被测系统
    怎么跑（M4 §3.2 N1 的同款隔离：不同时是选手与裁判）；
  · 驱动器把两者接起来：逐任务执行 → TaskResult → HarnessRun →
    交给 report.build_report（指标全部脚本化计算，无手工填数）。

污染检测语义（M9 §8）：`reset_between_tasks=True` 时每个任务前调用
adapter.reset() —— 第二次评测必须跑在重置后的状态上，否则结果不可比。
"""

from __future__ import annotations

import time
from collections.abc import Callable

from aletheia.harness.adapter import (
    BenchmarkAdapter,
    BenchmarkTask,
    HarnessRun,
    ReproducibilityManifest,
    TaskResult,
    score_task,
)

#: 被测系统接口：吃一个任务，返回该任务的结果。
#: 生产实现是 agent 编排层；测试用替身；dry-run 返回未解决+原因。
SystemFn = Callable[[BenchmarkTask], TaskResult]


class DryRunSystem:
    """无被测系统时的占位：每个任务返回「未执行」。

    用途：一键复跑脚本的 --dry-run 模式（验证靶场/任务清单/驱动器
    全链可达，不烧 LLM 成本）。solved=False 且 failure_reason 显式
    —— 不伪造任何结果（docs/09 §6 #4 的 harness 侧同款约束）。
    """

    def __call__(self, task: BenchmarkTask) -> TaskResult:
        return TaskResult(
            task_id=task.task_id,
            solved=False,
            reported=(),
            failure_reason="dry-run: no system under test wired",
        )


def run_benchmark(
    adapter: BenchmarkAdapter,
    system: SystemFn,
    manifest: ReproducibilityManifest,
    *,
    reset_between_tasks: bool = True,
    task_timeout_s: float = 0.0,
) -> HarnessRun:
    """跑一次完整评测，返回 HarnessRun（供 build_report 消费）。

    语义：
      · setup() → 逐任务（可选 reset → system(task) → 记录）→ teardown()；
      · 单任务异常**不中断**整场 —— 记为失败案例（结构化归档，
        M9 §8：失败分析价值不低于成功）；
      · 结果数与任务数严格一致（缺失即内部不变量破坏，显式抛错）。
    """
    tasks = adapter.tasks()
    if not tasks:
        raise ValueError(f"benchmark {adapter.name!r} returned no tasks")

    # 重置语义（M9 §8）：默认每任务前 reset()；适配器声明重置由外部
    # （如容器重启）承担时，任务间跳过 no-op reset —— 污染面以
    # reset_is_external 如实暴露，不假装已重置。
    external_reset = bool(getattr(adapter, "reset_is_external", False))
    adapter.setup()
    try:
        results: list[TaskResult] = []
        for task in tasks:
            if reset_between_tasks and not external_reset:
                adapter.reset()
            started = time.monotonic()
            try:
                result = system(task)
            except Exception as exc:  # noqa: BLE001 —— 单任务失败结构化归档
                result = TaskResult(
                    task_id=task.task_id,
                    solved=False,
                    failure_reason=f"system raised {type(exc).__name__}: {exc}",
                )
            if task_timeout_s > 0 and time.monotonic() - started > task_timeout_s:
                result = TaskResult(
                    task_id=task.task_id,
                    solved=False,
                    reported=result.reported,
                    tokens=result.tokens,
                    cost=result.cost,
                    failure_reason=(result.failure_reason or "") + " (timed out)",
                )
            if result.task_id != task.task_id:
                raise ValueError(
                    f"system returned mismatched task_id: expected {task.task_id!r}, "
                    f"got {result.task_id!r}"
                )
            results.append(result)
    finally:
        adapter.teardown()

    if len(results) != len(tasks):
        raise RuntimeError(  # pragma: no cover —— 上面的逐任务循环保证不变量
            f"internal invariant broken: {len(results)} results for {len(tasks)} tasks"
        )
    return HarnessRun(benchmark=adapter.name, tasks=list(tasks), results=results, manifest=manifest)


def aggregate_with_scores(run: HarnessRun) -> dict[str, dict[str, int]]:
    """逐任务打分汇总（tp/fp/fn + solved 计数），供报告或 quick 对比。

    HarnessRun.aggregate() 是全场合计；本函数保留**分任务**视图 ——
    失败分析（M9 §9）需要知道哪些任务在哪个类别上失败。
    """
    out: dict[str, dict[str, int]] = {}
    by_id = {t.task_id: t for t in run.tasks}
    for r in run.results:
        task = by_id.get(r.task_id)
        if task is None:
            raise ValueError(f"result references unknown task {r.task_id!r}")
        tp, fp, fn = score_task(r, task)
        entry = out.setdefault(
            task.category or "uncategorized",
            {"tp": 0, "fp": 0, "fn": 0, "solved": 0, "tasks": 0},
        )
        entry["tp"] += tp
        entry["fp"] += fp
        entry["fn"] += fn
        entry["solved"] += int(r.solved)
        entry["tasks"] += 1
    return out
