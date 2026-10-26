"""评测驱动器与 Juice Shop 适配器测试（I11 未竟项收口）。

覆盖：驱动器全链（setup→逐任务→teardown）、单任务异常结构化归档、
task_id 不变量、DryRunSystem 诚实占位、分类打分视图、reset 语义
（默认逐任务 reset / 外部重置跳过）、适配器探测 fail-closed 与
ground truth 任务集。
"""

from __future__ import annotations

import pytest

from aletheia.harness.adapter import (
    BenchmarkAdapter,
    BenchmarkTask,
    ReproducibilityManifest,
    TaskResult,
)
from aletheia.harness.driver import DryRunSystem, aggregate_with_scores, run_benchmark
from aletheia.harness.juiceshop import JUICE_SHOP_TASKS, JuiceShopAdapter


class FakeAdapter(BenchmarkAdapter):
    """脚本化适配器：记录生命周期调用序列。"""

    def __init__(self, tasks: list[BenchmarkTask] | None = None) -> None:
        self.calls: list[str] = []
        # 判空必须用 is None：[] 是合法入参（空任务清单用例），or 会吞掉它。
        self._tasks = (
            tasks
            if tasks is not None
            else [
                BenchmarkTask(task_id="t1", ground_truth=("g1",), category="cat-a"),
                BenchmarkTask(task_id="t2", ground_truth=("g2",), category="cat-a"),
                BenchmarkTask(task_id="t3", ground_truth=("g3",), category="cat-b"),
            ]
        )

    @property
    def name(self) -> str:
        return "fake"

    def setup(self) -> None:
        self.calls.append("setup")

    def tasks(self) -> list[BenchmarkTask]:
        return list(self._tasks)

    def teardown(self) -> None:
        self.calls.append("teardown")

    def reset(self) -> None:
        self.calls.append("reset")


def good_system(task: BenchmarkTask) -> TaskResult:
    """solved：reported 等于 ground truth。"""
    return TaskResult(task_id=task.task_id, solved=True, reported=task.ground_truth, tokens=10)


def test_driver_full_lifecycle_and_scoring() -> None:
    adapter = FakeAdapter()
    run = run_benchmark(adapter, good_system, ReproducibilityManifest(system_version="t"))

    assert adapter.calls == ["setup", "reset", "reset", "reset", "teardown"]  # 逐任务 reset
    assert [r.task_id for r in run.results] == ["t1", "t2", "t3"]
    assert all(r.solved for r in run.results)

    scores = aggregate_with_scores(run)
    assert scores["cat-a"] == {"tp": 2, "fp": 0, "fn": 0, "solved": 2, "tasks": 2}
    assert scores["cat-b"] == {"tp": 1, "fp": 0, "fn": 0, "solved": 1, "tasks": 1}


def test_driver_reset_skipped_when_external() -> None:
    """适配器声明外部重置（如 Juice Shop 容器重启）→ 任务间不调 no-op reset。"""

    class ExternalResetAdapter(FakeAdapter):
        @property
        def reset_is_external(self) -> bool:
            return True

    adapter = ExternalResetAdapter()
    run_benchmark(adapter, good_system, ReproducibilityManifest(system_version="t"))
    assert "reset" not in adapter.calls  # no-op reset 被跳过
    assert adapter.calls[0] == "setup" and adapter.calls[-1] == "teardown"


def test_driver_reset_disabled() -> None:
    adapter = FakeAdapter()
    run_benchmark(
        adapter,
        good_system,
        ReproducibilityManifest(system_version="t"),
        reset_between_tasks=False,
    )
    assert adapter.calls == ["setup", "teardown"]


def test_driver_system_exception_is_structured_failure() -> None:
    """单任务抛异常 → 结构化失败案例（不中断整场，M9 §8）。"""

    def flaky(task: BenchmarkTask) -> TaskResult:
        if task.task_id == "t2":
            raise RuntimeError("boom")
        return good_system(task)

    run = run_benchmark(FakeAdapter(), flaky, ReproducibilityManifest(system_version="t"))
    assert len(run.results) == 3
    failed = [r for r in run.results if not r.solved]
    assert len(failed) == 1
    assert failed[0].task_id == "t2"
    assert "RuntimeError" in failed[0].failure_reason and "boom" in failed[0].failure_reason
    # 其余任务不受影响
    assert all(r.solved for r in run.results if r.task_id != "t2")


def test_driver_task_id_mismatch_is_invariant_violation() -> None:
    def wrong_id(task: BenchmarkTask) -> TaskResult:
        return TaskResult(task_id="other", solved=False, failure_reason="x")

    with pytest.raises(ValueError, match="mismatched task_id"):
        run_benchmark(FakeAdapter(), wrong_id, ReproducibilityManifest(system_version="t"))


def test_driver_empty_tasks_rejected() -> None:
    with pytest.raises(ValueError, match="no tasks"):
        run_benchmark(
            FakeAdapter(tasks=[]), good_system, ReproducibilityManifest(system_version="t")
        )


def test_dry_run_system_never_fakes_success() -> None:
    """DryRunSystem 诚实占位：solved=False + 显式 failure_reason。"""
    adapter = FakeAdapter()
    run = run_benchmark(adapter, DryRunSystem(), ReproducibilityManifest(system_version="t"))
    assert all(not r.solved for r in run.results)
    assert all("dry-run" in r.failure_reason for r in run.results)


# ---- JuiceShopAdapter ----


def test_juiceshop_tasks_have_ground_truth_and_categories() -> None:
    assert len(JUICE_SHOP_TASKS) >= 4
    for t in JUICE_SHOP_TASKS:
        assert t.ground_truth, f"{t.task_id} must carry ground truth"
        assert t.category, f"{t.task_id} must carry category (M9 §11 分场景)"
        assert t.difficulty, f"{t.task_id} must carry difficulty"


def test_juiceshop_setup_fingerprint_miss_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """靶场可达但指纹不匹配 → setup 抛错（跑出全 0 分比失败更误导）。"""
    adapter = JuiceShopAdapter("http://not-juice.test")

    class FakeResp:
        def read(self, n: int) -> bytes:
            return b"<html><title>Some Other Site</title></html>"

        def __enter__(self) -> FakeResp:
            return self

        def __exit__(self, *a: object) -> None:
            return None

    monkeypatch.setattr("urllib.request.urlopen", lambda *_a, **_k: FakeResp())
    with pytest.raises(RuntimeError, match="fingerprint miss"):
        adapter.setup()


def test_juiceshop_setup_unreachable_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = JuiceShopAdapter("http://127.0.0.1:1")  # 无服务端口

    def refuse(req, timeout=0):
        raise OSError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", refuse)
    with pytest.raises(RuntimeError, match="not reachable"):
        adapter.setup()


def test_juiceshop_setup_passes_on_fingerprint(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = JuiceShopAdapter("http://juice.test")

    class FakeResp:
        def read(self, n: int) -> bytes:
            return b"<html><title>OWASP Juice Shop</title></html>"

        def __enter__(self) -> FakeResp:
            return self

        def __exit__(self, *a: object) -> None:
            return None

    monkeypatch.setattr("urllib.request.urlopen", lambda *_a, **_k: FakeResp())
    adapter.setup()  # 不抛即通过
    # 全链 dry-run：setup + DryRunSystem + teardown
    run = run_benchmark(adapter, DryRunSystem(), ReproducibilityManifest(system_version="t"))
    assert len(run.results) == len(JUICE_SHOP_TASKS)
    assert adapter.reset_is_external  # 重置由容器重启承担（如实暴露）
