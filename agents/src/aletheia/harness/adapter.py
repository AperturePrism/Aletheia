"""基准适配器框架与可复现性保障（modules/M9 §5.1、§5.3，T9.1/T9.12）。

# 适配器接口（M9 §5.1 原文签名）

    setup() -> Environment
    tasks() -> list[BenchmarkTask]
    run_task(task, system) -> TaskResult
    teardown() -> None
    reset() -> None

`reset()` 的存在是为了满足 M9 §8 的"靶场重置"测试要求：
**每次评测后状态完全重置（污染检测）** —— 不复位会让第二次评测
跑在第一次的残留状态上，结果不可比。

# ★ 可复现性保障（M9 §5.3）

| 项 | 措施 |
|---|---|
| 环境冻结 | 容器镜像按 digest 固定；依赖锁文件 |
| 随机性消除 | 固定随机种子；LLM temperature 记录并报告 |
| 时间快照 | 靶场版本、工具版本、模型版本全部记录 |

本模块提供 `ReproducibilityManifest` 承载这些字段 —— 它是报告第 1 节
（运行元信息）的数据来源，也是"第三方可在干净环境复现并得到同量级
结果"（§9 DoD）的技术前提。
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# 可复现性清单（M9 §5.3）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReproducibilityManifest:
    """可复现性清单 —— 报告第 1 节的数据来源（M9 §5.3）。

    缺任何一项都会让"第三方复跑"失效，因此 `missing_fields()` 让
    调用方**能检出**缺失项，而不是让报告静默地少几行。
    """

    #: 被测系统版本（如 git sha）。
    system_version: str = ""
    #: 模型与版本。
    model: str = ""
    #: LLM temperature（**必须记录并报告** —— §5.3 明文）。
    temperature: str = ""
    #: 随机种子。
    seed: str = ""
    #: 靶场与版本（含镜像 digest）。
    target_environment: str = ""
    #: 工具版本快照（nmap / httpx / nuclei 等）。
    tool_versions: dict[str, str] = field(default_factory=dict)
    #: 观测覆盖度（M7 §9 的声明，评报告第 1 节要求）。
    observation_coverage: str = ""

    #: 必需字段（缺一即不可复现）。
    REQUIRED: tuple[str, ...] = (
        "system_version",
        "model",
        "temperature",
        "seed",
        "target_environment",
    )

    def missing_fields(self) -> list[str]:
        """返回缺失的必需字段（空表示清单完整）。

        为什么"temperature 未记录"算缺失：M9 §5.3 明确要求记录并报告它。
        temperature=0 与 temperature=1 的结果分布完全不同，
        不记录就无法判断两次运行的差异是"系统改进"还是"采样噪声"。
        """
        return [f for f in self.REQUIRED if not str(getattr(self, f, "")).strip()]

    def is_complete(self) -> bool:
        return not self.missing_fields()

    def as_meta(self) -> dict[str, str]:
        """转成报告元信息字典。"""
        meta = {
            "system_version": self.system_version or "⚠ 未记录",
            "model": self.model or "⚠ 未记录",
            "temperature": self.temperature or "⚠ 未记录",
            "seed": self.seed or "⚠ 未记录",
            "target_environment": self.target_environment or "⚠ 未记录",
            "observation_coverage": self.observation_coverage or "⚠ 未记录",
        }
        for name, ver in sorted(self.tool_versions.items()):
            meta[f"tool:{name}"] = ver
        return meta


# ---------------------------------------------------------------------------
# 基准任务与结果
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BenchmarkTask:
    """一个基准任务（含 ground truth）。"""

    task_id: str
    #: 任务描述（给被测系统的输入）。
    description: str = ""
    #: 难度分级（如 HTB 的 easy/medium/hard —— M9 §5.1 要求分难度统计）。
    difficulty: str = ""
    #: ground truth：该任务的预期结果（如 flag、应检出的缺陷清单）。
    #:
    #: 必需 —— 没有 ground truth 就无法算精确率/召回率/假阴性率。
    ground_truth: tuple[str, ...] = ()
    #: 任务类别（用于分场景统计 —— §11 承诺 2"不混合"）。
    category: str = ""


@dataclass(frozen=True)
class TaskResult:
    """一次任务执行的结果。"""

    task_id: str
    #: 是否完成（拿到 flag / 达成目标）。
    solved: bool = False
    #: 被测系统报出的结论（用于与 ground truth 比对）。
    reported: tuple[str, ...] = ()
    #: 成本（token）。
    tokens: int = 0
    #: 成本（货币）。
    cost: float = 0.0
    #: 失败原因（未解决时）。**不得为空** —— M9 §8：
    #: "失败任务必须结构化归档，不可丢弃"。
    failure_reason: str = ""


def score_task(result: TaskResult, task: BenchmarkTask) -> tuple[int, int, int]:
    """把一个任务结果与 ground truth 比对，返回 `(tp, fp, fn)`。

    比对口径：`reported` 与 `ground_truth` 的集合交并。
    **大小写与空白不敏感**（不同靶场的 flag 格式有差异），
    但**不做模糊匹配** —— 模糊匹配会让"接近但不正确"被算成命中，
    那正是 `docs/10` §0 要防的失真。
    """
    truth = {_norm(x) for x in task.ground_truth}
    reported = {_norm(x) for x in result.reported}
    if not truth:
        # 无 ground truth → 无法计算，返回全零（调用方应据此判定样本不足）。
        return 0, 0, 0
    tp = len(truth & reported)
    fp = len(reported - truth)
    fn = len(truth - reported)
    return tp, fp, fn


def _norm(s: str) -> str:
    return s.strip().lower()


# ---------------------------------------------------------------------------
# 适配器接口（T9.1）
# ---------------------------------------------------------------------------


class BenchmarkAdapter(abc.ABC):
    """基准适配器接口（M9 §5.1）。

    具体适配器（CyBench / CVE-Bench / XBOW / HTB）需要外部环境
    （CTFd、容器编排、靶场 API），因此不在本模块内实现 ——
    本模块提供**框架**与**契约**，让适配器可插拔且可被测试替身验证。
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """基准名（如 `cybench`）。"""

    @abc.abstractmethod
    def setup(self) -> None:
        """起靶场/准备环境。"""

    @abc.abstractmethod
    def tasks(self) -> list[BenchmarkTask]:
        """返回任务清单（含 ground truth）。"""

    @abc.abstractmethod
    def teardown(self) -> None:
        """清理环境。"""

    @abc.abstractmethod
    def reset(self) -> None:
        """状态重置（M9 §8：**每次评测后状态完全重置，污染检测**）。"""


@dataclass
class HarnessRun:
    """一次完整评测运行的汇总（供 `build_report` 消费）。"""

    benchmark: str
    tasks: list[BenchmarkTask] = field(default_factory=list)
    results: list[TaskResult] = field(default_factory=list)
    manifest: ReproducibilityManifest = field(default_factory=ReproducibilityManifest)

    def aggregate(self) -> tuple[int, int, int, int]:
        """汇总 `(tp, fp, fn, ground_truth_total)`。

        全部任务都参与统计 —— M9 §10 风险栏："**全部基准跑全量任务，
        不做筛选**；公开失败案例"。因此本函数**不提供**过滤参数。
        """
        tp = fp = fn = truth_total = 0
        by_id = {t.task_id: t for t in self.tasks}
        for r in self.results:
            task = by_id.get(r.task_id)
            if task is None:
                continue
            a, b, c = score_task(r, task)
            tp += a
            fp += b
            fn += c
            truth_total += len(task.ground_truth)
        return tp, fp, fn, truth_total

    def unsolved(self) -> list[TaskResult]:
        """未解决的任务（**必须进报告第 5 节** —— M9 §2.2 N3 不筛选）。"""
        return [r for r in self.results if not r.solved]

    def reset_required_after_run(self, adapter: BenchmarkAdapter) -> None:
        """运行后调用适配器的 `reset()`（M9 §8 的污染检测要求）。

        单独成一个方法而不是在 `aggregate` 里顺手调用：调用时机是
        调用方的责任（评测可能在 reset 前还要读流水日志）。
        本方法存在的意义是让"必须 reset"这件事**在 API 上可见**。
        """
        adapter.reset()
