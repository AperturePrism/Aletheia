"""harness —— 评测 Harness（modules/M9，迭代 I11）。

# 本模块的定位（M9 §1）

> **M9 是项目诚实性的技术保障 —— 所有对外数字必须由它产生。**

# 三条硬约束（M9 §2.2 + §11）

| 约束 | 落实方式 |
|---|---|
| **N2 不允许手工填数** | `RunInputs` 只接受**原始计数**，比率全部由 `metrics.py` 计算 |
| **N3 不选择性报告** | `build_report` 的 `failures` / `limitations` 是**必填关键字参数** |
| 不筛选 | `HarnessRun.aggregate()` **不提供**过滤参数 |
| 不混合 | `Report.scenario_results` 分场景统计（有/无契约等） |
| 不隐藏 | 能力边界声明在报告**正文**第 6 节，非附录脚注 |

# 为什么"指标本身是可交付物"（M9 §4）

行业空白 G1（可证明性）没有现成指标。规格原文：

> **这些指标本身是项目的可交付物之一。** 即使检出率不理想，只要能给出
> 这些行业此前无法量化的数字，就已经推进了领域。

因此本包提供 7 个自定义指标的**自动化计算**（幻觉率 / 证据可复现率 /
越界尝试数 / 实体召回率 / 每个 CONFIRMED 成本 / 假阴性率 / 归因准确率）。

# 本包的结构

* :mod:`metrics` —— 标准指标 + 7 个自定义指标（T9.9–T9.10）
* :mod:`report`  —— 七节报告生成 + 引用纪律（T9.11）
* :mod:`adapter` —— 基准适配器框架 + 可复现性清单（T9.1/T9.12）

# 关于具体基准适配器（T9.2–T9.8）

CyBench / CVE-Bench / XBOW / HTB 的适配器需要外部环境（CTFd、容器
编排、靶场 API），不在本包内实现 —— 本包提供**框架与契约**，
让适配器可插拔，并让指标计算与报告生成可**离线完整测试**。

这与 I8（M7 的融合逻辑与引擎适配器分离）是同一策略：
最需要保证正确性的部分是**判定与统计口径**，而那部分不该依赖
外部环境的可用性。
"""

from aletheia.harness.adapter import (
    BenchmarkAdapter,
    BenchmarkTask,
    HarnessRun,
    ReproducibilityManifest,
    TaskResult,
    score_task,
)
from aletheia.harness.driver import DryRunSystem, aggregate_with_scores, run_benchmark
from aletheia.harness.juiceshop import JuiceShopAdapter
from aletheia.harness.metrics import (
    NEW_METRIC_NAMES,
    Metric,
    RunInputs,
    all_metrics,
    attribution_accuracy,
    cost_per_confirmed,
    entity_recall,
    false_negative_rate,
    hallucination_rate,
    precision,
    recall,
    reproduction_rate,
    scope_violation_rate,
)
from aletheia.harness.report import (
    REFERENCE_BASELINES,
    REQUIRED_SECTIONS,
    BaselineClaim,
    FailureCase,
    Limitation,
    Report,
    build_report,
)

__all__ = [
    "NEW_METRIC_NAMES",
    "REFERENCE_BASELINES",
    "REQUIRED_SECTIONS",
    "BaselineClaim",
    "BenchmarkAdapter",
    "BenchmarkTask",
    "DryRunSystem",
    "FailureCase",
    "HarnessRun",
    "JuiceShopAdapter",
    "Limitation",
    "Metric",
    "Report",
    "ReproducibilityManifest",
    "RunInputs",
    "TaskResult",
    "aggregate_with_scores",
    "all_metrics",
    "attribution_accuracy",
    "build_report",
    "cost_per_confirmed",
    "entity_recall",
    "false_negative_rate",
    "hallucination_rate",
    "precision",
    "recall",
    "reproduction_rate",
    "run_benchmark",
    "scope_violation_rate",
    "score_task",
]
