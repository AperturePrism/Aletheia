"""fusion —— 三路融合（modules/M7，迭代 I8）。

**冲突不是需要消除的噪声，而是最高价值的信号。**

调研 39+ 个开源项目后的结论（M7 §2）：没有任何项目统一了黑盒 / 白盒 /
二进制三路观测。这是 Aletheia 的第二个"第一"。

# 本包的结构

* :mod:`observers` —— 观测器统一接口 + `SourceKind` 语义映射（T7.1）
* :mod:`matrix`    —— 冲突检测 + 四象限矩阵（T7.9–T7.10）
* :mod:`coverage`  —— 覆盖度声明 + 融合编排（T7.3、§9）
* :mod:`derive`    —— 冲突驱动的下游任务派生（T7.11）

# 关于"观测器实现"（T7.2–T7.8）的交付边界

M7 §3.2 **N4 明确"不重实现 SAST 引擎"**，应复用 Semgrep / CodeQL /
tree-sitter / Ghidra。因此本包定义**统一接口**（:class:`Observer`），
具体引擎的适配器是可插拔实现，**不在本包内**。

这个边界让融合逻辑（矩阵、象限、派生）可以在**没有任何 SAST 工具**
的环境下被完整测试 —— 而那正是最需要保证正确性的部分：
四象限的解读规则错了，接再多引擎也没用。

引擎适配器的落地需要对应工具链（`semgrep` / `radare2` / `ghidra`），
属环境依赖项，已在 I8 交接文档中登记。
"""

from aletheia.fusion.coverage import (
    CoverageEntry,
    CoverageReport,
    CoverageStatus,
    Fusion,
    FusionResult,
)
from aletheia.fusion.derive import DerivedTask, derive_tasks
from aletheia.fusion.matrix import (
    MAX_CONFLICTS,
    MIN_CONFLICT_CONFIDENCE,
    QUADRANT_META,
    Conflict,
    ConflictMatrix,
    Quadrant,
    build_matrix,
    classify,
)
from aletheia.fusion.observers import (
    BINARY,
    BLACKBOX,
    TRICHROMATIC,
    WHITEBOX,
    Observation,
    Observer,
    StaticObserver,
    source_label,
)

__all__ = [
    "BINARY",
    "BLACKBOX",
    "MAX_CONFLICTS",
    "MIN_CONFLICT_CONFIDENCE",
    "QUADRANT_META",
    "TRICHROMATIC",
    "WHITEBOX",
    "Conflict",
    "ConflictMatrix",
    "CoverageEntry",
    "CoverageReport",
    "CoverageStatus",
    "DerivedTask",
    "Fusion",
    "FusionResult",
    "Observation",
    "Observer",
    "Quadrant",
    "StaticObserver",
    "build_matrix",
    "classify",
    "derive_tasks",
    "source_label",
]
