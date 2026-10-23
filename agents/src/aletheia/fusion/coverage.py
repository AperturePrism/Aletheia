"""观测覆盖度声明与融合编排（modules/M7 §9、§3.1 R3–R6）。

# 观测覆盖度声明（M7 §9）

**"声明覆盖度是诚实的必要条件。"**

规格原文：三路观测不是总能齐全，报告必须显式声明本次运行的观测覆盖度。
理由：**30% 的目标永远拿不到源码**，把"用了三路"当作默认假设会产生
过度自信（D13 —— 把产出量当价值）。

因此本模块的融合结果**总是**带一份覆盖度声明，且声明是结构化的
（不是给 LLM 生成一段文字）—— 结构化才能被下游任务消费与断言。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aletheia.fusion.matrix import ConflictMatrix, build_matrix
from aletheia.fusion.observers import (
    BINARY,
    BLACKBOX,
    TRICHROMATIC,
    WHITEBOX,
    Observation,
    Observer,
    source_label,
)

# ---------------------------------------------------------------------------
# 覆盖度
# ---------------------------------------------------------------------------


class CoverageStatus:
    """单路的覆盖状态（M7 §9 的 ✅/⚠️/❌ 三级）。"""

    #: 完整覆盖（如黑盒完整跑了、白盒覆盖了全部组件）。
    COMPLETE = "COMPLETE"
    #: 部分覆盖（如白盒只覆盖了部分组件、二进制只看了一部分可执行文件）。
    PARTIAL = "PARTIAL"
    #: 该路完全不可用（如目标无源码 → 白盒失明）。
    UNAVAILABLE = "UNAVAILABLE"


_COVERAGE_ICON = {
    CoverageStatus.COMPLETE: "✅",
    CoverageStatus.PARTIAL: "⚠️",
    CoverageStatus.UNAVAILABLE: "❌",
}


@dataclass(frozen=True)
class CoverageEntry:
    """一路的覆盖情况。"""

    source: int
    status: str
    #: 人类可读说明（M7 §9 的"覆盖 3 个组件，1 个组件仅二进制"这类）。
    detail: str = ""
    #: 该路产出的观测数量。
    observation_count: int = 0

    def render(self) -> str:
        """渲染为 M7 §9 所示的一行。"""
        icon = _COVERAGE_ICON.get(self.status, "?")
        suffix = f" —— {self.detail}" if self.detail else ""
        return f"  {icon} {source_label(self.source)}{suffix}"


@dataclass
class CoverageReport:
    """本次运行的观测覆盖度声明（M7 §9）。"""

    entries: list[CoverageEntry] = field(default_factory=list)

    @property
    def active_paths(self) -> int:
        """有产出的观测路数（1–3）。"""
        return sum(1 for e in self.entries if e.status != CoverageStatus.UNAVAILABLE)

    @property
    def is_trichromatic(self) -> bool:
        """三路是否全部可用。

        **刻意暴露这个属性**：调用方（报告生成器）需要据此决定是否
        声明"本次为三路观测"。若直接假设总是三路，就是 D13。
        """
        return self.active_paths == len(TRICHROMATIC)

    def render(self) -> str:
        """渲染为报告片段（M7 §9 的形态）。"""
        lines = ["观测覆盖度："]
        lines.extend(e.render() for e in self.entries)
        if not self.is_trichromatic:
            lines.append(
                f"  ⚠️ 本次仅 {self.active_paths}/3 路可用 —— "
                "结论的观测基础有限，不要把未覆盖维度当作已验证"
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 融合编排
# ---------------------------------------------------------------------------


@dataclass
class FusionResult:
    """一次三路融合的完整产出（M7 §3.1 R3–R6）。"""

    target: str
    matrix: ConflictMatrix
    coverage: CoverageReport
    #: 全部观测（写入 M2 的原料；M7 §3.1 R3）。
    observations: list[Observation] = field(default_factory=list)
    #: 融合过程中的告警（如某路观测器抛错）。
    warnings: list[str] = field(default_factory=list)


class Fusion:
    """三路融合编排器（M7 §3.1）。

    依赖注入三路观测器；**任一缺失或失败不阻断其余路**
    （M7 §8："三路不是必须全有：单路可用时降级为单路模式，
    报告中标注观测覆盖度"）。

    这个"不阻断"是刻意的：白盒失明（目标无源码）是**常态**
    （规格说 30% 的目标拿不到源码），若白盒不可用就整体失败，
    这个模块在最需要它的场景下反而不可用。
    """

    def __init__(
        self,
        *,
        blackbox: Observer | None = None,
        whitebox: Observer | None = None,
        binary: Observer | None = None,
        min_confidence: float = 0.5,
        max_conflicts: int = 200,
    ) -> None:
        self._observers: dict[int, Observer] = {}
        if blackbox is not None:
            self._observers[BLACKBOX] = blackbox
        if whitebox is not None:
            self._observers[WHITEBOX] = whitebox
        if binary is not None:
            self._observers[BINARY] = binary
        self._min_confidence = min_confidence
        self._max_conflicts = max_conflicts

    # -- 主入口 --------------------------------------------------------

    def fuse(self, target: str) -> FusionResult:
        """对目标执行三路观测并融合（M7 §3.1 R3–R6）。

        每路独立执行：一路抛错只记 warning，不影响其余路与融合结果。
        """
        observations: list[Observation] = []
        warnings: list[str] = []
        entries: list[CoverageEntry] = []

        for source in TRICHROMATIC:
            obs = self._observers.get(source)
            if obs is None:
                entries.append(
                    CoverageEntry(
                        source=source,
                        status=CoverageStatus.UNAVAILABLE,
                        detail="未配置该路观测器",
                        observation_count=0,
                    )
                )
                continue
            try:
                produced = list(obs.observe(target))
            except Exception as exc:  # noqa: BLE001 —— 一路失败不阻断其余路
                # 刻意捕获宽泛异常：观测器是外部引擎适配（Semgrep /
                # Ghidra 等），它们的失败模式不可穷举。**不吞**：
                # 记入 warnings 并降级覆盖度为 UNAVAILABLE（不是静默）。
                warnings.append(f"{source_label(source)} 观测失败：{exc!r}")
                entries.append(
                    CoverageEntry(
                        source=source,
                        status=CoverageStatus.UNAVAILABLE,
                        detail=f"执行失败：{exc!r}",
                        observation_count=0,
                    )
                )
                continue

            observations.extend(produced)
            entries.append(
                CoverageEntry(
                    source=source,
                    status=(CoverageStatus.COMPLETE if produced else CoverageStatus.PARTIAL),
                    detail=f"产出 {len(produced)} 条观测" if produced else "无发现",
                    observation_count=len(produced),
                )
            )

        matrix = build_matrix(
            target,
            observations,
            min_confidence=self._min_confidence,
            max_conflicts=self._max_conflicts,
        )
        return FusionResult(
            target=target,
            matrix=matrix,
            coverage=CoverageReport(entries=entries),
            observations=observations,
            warnings=warnings,
        )
