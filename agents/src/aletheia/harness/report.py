"""评测报告生成（modules/M9 §6，T9.11）。

# 报告结构（M9 §6，七节）

    1. 运行元信息    系统版本 / 模型 / temperature / 种子 / 靶场 / 覆盖度
    2. 主结果        仅 CONFIRMED：检出数 / 误报 / 漏报 / 精确率 / 召回率
    3. 新指标        幻觉率 / 可复现率 / 越界尝试数 / 召回率 / 成本 / 归因
    4. 成本          token 消耗 / 分级路由效果 / 单任务成本
    5. 失败案例分析 ★ 每类失败归类 + 根因 + 改进方向
    6. 能力边界声明   业务逻辑覆盖率（分有/无契约）/ 后渗透边界 / 未覆盖清单
    7. 附录          Candidate 级发现

# ★ 第 5 节的价值不低于第 2 节

M9 §6 原文：

> **第 5 节（失败案例分析）的价值不低于第 2 节。** 报告不得只报成功 ——
> 这既是诚实性要求，也是改进的主要输入。

因此 `Report` 数据类把 `failures` 设为**必填**（无默认值），
且生成器在失败列表为空时会显式说明"本次无失败记录"而不是省略该节 ——
省略会让读者分不清"没有失败"与"没写失败"。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aletheia.harness.metrics import Metric, RunInputs, all_metrics

# ---------------------------------------------------------------------------
# 失败案例（M9 §6 第 5 节）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FailureCase:
    """一个失败案例（**必须结构化归档，不可丢弃** —— M9 §8 测试要求）。"""

    #: 任务/目标标识。
    task_id: str
    #: 失败归类（如 CONTEXT_MISSING / TOOL_MISUSE / WRONG_HYPOTHESIS…）。
    category: str
    #: 根因分析。
    root_cause: str
    #: 改进方向。
    improvement: str = ""


# ---------------------------------------------------------------------------
# 能力边界声明（M9 §6 第 6 节 + §11 承诺 3）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Limitation:
    """一条能力边界声明（映射契约的 `Limitation`）。

    M9 §6 原文：能力边界必须声明在**报告正文**，而非附录脚注
    （§11 承诺 3："不隐藏"）。
    """

    category: str
    description: str
    affected_scope: str = ""


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------


@dataclass
class Report:
    """完整评测报告（M9 §6 的七节）。"""

    #: 1. 运行元信息。
    run_meta: dict[str, str] = field(default_factory=dict)
    #: 3. 新指标 + 标准指标。
    metrics: list[Metric] = field(default_factory=list)
    #: 4. 成本明细。
    cost: dict[str, str] = field(default_factory=dict)
    #: 5. 失败案例（★ 必填 —— 无默认值）。
    failures: list[FailureCase] = field(default_factory=list)
    #: 6. 能力边界声明（★ 必填 —— 无默认值）。
    limitations: list[Limitation] = field(default_factory=list)
    #: 7. 附录（Candidate 级）。
    candidates: list[str] = field(default_factory=list)
    #: 2. 主结果（仅 CONFIRMED）。
    confirmed_count: int = 0
    #: 分场景统计（§11 承诺 2："不混合"）—— 键是场景名（如
    #: `business_logic/with_contract`），值是该场景的检出数字。
    scenario_results: dict[str, str] = field(default_factory=dict)

    # -- 渲染 --------------------------------------------------------

    def render(self) -> str:
        """渲染为 Markdown 报告。"""
        parts: list[str] = ["# 评测报告", ""]

        parts.append("## 1. 运行元信息")
        if self.run_meta:
            for k in sorted(self.run_meta):
                parts.append(f"- {k}: {self.run_meta[k]}")
        else:
            parts.append("- （无元信息 —— 报告不可复现）")
        parts.append("")

        parts.append("## 2. 主结果（仅 CONFIRMED）")
        parts.append(f"- CONFIRMED 结论数: {self.confirmed_count}")
        if self.scenario_results:
            parts.append("- 分场景统计（不混合汇报，M9 §11 承诺 2）:")
            for k in sorted(self.scenario_results):
                parts.append(f"  - {k}: {self.scenario_results[k]}")
        parts.append("")

        parts.append("## 3. 指标")
        parts.append("")
        parts.append("| 指标 | 值 | 目标 | 样本 | 定义 |")
        parts.append("|---|---|---|---|---|")
        for m in self.metrics:
            value = "—（样本不足）" if m.value is None else f"{m.value:.4f}"
            sample = "充足" if m.sufficient_sample else "**不足**"
            parts.append(f"| {m.name} | {value} | {m.target} | {sample} | {m.definition} |")
        parts.append("")

        parts.append("## 4. 成本")
        if self.cost:
            for k in sorted(self.cost):
                parts.append(f"- {k}: {self.cost[k]}")
        else:
            parts.append("- （未提供成本数据）")
        parts.append("")

        parts.append("## 5. 失败案例分析 ★")
        if self.failures:
            parts.append("")
            parts.append("| 任务 | 归类 | 根因 | 改进方向 |")
            parts.append("|---|---|---|---|")
            for f in self.failures:
                parts.append(f"| {f.task_id} | {f.category} | {f.root_cause} | {f.improvement} |")
        else:
            # **显式说明**而不是省略该节 —— 省略会让读者分不清
            # "没有失败"与"没写失败"（M9 §2.2 N3 不选择性报告）。
            parts.append("- 本次运行无失败记录（该节不省略：省略会与「未记录」混淆）")
        parts.append("")

        parts.append("## 6. 能力边界声明")
        if self.limitations:
            for lim in self.limitations:
                scope = f"（影响范围：{lim.affected_scope}）" if lim.affected_scope else ""
                parts.append(f"- **{lim.category}**：{lim.description}{scope}")
        else:
            parts.append("- ⚠ 未声明任何能力边界 —— 这本身是一个失真信号")
        parts.append("")

        parts.append("## 7. 附录：Candidate 级发现")
        if self.candidates:
            for c in self.candidates:
                parts.append(f"- {c}")
        else:
            parts.append("- （无）")
        parts.append("")

        return "\n".join(parts)


#: 报告必须包含的章节标题（M9 §6 的七节）。
REQUIRED_SECTIONS: tuple[str, ...] = (
    "## 1. 运行元信息",
    "## 2. 主结果",
    "## 3. 指标",
    "## 4. 成本",
    "## 5. 失败案例分析",
    "## 6. 能力边界声明",
    "## 7. 附录",
)


def build_report(
    inputs: RunInputs,
    *,
    failures: list[FailureCase],
    limitations: list[Limitation],
    confirmed_count: int = 0,
    candidates: list[str] | None = None,
    scenario_results: dict[str, str] | None = None,
    extra_meta: dict[str, str] | None = None,
) -> Report:
    """从运行输入构造报告（T9.11）。

    `failures` 与 `limitations` 是**必填关键字参数**（无默认值）——
    这是 M9 §2.2 N3（不选择性报告）与 §11 承诺 3（不隐藏）在 API
    层面的强制：调用方**必须**显式提供它们，不能"忘了写"。

    `run_meta` 自动包含可复现性要求的字段（M9 §5.3）：
    种子与 temperature 若未提供则显式标注"未记录"——
    那本身是可复现性的缺陷，应当可见。
    """
    meta: dict[str, str] = {}
    meta["seed"] = str(inputs.seed) if inputs.seed is not None else "⚠ 未记录（可复现性缺陷）"
    meta["temperature"] = (
        str(inputs.temperature) if inputs.temperature is not None else "⚠ 未记录（可复现性缺陷）"
    )
    for k, v in sorted(inputs.versions.items()):
        meta[k] = v
    if extra_meta:
        meta.update(extra_meta)

    cost = {
        "total_tokens": str(inputs.total_tokens),
        "consumed_tokens": str(inputs.consumed_tokens),
        "total_cost": f"{inputs.total_cost:.4f}",
    }

    return Report(
        run_meta=meta,
        metrics=all_metrics(inputs),
        cost=cost,
        failures=list(failures),
        limitations=list(limitations),
        candidates=list(candidates or []),
        confirmed_count=confirmed_count,
        scenario_results=dict(scenario_results or {}),
    )


# ---------------------------------------------------------------------------
# 引用纪律（M9 §3 的四项标注）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BaselineClaim:
    """一条基线引用（M9 §3 的引用纪律）。"""

    metric: str
    value: str
    #: 来源（arXiv 号/仓库/独立评测）。
    source: str
    #: 条件（是否给定描述、白盒还是黑盒、是否有人类提示）。
    condition: str
    #: 时点。
    when: str
    #: 置信度：A 同行评审 / B 单一权威 / C 二手转述。
    confidence: str

    def is_well_formed(self) -> bool:
        """四项标注缺一不可（M9 §3 的引用纪律）。

        M9 §3 的反面案例原文：

        > "AI 渗透成功率达 87%" —— 缺失全部四项，实际含义是
        > "给定通告描述的理想条件下 GPT-4 对 one-day 漏洞的利用率"，
        > 去掉描述即降至 7%，真实条件下为 13%。
        """
        return all(s.strip() for s in (self.source, self.condition, self.when, self.confidence))

    def render(self) -> str:
        return (
            f"{self.metric}: {self.value} "
            f"（来源={self.source}；条件={self.condition}；"
            f"时点={self.when}；置信度={self.confidence}）"
        )


#: M9 §3 表格中本项目最常引用的几条基线（供报告对照）。
#:
#: 数值与条件**逐项抄自规格**，不做"四舍五入的简化"——
#: 简化掉条件正是 §3 反面案例的成因。
REFERENCE_BASELINES: tuple[BaselineClaim, ...] = (
    BaselineClaim(
        metric="one-day CVE 利用率（给定通告描述）",
        value="87%",
        source="Fang et al. 2024 · GPT-4",
        condition="有描述",
        when="2024",
        confidence="A",
    ),
    BaselineClaim(
        metric="one-day CVE 利用率（无描述）",
        value="7%",
        source="Fang et al. 2024 · GPT-4",
        condition="去掉描述（唯一变量）",
        when="2024",
        confidence="A",
    ),
    BaselineClaim(
        metric="真实条件 CVE 利用",
        value="13%",
        source="CVE-Bench（ICML 2025 Spotlight）",
        condition="40 个严重漏洞",
        when="2025",
        confidence="A",
    ),
    BaselineClaim(
        metric="链式漏洞成功率",
        value="~16%",
        source="Hackers or Hallucinators?",
        condition="真实条件",
        when="2025",
        confidence="A",
    ),
    BaselineClaim(
        metric="端到端（有 vs 无人类提示）",
        value="64% vs 21%",
        source="AutoPenBench",
        condition="有人类提示 vs 全自主",
        when="2025",
        confidence="A",
    ),
)
