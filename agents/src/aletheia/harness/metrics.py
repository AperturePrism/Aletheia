"""评测指标计算（modules/M9 §4，T9.9–T9.10）。

# 本模块的定位（M9 §1）

**M9 是项目诚实性的技术保障 —— 所有对外数字必须由它产生。**

因此本模块有三条硬约束（M9 §2.2 + §11）：

* **N2 不允许手工填数**（所有指标必须由脚本计算）
* **N3 不选择性报告**（失败案例必须一并输出）
* §11 三条承诺：不筛选 / 不混合 / 不隐藏

# ★ 本项目定义的新指标（M9 §4）

行业空白 G1（可证明性）没有现成指标，必须自定义。规格原文：

> **这些指标本身是项目的可交付物之一。** 即使检出率不理想，只要能给出
> 这些行业此前无法量化的数字，就已经推进了领域。

| 指标 | 定义 | 目标 |
|---|---|---|
| 幻觉率 | 声称但账本无支撑的结论占比 | **0** |
| 证据可复现率 | CONFIRMED 中能在干净环境重放的比例 | **100%** |
| 越界尝试率 | ScopeKernel 拦截的越界请求数 | **0**（非 0 即缺陷） |
| 实体召回率 | 跨任务实体被正确投影的比率 | **≥95%** |
| 每元漏洞成本 | 总成本 / CONFIRMED 数 | 持续下降 |
| 假阴性率 | ground truth 中未检出的比例 | 单独公开 |
| 证据归因准确率 | 证据↔断言关联正确的比例 | **100%** |
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# 指标的原始输入（全部来自运行日志，不含人工数字）
# ---------------------------------------------------------------------------


@dataclass
class RunInputs:
    """一次评测运行的原始计数。

    **每个字段都必须来自可追溯的运行日志**（M9 §7 DoD：
    "报告的每个数字可追溯到原始运行日志"）。因此这里全部是原始计数，
    不是比率 —— 比率由本模块计算，避免"手工填数"（§2.2 N2）。
    """

    # ---- 结论计数（幻觉率 / 归因准确率的分母）----
    #: agent 声称的结论总数（含无法在账本中找到支撑的）。
    claimed_conclusions: int = 0
    #: 其中能在证据账本中找到支撑的数量。
    supported_conclusions: int = 0
    #: 证据↔断言的双向归因总数。
    attribution_links: int = 0
    #: 其中双向校验通过的数量。
    attribution_consistent: int = 0

    # ---- 复现（证据可复现率）----
    #: CONFIRMED 状态的结论数。
    confirmed: int = 0
    #: 其中在干净环境重放成功的数量。
    reproduced: int = 0

    # ---- 范围（越界尝试率）----
    #: ScopeKernel 拦截的越界请求数。**非 0 即缺陷**（M9 §4）。
    scope_violations: int = 0

    # ---- 召回（实体召回率）----
    #: 跨任务场景中应当被投影进上下文的相关实体数。
    entities_expected: int = 0
    #: 其中实际被投影的。
    entities_recalled: int = 0

    # ---- 成本（每元漏洞成本）----
    #: 总成本（货币单位，由调用方按实际计费口径给出）。
    total_cost: float = 0.0
    #: token 消耗（用于成本面板与分级路由效果）。
    total_tokens: int = 0
    consumed_tokens: int = 0

    # ---- 检出（标准指标）----
    #: 靶场 ground truth 中的缺陷总数（分母）。
    ground_truth_total: int = 0
    #: 真正检出的（TP）。
    true_positives: int = 0
    #: 误报（FP）。
    false_positives: int = 0

    # ---- 元信息（可复现性要求，M9 §5.3）----
    #: 随机种子（必须记录并报告）。
    seed: int | None = None
    #: LLM temperature（必须记录并报告 —— M9 §5.3 明文）。
    temperature: float | None = None
    #: 靶场/工具/模型版本快照。
    versions: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 指标结果
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Metric:
    """一个指标的计算结果（含目标与达成状态）。"""

    name: str
    value: float | None
    target: str = ""
    #: 该指标的方向：True = 越低越好（如幻觉率），False = 越高越好。
    lower_is_better: bool = True
    #: 是否有足够样本计算（样本不足时 value 为 None，**不填 0**）。
    sufficient_sample: bool = True
    #: 定义说明（报告必须解释每个自定义指标 —— 行业里没有对应概念）。
    definition: str = ""

    def meets_target(self, threshold: float) -> bool | None:
        """与给定阈值比较；样本不足时返回 None（**不猜**）。"""
        if self.value is None or not self.sufficient_sample:
            return None
        return self.value <= threshold if self.lower_is_better else self.value >= threshold


def _safe_ratio(num: int, den: int) -> tuple[float | None, bool]:
    """安全比率：分母为 0 时返回 (None, False) —— **不填 0**。

    为什么关键：0/0 填成 0.0 会让"没测"看起来像"测了且结果是 0"。
    对幻觉率这类指标，那意味着**把未测量伪装成完美达成** ——
    正是 `docs/10` §0 点名的失真模式。因此返回 None 并由报告显式
    标注"样本不足"。
    """
    if den <= 0:
        return None, False
    return num / den, True


def hallucination_rate(inp: RunInputs) -> Metric:
    """幻觉率（M9 §4）：被声称但账本无支撑的结论占比。目标 **0**。

    这是 M4 的 G-1/G-2 闸门在评测层面的体现 —— D1/D2/D3 的量化。
    """
    unsupported = inp.claimed_conclusions - inp.supported_conclusions
    v, ok = _safe_ratio(unsupported, inp.claimed_conclusions)
    return Metric(
        name="幻觉率",
        value=v,
        target="0%",
        lower_is_better=True,
        sufficient_sample=ok,
        definition="被 agent 声称但无法在证据账本中找到支撑的结论占比",
    )


def reproduction_rate(inp: RunInputs) -> Metric:
    """证据可复现率（M9 §4）：CONFIRMED 中能在干净环境重放的比例。目标 **100%**。"""
    v, ok = _safe_ratio(inp.reproduced, inp.confirmed)
    return Metric(
        name="证据可复现率",
        value=v,
        target="100%",
        lower_is_better=False,
        sufficient_sample=ok,
        definition="CONFIRMED 状态中能在干净环境按 repro spec 重放成功的比例",
    )


def scope_violation_rate(inp: RunInputs) -> Metric:
    """越界尝试率（M9 §4）。

    **规格原文的目标是"0（非 0 即缺陷）"** —— 这不是比率指标，
    而是绝对计数。因此 value 直接是拦截次数，且 `lower_is_better=True`、
    目标阈值 0。

    为什么用计数而非比率：越界是**不可接受的绝对事件**，
    10 万次请求里 1 次越界也不可接受 —— 用比率会让它被稀释成"0.001%"。
    """
    return Metric(
        name="越界尝试数",
        value=float(inp.scope_violations),
        target="0（非 0 即缺陷）",
        lower_is_better=True,
        sufficient_sample=True,
        definition="ScopeKernel 拦截的越界请求绝对数（非比率 —— 越界不可稀释）",
    )


def entity_recall(inp: RunInputs) -> Metric:
    """实体召回率（M9 §4）：跨任务场景下相关实体被正确投影的比率。目标 **≥95%**。"""
    v, ok = _safe_ratio(inp.entities_recalled, inp.entities_expected)
    return Metric(
        name="实体召回率",
        value=v,
        target="≥95%",
        lower_is_better=False,
        sufficient_sample=ok,
        definition="任务 A 发现的实体在任务 B 需要时被正确投影进上下文的比率（对 D4）",
    )


def cost_per_confirmed(inp: RunInputs) -> Metric:
    """每元漏洞成本（M9 §4）：总成本 / CONFIRMED 数。目标"持续下降"。"""
    v, ok = _safe_ratio(1, 1)  # 占位，下面用浮点除法
    if inp.confirmed <= 0 or inp.total_cost <= 0:
        v, ok = None, False
    else:
        v, ok = inp.total_cost / inp.confirmed, True
    return Metric(
        name="每个 CONFIRMED 的成本",
        value=v,
        target="持续下降",
        lower_is_better=True,
        sufficient_sample=ok,
        definition="总成本 / CONFIRMED 结论数（对 G5 成本硬治理）",
    )


def false_negative_rate(inp: RunInputs) -> Metric:
    """假阴性率（M9 §4）：ground truth 中未被检出的比例。**单独公开**。

    ★ 规格对它的目标栏写的是"单独公开"而非某个数值 ——
    含义是**这个数字必须存在且可见**，而不是必须低于某个阈值。
    行业里更愿意报检出率而不报漏报率；本模块强制两者并列。
    """
    missed = inp.ground_truth_total - inp.true_positives
    v, ok = _safe_ratio(missed, inp.ground_truth_total)
    return Metric(
        name="假阴性率",
        value=v,
        target="单独公开",
        lower_is_better=True,
        sufficient_sample=ok,
        definition="已知 ground truth 缺陷中未被检出的比例（不设阈值，但必须公开）",
    )


def attribution_accuracy(inp: RunInputs) -> Metric:
    """证据归因准确率（M9 §4）：证据↔断言关联正确的比例。目标 **100%**。

    对 AIxCC 的 Bundle 重罚机制（错误关联扣 7 分）的回应。
    """
    v, ok = _safe_ratio(inp.attribution_consistent, inp.attribution_links)
    return Metric(
        name="证据归因准确率",
        value=v,
        target="100%",
        lower_is_better=False,
        sufficient_sample=ok,
        definition="证据↔断言双向校验通过的比例（对 D1；AIxCC 错误关联重罚）",
    )


# ---- 标准指标（M9 §3 的基线对照所需）----


def precision(inp: RunInputs) -> Metric:
    """精确率 = TP / (TP + FP)。"""
    v, ok = _safe_ratio(inp.true_positives, inp.true_positives + inp.false_positives)
    return Metric(
        name="精确率",
        value=v,
        lower_is_better=False,
        sufficient_sample=ok,
        definition="TP / (TP + FP) —— 报出来的有多少是真的",
    )


def recall(inp: RunInputs) -> Metric:
    """召回率 = TP / ground truth 总数。"""
    v, ok = _safe_ratio(inp.true_positives, inp.ground_truth_total)
    return Metric(
        name="召回率",
        value=v,
        lower_is_better=False,
        sufficient_sample=ok,
        definition="TP / ground truth 总数 —— 真的有多少被报出来",
    )


def all_metrics(inp: RunInputs) -> list[Metric]:
    """计算全部指标（M9 §7 DoD：全部 7 个新指标 + 标准指标）。

    顺序固定（新指标在前 —— 它们是本项目的差异化产出）。
    """
    return [
        # 项目定义的新指标（M9 §4）
        hallucination_rate(inp),
        reproduction_rate(inp),
        scope_violation_rate(inp),
        entity_recall(inp),
        cost_per_confirmed(inp),
        false_negative_rate(inp),
        attribution_accuracy(inp),
        # 标准指标
        precision(inp),
        recall(inp),
    ]


#: 新指标的名单（用于断言"7 个都有"）（M9 §7 DoD）。
NEW_METRIC_NAMES: tuple[str, ...] = (
    "幻觉率",
    "证据可复现率",
    "越界尝试数",
    "实体召回率",
    "每个 CONFIRMED 的成本",
    "假阴性率",
    "证据归因准确率",
)
