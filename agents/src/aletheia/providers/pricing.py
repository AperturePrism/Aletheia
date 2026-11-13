"""货币口径的成本核算（`docs/04` §I12 DoD② 的口径落点）。

# 为什么需要这个模块

`04` §I12 DoD② 的原文是「成本较单一前沿模型方案降 ≥ 60%」，但**没写明
口径**。而 token 口径与货币口径的结论相反：

* **token 口径**：实测最佳 **32.72%**，且已证明结构性不可达
  （推理 token 占基线 89%；思考档占权重 27% 且推理保留是质量要求）；
* **货币口径**：token 降 33% + 轻档单价通常低 5–10 倍 → 大概率 ≥60%，
  但**需要渠道计费单价**才能算。

本模块把"货币口径"从一句推测变成**可计算、可复跑**的东西：
给定一张价目表，从 `CostLedger` 算出真实货币成本。

# 三条硬约束（都体现"不得虚报"）

1. **缺单价必须报错**（`UnpricedModelError`），不得**默认 0** ——
   把未知单价当 0 会让成本凭空变小，是最隐蔽的一类数字造假。
2. **价目表必须带来源与版本**（`source` / `version`）——
   没有出处的单价无法复核，而无法复核的降本结论等于没有结论。
3. **币种必须显式**（`currency`）—— 混币种相加得到的数没有意义。

# 计价口径

按业界通行做法分两类：

    prompt tokens      × prompt_per_mtok
    completion tokens  × completion_per_mtok

`reasoning_tokens` 是 `completion_tokens` 的**子集**（OpenAI 兼容协议里
它来自 `completion_tokens_details.reasoning_tokens`），因此**不重复计价** ——
否则推理型模型的成本会被算成两倍。这一点在测试里有专门断言。

单位是「每百万 token」（`per_mtok`），与渠道报价单一致。
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from aletheia.providers.provider import CostLedger, LedgerEntry


class PricingError(ValueError):
    """价目表不合法。"""


class UnpricedModelError(PricingError):
    """账本里出现了价目表未覆盖的模型。

    单独成一个类型，是为了让调用方能明确区分"价目表坏了"与
    "有一个模型没报价"—— 前者是配置错误，后者通常只是漏填一行。
    """


@dataclass(frozen=True)
class ModelPrice:
    """一个模型的单价（每百万 token）。"""

    model: str
    prompt_per_mtok: float
    completion_per_mtok: float
    #: 备注（例如"官网 2026-10 报价"），便于复核。
    note: str = ""

    def __post_init__(self) -> None:
        if self.prompt_per_mtok < 0 or self.completion_per_mtok < 0:
            raise PricingError(
                f"{self.model}: 单价不得为负（prompt={self.prompt_per_mtok}, "
                f"completion={self.completion_per_mtok}）"
            )


@dataclass(frozen=True)
class Pricing:
    """一张价目表。

    `source` 与 `version` 不是装饰：`M9` §2 的可复现性清单要求
    成本结论能追溯到"按哪份报价、什么时候的价"。
    """

    currency: str
    source: str
    version: str
    prices: dict[str, ModelPrice] = field(default_factory=dict)

    def price_for(self, model: str) -> ModelPrice:
        try:
            return self.prices[model]
        except KeyError as exc:
            raise UnpricedModelError(
                f"模型 {model!r} 没有单价。价目表（{self.source}@{self.version}）"
                f"只覆盖：{sorted(self.prices)}。\n"
                "  ★ 不得默认按 0 处理 —— 那会让成本凭空变小。"
            ) from exc

    def missing_models(self, ledger: CostLedger) -> list[str]:
        """账本里出现但价目表没报价的模型（去重排序）。"""
        seen = {e.model for e in ledger.entries}
        return sorted(seen - set(self.prices))


@dataclass(frozen=True)
class CostBreakdown:
    """一次货币口径核算的结果。"""

    currency: str
    total: float
    by_model: dict[str, float]
    by_tier: dict[str, float]
    #: 实际使用的价目表版本（可复现性所需）。
    pricing_source: str
    pricing_version: str
    #: 参与核算的调用数（与 `CostLedger.entries` 数量一致）。
    calls: int

    def as_meta(self) -> dict[str, str]:
        """写进报告元信息的扁平字典。"""
        return {
            "cost_currency": self.currency,
            "cost_total": f"{self.total:.6f}",
            "pricing_source": self.pricing_source,
            "pricing_version": self.pricing_version,
            "costed_calls": str(self.calls),
        }


def load_pricing(path: Path) -> Pricing:
    """从 JSON 加载价目表（严格校验，fail-closed）。

    期望格式见 `agents/src/aletheia/providers/pricing.example.json`。
    """
    if not path.exists():
        raise PricingError(f"价目表不存在：{path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PricingError(f"{path} 不是合法 JSON：{exc}") from exc
    if not isinstance(raw, dict):
        raise PricingError(f"{path} 顶层必须是对象")

    for key in ("currency", "source", "version", "prices"):
        if key not in raw:
            raise PricingError(f"{path} 缺少必需字段 {key!r}")

    prices_raw = raw["prices"]
    if not isinstance(prices_raw, dict) or not prices_raw:
        raise PricingError(f"{path} 的 prices 必须是非空对象")

    source = str(raw["source"]).strip()
    # ★ 示例价目表不得用于真实核算。
    #
    # 这一条防的是一类很隐蔽的失误：有人懒得填真实报价，直接用
    # `pricing.example.json` 跑出"降本 62%"—— 那个数字看起来完全正常，
    # 但底下是编的单价。fail-closed 在这里比"友好的默认值"更有价值。
    if source.upper().startswith("EXAMPLE"):
        raise PricingError(
            f"{path} 是**示例**价目表（source={source!r}），不得用于真实核算。\n"
            "  请填入渠道报价页/账单导出的真实单价，并把 source 换成可复核的出处。"
        )

    prices: dict[str, ModelPrice] = {}
    for model, v in prices_raw.items():
        if not isinstance(v, dict):
            raise PricingError(f"{path}: prices[{model!r}] 必须是对象")
        for key in ("prompt_per_mtok", "completion_per_mtok"):
            if key not in v:
                raise PricingError(f"{path}: prices[{model!r}] 缺少 {key!r}")
            if not isinstance(v[key], (int, float)) or isinstance(v[key], bool):
                raise PricingError(f"{path}: prices[{model!r}].{key} 必须是数字")
        prices[model] = ModelPrice(
            model=model,
            prompt_per_mtok=float(v["prompt_per_mtok"]),
            completion_per_mtok=float(v["completion_per_mtok"]),
            note=str(v.get("note", "")),
        )

    return Pricing(
        currency=str(raw["currency"]).strip(),
        source=source,
        version=str(raw["version"]).strip(),
        prices=prices,
    )


def _cost_of(entry: LedgerEntry, price: ModelPrice) -> float:
    """单条账目条目的货币成本。

    `reasoning_tokens` **不计价**：它是 `completion_tokens` 的子集，
    重复计价会让推理型模型的成本翻倍（见模块文档）。
    """
    return (
        entry.usage.prompt_tokens * price.prompt_per_mtok
        + entry.usage.completion_tokens * price.completion_per_mtok
    ) / 1_000_000.0


def currency_cost(ledger: CostLedger, pricing: Pricing) -> CostBreakdown:
    """按价目表算货币成本。

    缺任何模型的单价 → 抛 `UnpricedModelError`（**不做部分核算**）。

    为什么不做部分核算：只算"有报价的那部分"会给出一个偏小的总额，
    而报告里它看起来就是一个完整的成本数字 —— 那正是本模块要防的事。
    """
    missing = pricing.missing_models(ledger)
    if missing:
        raise UnpricedModelError(
            f"以下模型缺单价，无法核算货币成本：{missing}\n"
            f"  价目表：{pricing.source}@{pricing.version}\n"
            "  ★ 不得默认按 0 处理 —— 那会让成本凭空变小；"
            "也不做部分核算（部分核算的总额会偏小，却看起来像个完整数字）。"
        )

    by_model: dict[str, float] = {}
    by_tier: dict[str, float] = {}
    total = 0.0
    for e in ledger.entries:
        c = _cost_of(e, pricing.price_for(e.model))
        total += c
        by_model[e.model] = by_model.get(e.model, 0.0) + c
        by_tier[e.task_tier] = by_tier.get(e.task_tier, 0.0) + c

    return CostBreakdown(
        currency=pricing.currency,
        total=total,
        by_model=dict(sorted(by_model.items())),
        by_tier=dict(sorted(by_tier.items())),
        pricing_source=pricing.source,
        pricing_version=pricing.version,
        calls=len(ledger.entries),
    )


def reduction_ratio(baseline: CostBreakdown, optimized: CostBreakdown) -> float:
    """相对基线的降幅（0.6 = 降 60%）。

    两个 breakdown 的币种必须一致 —— 否则算出的比例没有意义。
    """
    if baseline.currency != optimized.currency:
        raise PricingError(f"币种不一致，无法比较：{baseline.currency} vs {optimized.currency}")
    if baseline.total <= 0:
        raise PricingError("基线成本为 0，无法计算降幅（价目表可能未填或账本为空）")
    return 1.0 - (optimized.total / baseline.total)


def cost_entries(entries: Iterable[LedgerEntry], pricing: Pricing) -> float:
    """便捷函数：直接对一组账目条目算总成本（不构造 CostLedger）。"""
    total = 0.0
    for e in entries:
        total += _cost_of(e, pricing.price_for(e.model))
    return total
