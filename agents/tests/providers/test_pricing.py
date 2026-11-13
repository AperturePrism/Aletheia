"""货币口径成本核算的测试（`04` §I12 DoD② 的口径落点）。

# 测试重点：三类"会让成本数字变小"的错误

成本模块的失败模式与别处不同 —— 它出错时通常**不会报错**，而是给出一个
看起来合理的偏小数字：

1. **缺单价当 0**：没报价的模型按 0 计 → 总额变小；
2. **推理 token 重复计价**：`reasoning_tokens` 是 `completion_tokens` 的
   子集，再算一次会让推理型模型成本**翻倍**（这一类是变大，同样失真）；
3. **混币种相加**：CNY 与 USD 直接加 → 数没有意义。

因此本文件大量用例在断言"这些情况下必须报错/必须不重复计"。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aletheia.providers.pricing import (
    ModelPrice,
    Pricing,
    PricingError,
    UnpricedModelError,
    currency_cost,
    load_pricing,
    reduction_ratio,
)
from aletheia.providers.provider import CostLedger, LedgerEntry, Usage

EXAMPLE = (
    Path(__file__).resolve().parents[2] / "src" / "aletheia" / "providers" / "pricing.example.json"
)


def _entry(
    model: str, *, prompt: int, completion: int, reasoning: int = 0, tier: str = "default"
) -> LedgerEntry:
    return LedgerEntry(
        ts=0.0,
        model=model,
        task_tier=tier,
        usage=Usage(
            prompt_tokens=prompt,
            completion_tokens=completion,
            reasoning_tokens=reasoning,
            total_tokens=prompt + completion,
        ),
        latency_ms=10,
    )


def _ledger(*entries: LedgerEntry) -> CostLedger:
    led = CostLedger()
    for e in entries:
        led.record(e)
    return led


def _pricing(**over) -> Pricing:
    base = Pricing(
        currency="CNY",
        source="https://example.test/pricing",
        version="2026-11",
        prices={
            "heavy": ModelPrice("heavy", 4.0, 16.0),
            "light": ModelPrice("light", 0.5, 2.0),
        },
    )
    return Pricing(
        currency=over.get("currency", base.currency),
        source=over.get("source", base.source),
        version=over.get("version", base.version),
        prices=over.get("prices", base.prices),
    )


# ---------------------------------------------------------------------------
# 基本正确性
# ---------------------------------------------------------------------------


def test_computes_prompt_and_completion_cost() -> None:
    # 1,000,000 prompt @4 + 1,000,000 completion @16 = 20 CNY
    led = _ledger(_entry("heavy", prompt=1_000_000, completion=1_000_000))
    bd = currency_cost(led, _pricing())
    assert bd.currency == "CNY"
    assert bd.total == pytest.approx(20.0)
    assert bd.by_model == {"heavy": pytest.approx(20.0)}


def test_by_tier_uses_real_tier() -> None:
    """按档位聚合必须反映真实档位（`task_tier` 传参修复后的行为）。"""
    led = _ledger(
        _entry("light", prompt=1_000_000, completion=0, tier="rank"),
        _entry("heavy", prompt=1_000_000, completion=0, tier="planning"),
    )
    bd = currency_cost(led, _pricing())
    assert bd.by_tier["rank"] == pytest.approx(0.5)
    assert bd.by_tier["planning"] == pytest.approx(4.0)


def test_reasoning_tokens_are_not_double_counted() -> None:
    """★ `reasoning_tokens` 已含在 `completion_tokens` 内，不得再算一次。

    若重复计价，推理型模型的成本会翻倍 —— 这会让"降本"看起来更好，
    属于必须避免的失真。
    """
    with_reasoning = currency_cost(
        _ledger(_entry("heavy", prompt=0, completion=1_000_000, reasoning=800_000)),
        _pricing(),
    )
    without = currency_cost(_ledger(_entry("heavy", prompt=0, completion=1_000_000)), _pricing())
    assert with_reasoning.total == pytest.approx(without.total)


def test_meta_records_pricing_provenance() -> None:
    """成本结论必须能追溯到"按哪份报价算的"。"""
    bd = currency_cost(_ledger(_entry("heavy", prompt=1, completion=1)), _pricing())
    meta = bd.as_meta()
    assert meta["pricing_source"] == "https://example.test/pricing"
    assert meta["pricing_version"] == "2026-11"
    assert meta["cost_currency"] == "CNY"


# ---------------------------------------------------------------------------
# ★ 缺单价必须报错，不得当 0
# ---------------------------------------------------------------------------


def test_unpriced_model_raises() -> None:
    led = _ledger(_entry("mystery-model", prompt=10, completion=10))
    with pytest.raises(UnpricedModelError) as exc:
        currency_cost(led, _pricing())
    msg = str(exc.value)
    assert "mystery-model" in msg
    assert "不得默认按 0 处理" in msg


def test_missing_models_lists_all_gaps() -> None:
    led = _ledger(
        _entry("heavy", prompt=1, completion=1),
        _entry("m1", prompt=1, completion=1),
        _entry("m2", prompt=1, completion=1),
    )
    assert _pricing().missing_models(led) == ["m1", "m2"]


def test_no_partial_costing() -> None:
    """★ 有任何一个模型缺价 → 整体失败，不产出"部分成本"。

    部分核算会给出偏小的总额，而报告里它看起来就是个完整的成本数字。
    """
    led = _ledger(
        _entry("heavy", prompt=1_000_000, completion=0),
        _entry("mystery", prompt=1_000_000, completion=0),
    )
    with pytest.raises(UnpricedModelError):
        currency_cost(led, _pricing())


# ---------------------------------------------------------------------------
# ★ 混币种不得相加
# ---------------------------------------------------------------------------


def test_reduction_ratio_rejects_currency_mismatch() -> None:
    cny = currency_cost(_ledger(_entry("heavy", prompt=1, completion=1)), _pricing())
    usd = currency_cost(_ledger(_entry("heavy", prompt=1, completion=1)), _pricing(currency="USD"))
    with pytest.raises(PricingError, match="币种不一致"):
        reduction_ratio(cny, usd)


def test_reduction_ratio_zero_baseline_rejected() -> None:
    empty = currency_cost(_ledger(), _pricing())
    other = currency_cost(_ledger(_entry("heavy", prompt=1, completion=1)), _pricing())
    with pytest.raises(PricingError, match="基线成本为 0"):
        reduction_ratio(empty, other)


def test_reduction_ratio_math() -> None:
    """heavy → light 的降本比例（按本文件的假单价）。"""
    baseline = currency_cost(
        _ledger(_entry("heavy", prompt=1_000_000, completion=1_000_000)), _pricing()
    )
    optimized = currency_cost(
        _ledger(_entry("light", prompt=1_000_000, completion=1_000_000)), _pricing()
    )
    # 基线 20，优化后 2.5 → 降 87.5%
    assert reduction_ratio(baseline, optimized) == pytest.approx(0.875)


# ---------------------------------------------------------------------------
# 价目表校验
# ---------------------------------------------------------------------------


def test_load_rejects_example_table() -> None:
    """★ 示例价目表不得用于真实核算（防"用编的单价算出漂亮数字"）。"""
    with pytest.raises(PricingError, match="示例"):
        load_pricing(EXAMPLE)


def test_example_table_is_parseable_otherwise(tmp_path: Path) -> None:
    """把 source 换成真出处后应能正常加载（证明示例结构是对的）。"""
    raw = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    raw["source"] = "https://example.test/real-pricing"
    p = tmp_path / "p.json"
    p.write_text(json.dumps(raw), encoding="utf-8")
    pricing = load_pricing(p)
    assert pricing.currency == "CNY"
    assert "glm-5.2" in pricing.prices


def test_load_rejects_missing_fields(tmp_path: Path) -> None:
    for key in ("currency", "source", "version", "prices"):
        raw = {
            "currency": "CNY",
            "source": "https://x",
            "version": "1",
            "prices": {"m": {"prompt_per_mtok": 1, "completion_per_mtok": 1}},
        }
        raw.pop(key)
        p = tmp_path / "p.json"
        p.write_text(json.dumps(raw), encoding="utf-8")
        with pytest.raises(PricingError, match=key):
            load_pricing(p)


def test_load_rejects_missing_price_field(tmp_path: Path) -> None:
    raw = {
        "currency": "CNY",
        "source": "https://x",
        "version": "1",
        "prices": {"m": {"prompt_per_mtok": 1}},
    }
    p = tmp_path / "p.json"
    p.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(PricingError, match="completion_per_mtok"):
        load_pricing(p)


def test_negative_price_rejected() -> None:
    with pytest.raises(PricingError, match="不得为负"):
        ModelPrice("m", -1.0, 1.0)


def test_missing_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(PricingError, match="不存在"):
        load_pricing(tmp_path / "nope.json")
