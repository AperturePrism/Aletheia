"""Provider 层测试。

分层策略（09 §6 #4：mock 只用于外部边界）：
    · 协议解析/账本/路由：mock urlopen（外部 HTTP 边界，允许）。
    · 真实渠道冒烟：标 llm_live，默认跳过（ALETHEIA_LLM_KEY 存在时才跑）
      —— CI 不烧真钱。
"""

from __future__ import annotations

import io
import json
import os
import urllib.error
from unittest import mock

import pytest

from aletheia.providers.provider import (
    CostLedger,
    OpenAICompatProvider,
    ProviderError,
    Router,
)


def _fake_response(content: str, usage: dict | None = None) -> io.BytesIO:
    payload = {
        "choices": [
            {"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}
        ],
        "usage": usage or {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }
    return io.BytesIO(json.dumps(payload).encode())


def make_provider(ledger=None) -> OpenAICompatProvider:
    return OpenAICompatProvider("https://example.invalid/v1", "sk-test", ledger=ledger)


class TestProtocolParsing:
    def test_content_and_usage_extracted(self):
        p = make_provider()
        with mock.patch("urllib.request.urlopen") as up:
            up.return_value = _fake_response(
                "OK",
                {
                    "prompt_tokens": 14,
                    "completion_tokens": 72,
                    "total_tokens": 86,
                    "completion_tokens_details": {"reasoning_tokens": 70},
                },
            )
            r = p.chat("hi", model="m", max_tokens=100)
        assert r.content == "OK"
        assert r.usage.reasoning_tokens == 70
        assert r.usage.total_tokens == 86

    def test_empty_content_is_explicit_failure(self):
        p = make_provider()
        with mock.patch("urllib.request.urlopen") as up:
            up.return_value = _fake_response("")
            with pytest.raises(ProviderError, match="empty content"):
                p.chat("hi", model="m", max_tokens=100)

    def test_http_error_raises_provider_error(self):
        p = make_provider()
        with mock.patch("urllib.request.urlopen") as up:
            up.side_effect = urllib.error.HTTPError("url", 429, "rate", {}, None)  # type: ignore[arg-type]
            with pytest.raises(ProviderError, match="chat failed"):
                p.chat("hi", model="m", max_tokens=100)


class TestCostLedger:
    def test_records_and_aggregates(self):
        led = CostLedger()
        p = make_provider(ledger=led)
        with mock.patch("urllib.request.urlopen") as up:
            up.return_value = _fake_response("x", {"total_tokens": 100})
            p.chat("a", model="glm-5.2", max_tokens=10)
        with mock.patch("urllib.request.urlopen") as up:
            up.return_value = _fake_response("y", {"total_tokens": 10})
            p.chat("b", model="lite", max_tokens=10)
        assert led.total_tokens() == 110
        assert led.by_model() == {"glm-5.2": 100, "lite": 10}
        assert len(led.entries) == 2


class TestPrivacyGatewayHook:
    def test_scan_called_before_send(self):
        p = make_provider()
        seen = []

        def scan(text: str) -> None:
            seen.append(text)

        with mock.patch("urllib.request.urlopen") as up:
            up.return_value = _fake_response("ok")
            p.chat("secret target", model="m", max_tokens=10, scan=scan)
        assert seen == ["secret target"]

    def test_scan_block_prevents_send(self):
        p = make_provider()

        def scan(text: str) -> None:
            raise RuntimeError("PRIVACY_LEAK_DETECTED")

        with mock.patch("urllib.request.urlopen") as up:
            with pytest.raises(RuntimeError, match="PRIVACY_LEAK"):
                p.chat("leak", model="m", max_tokens=10, scan=scan)
            up.assert_not_called()


class TestRouter:
    def test_tier_routing_deterministic(self):
        r = Router(provider=make_provider())
        assert r.model_for("planning") == "glm-5.2"
        assert r.model_for("rank") == "sensenova-6.8-flash-lite"
        assert r.model_for("unknown-tier") == r.tiers["default"]

    def test_custom_tiers_replaceable(self):
        r = Router(provider=make_provider(), tiers={"default": "x", "planning": "y"})
        assert r.model_for("planning") == "y"


def test_router_mechanical_tiers_disable_reasoning():
    """I12 推理控制：机械档位的模型命中控制表 → 请求体带关推理参数；
    思考档位（planning/analysis）不附加 —— 推理保留是质量要求。"""
    captured: list[dict] = []

    def fake_urlopen(req, timeout=0):
        captured.append(json.loads(req.data.decode()))
        return _fake_response("ok")

    led = CostLedger()
    provider = OpenAICompatProvider("https://x.example/v1", "k", ledger=led)
    router = Router(provider=provider)
    with mock.patch("urllib.request.urlopen", fake_urlopen):
        router.chat("rank", "排序 A B C")
        router.chat("planning", "规划下一步")
    rank_body, plan_body = captured
    assert rank_body.get("enable_thinking") is False  # flash-lite 认的开关
    assert "reasoning_effort" not in rank_body
    assert "enable_thinking" not in plan_body  # 思考档不降级
    assert "reasoning_effort" not in plan_body


def test_router_extras_table_overridable():
    """控制表可整体替换（不同渠道参数名差异显式注入）。"""
    captured: list[dict] = []

    def fake_urlopen(req, timeout=0):
        captured.append(json.loads(req.data.decode()))
        return _fake_response("ok")

    provider = OpenAICompatProvider("https://x.example/v1", "k")
    router = Router(
        provider=provider, tier_extras={"deepseek-flash": {"thinking": {"type": "disabled"}}}
    )
    with mock.patch("urllib.request.urlopen", fake_urlopen):
        router.chat("parse_assist", "提取端口")
    assert captured[0].get("thinking") == {"type": "disabled"}


@pytest.mark.llm_live
def test_live_channel_smoke():
    key = os.environ.get("ALETHEIA_LLM_KEY")
    base = os.environ.get("ALETHEIA_LLM_BASE", "https://token.sensenova.cn/v1")
    if not key:
        pytest.skip("ALETHEIA_LLM_KEY 未设置（真实渠道冒烟默认不烧钱）")
    led = CostLedger()
    p = OpenAICompatProvider(base, key, ledger=led, task_tier="smoke")
    r = p.chat("Reply with exactly: OK", model="deepseek-flash", max_tokens=512)
    assert r.content.strip(), f"empty content: {r}"
    assert led.total_tokens() > 0


@pytest.mark.llm_live
def test_live_tier_routing_cost_ledger():
    """I12「分级路由生效且有成本账本验证」的机制级证据：

    两个档位各跑一次真实调用 → 账本按 model/tier 聚合 →
    路由确定性（planning 走重档、rank 走轻档）与记账完整性同时验证。
    """
    key = os.environ.get("ALETHEIA_LLM_KEY")
    if not key:
        pytest.skip("ALETHEIA_LLM_KEY 未设置")
    led = CostLedger()
    provider = OpenAICompatProvider(
        os.environ.get("ALETHEIA_LLM_BASE", "https://token.sensenova.cn/v1"), key, ledger=led
    )
    router = Router(provider=provider)

    r_planning = router.chat("planning", "用一句话说明端口扫描的目的")
    r_rank = router.chat("rank", "给以下漏洞按严重度排序：XSS、RCE（只回复排序结果）")

    assert r_planning.model == router.model_for("planning")
    assert r_rank.model == router.model_for("rank")
    assert r_planning.usage.total_tokens > 0
    assert r_rank.usage.total_tokens > 0
    # 账本聚合：按模型与按档位两种口径都能对上。
    by_model = led.by_model()
    assert by_model.get(router.model_for("planning"), 0) > 0
    assert by_model.get(router.model_for("rank"), 0) > 0
    assert led.total_tokens() > 0
