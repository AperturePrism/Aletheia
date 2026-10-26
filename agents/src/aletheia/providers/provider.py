"""模型 Provider 层（02 §8 `agents/providers/`，对 D17 生态锁定的正面回应）。

设计约束（02 §2 D17 对策 + 04 §1 P-2）：
    · **模型中立**：任何单一模型不得成为架构假设。Provider 接口只承诺
      "chat 返回 content 与 token 用量"，不暴露模型特有能力。
    · **分级路由**（I12 成本治理的执行面）：任务档位 → 模型档位的映射
      外置可配；默认档位表把推理型重模型留给规划、轻模型留给高频子任务。
    · **成本账本**：每次调用记录 (model, prompt/completion/reasoning tokens,
      latency)，供 I12 的"降本 ≥60%"验证与 Q9 预算联动。
    · **零新依赖**：OpenAI 兼容协议用标准库 urllib 实现 —— 本项目拒绝
      "全家桶"式 SDK（go.mod/pyproject 的依赖策略），而 chat/completions
      的协议面足够小且稳定，标准库实现消除了一个供应链面。

Q5 关联：本层是"送往模型的内容"的唯一出口 —— 出站内容必须先经
PrivacyGateway.ScanOutbound（由调用方注入 scan 回调，见 Provider.chat
的 scan 参数），这是 R7 在 L4 的执行点。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol


class ProviderError(Exception):
    """Provider 调用失败（fail-closed：向上传播，不降级不重试遮掩）。"""


@dataclass(frozen=True)
class Usage:
    """一次调用的 token 用量（成本账本的记账单位）。"""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0

    @classmethod
    def from_response(cls, u: dict) -> Usage:
        return cls(
            prompt_tokens=u.get("prompt_tokens", 0),
            completion_tokens=u.get("completion_tokens", 0),
            reasoning_tokens=u.get("completion_tokens_details", {}).get("reasoning_tokens", 0),
            total_tokens=u.get("total_tokens", 0),
        )


@dataclass(frozen=True)
class ChatResult:
    """chat 的返回：content + 用量 + 延迟（供成本账本与评测）。"""

    content: str
    usage: Usage
    latency_ms: int
    model: str


@dataclass
class LedgerEntry:
    """成本账本条目（append-only；I12 的"分级路由账本验证"数据源）。"""

    ts: float
    model: str
    task_tier: str
    usage: Usage
    latency_ms: int


class CostLedger:
    """进程内成本账本（I12 验证的本地形态；持久化在 I12 落地时接 SQLite）。"""

    def __init__(self) -> None:
        self.entries: list[LedgerEntry] = []

    def record(self, e: LedgerEntry) -> None:
        self.entries.append(e)

    def total_tokens(self) -> int:
        return sum(e.usage.total_tokens for e in self.entries)

    def by_model(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.entries:
            out[e.model] = out.get(e.model, 0) + e.usage.total_tokens
        return out

    def by_tier(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.entries:
            out[e.task_tier] = out.get(e.task_tier, 0) + e.usage.total_tokens
        return out


class Provider(Protocol):
    """模型中立的最小接口（D17：不暴露任何模型特有能力）。"""

    name: str

    def chat(
        self,
        prompt: str,
        *,
        model: str,
        max_tokens: int,
        scan: Callable[[str], None] | None = None,
        extras: dict | None = None,
    ) -> ChatResult: ...


class OpenAICompatProvider:
    """OpenAI 兼容协议的 Provider（base_url + api_key 注入）。

    reasoning 型模型（reasoning_content）的处置：推理过程**不是产出**，
    只取 content；reasoning_tokens 单独记账（I12 降本分析的关键维度）。
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        ledger: CostLedger | None = None,
        task_tier: str = "default",
        timeout_s: int = 120,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.ledger = ledger
        self.task_tier = task_tier
        self.timeout_s = timeout_s
        self.name = "openai-compat"

    def chat(
        self,
        prompt: str,
        *,
        model: str,
        max_tokens: int,
        scan: Callable[[str], None] | None = None,
        extras: dict | None = None,
    ) -> ChatResult:
        if scan is not None:
            scan(prompt)  # R7：出站前扫描；命中即 scan 内抛错阻断
        payload: dict = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
        }
        if extras:
            # extras 是请求体级参数（推理控制等），由 Router 按档位注入
            # （机械档位关推理 —— I12 成本实测 reasoning 占 73-80%）。
            payload.update(extras)
        body = json.dumps(payload).encode()
        # base_url 是部署配置注入的受信值（运营者设定，非用户输入），
        # scheme 由部署形态保证为 https —— S310 的审计点不适用，noqa 带理由。
        req = urllib.request.Request(  # noqa: S310
            f"{self.base_url}/chat/completions",
            data=body,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
        )
        t0 = time.monotonic()
        # 有限重试：仅对 429（限流）与网络瞬时错误，指数退避。
        # 其它 HTTP 错误（401/404/5xx）不重试 —— 那是配置或上游故障，
        # 重试只会遮掩根因（fail-closed，P-4）。
        last_exc: Exception | None = None
        resp = None
        for attempt in range(3):
            try:
                resp = json.load(urllib.request.urlopen(req, timeout=self.timeout_s))  # noqa: S310 —— 同上，受信 base_url
                break
            except urllib.error.HTTPError as exc:
                last_exc = exc
                if exc.code == 429 and attempt < 2:
                    time.sleep(2**attempt)  # 1s, 2s
                    continue
                raise ProviderError(f"{self.name}:{model} chat failed: {exc}") from exc
            except Exception as exc:  # 网络瞬时错误：同样有限重试
                last_exc = exc
                if attempt < 2:
                    time.sleep(2**attempt)
                    continue
                raise ProviderError(f"{self.name}:{model} chat failed: {exc}") from exc
        if resp is None:
            raise ProviderError(f"{self.name}:{model} chat failed: {last_exc}")
        latency = int((time.monotonic() - t0) * 1000)
        try:
            choice = resp["choices"][0]
            content = choice["message"].get("content") or ""
            usage = Usage.from_response(resp.get("usage", {}))
        except (KeyError, IndexError) as exc:
            raise ProviderError(f"{self.name}:{model} malformed response: {resp}") from exc
        if not content.strip():
            # content 为空通常是 max_tokens 被推理耗尽 —— 显式失败而非返回空串
            raise ProviderError(
                f"{self.name}:{model} empty content (max_tokens={max_tokens} "
                f"consumed by reasoning?); increase max_tokens"
            )
        result = ChatResult(content=content, usage=usage, latency_ms=latency, model=model)
        if self.ledger is not None:
            self.ledger.record(
                LedgerEntry(
                    ts=time.time(),
                    model=model,
                    task_tier=self.task_tier,
                    usage=usage,
                    latency_ms=latency,
                )
            )
        return result


# ---- 分级路由（I12 的执行面）----
#
# 档位表：任务类型 → 模型。原则（04 §I12/I13）：
#   · planning/planner   → 重推理档（质量优先）
#   · parse_assist/rank  → 轻量档（高频子任务，I13 的微调目标位）
# 档位表可整体替换（构造 Router 时传入自定义映射），默认表只是起点，
# 真实校准依赖账本数据（M4 §8 阈值校准的同款方法论）。

DEFAULT_TIERS: dict[str, str] = {
    "planning": "glm-5.2",
    "analysis": "glm-5.2",
    "parse_assist": "deepseek-flash",
    "rank": "sensenova-6.8-flash-lite",
    "default": "deepseek-flash",
}

#: 机械档位（排序/解析辅助等）默认关闭模型推理 —— I12 成本实测
#: reasoning token 占总消耗 73-80%，而这类任务不需要推理（质量不依赖）。
#: 参数名按模型探测结果（tests/i12/probe_reasoning_control.py）：
#: deepseek/glm 认 reasoning_effort=none；sensenova flash-lite 认
#: enable_thinking=false。思考档位（planning/analysis）不配置 ——
#: 保留推理是质量要求，不做隐性降级。
DEFAULT_TIER_EXTRAS: dict[str, dict[str, dict]] = {
    "deepseek-flash": {"reasoning_effort": "none"},
    "sensenova-6.8-flash-lite": {"enable_thinking": False},
}


@dataclass
class Router:
    """任务档位 → 模型 的确定性路由（零 LLM 参与，P-2）。"""

    provider: Provider
    tiers: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_TIERS))
    # 模型 → 请求体附加参数（推理控制）。键是模型名而非档位名：同一模型
    # 服务多个档位时控制一致；不同渠道的参数名差异在表里显式呈现。
    tier_extras: dict[str, dict] = field(default_factory=lambda: dict(DEFAULT_TIER_EXTRAS))
    max_tokens_by_tier: dict[str, int] = field(
        default_factory=lambda: {
            "planning": 4096,
            "analysis": 2048,
            "parse_assist": 1024,
            "rank": 512,
            "default": 2048,
        }
    )

    def model_for(self, tier: str) -> str:
        return self.tiers.get(tier, self.tiers["default"])

    def chat(
        self, tier: str, prompt: str, *, scan: Callable[[str], None] | None = None
    ) -> ChatResult:
        model = self.model_for(tier)
        # 机械档位的模型命中推理控制表 → 关推理（显式表驱动，不猜参数名）；
        # 思考档位（planning/analysis 等）不在表内即不附加 —— 推理保留。
        extras = self.tier_extras.get(model)
        return self.provider.chat(
            prompt,
            model=model,
            max_tokens=self.max_tokens_by_tier.get(tier, 2048),
            scan=scan,
            extras=extras,
        )
