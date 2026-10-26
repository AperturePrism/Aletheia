"""探测渠道对推理控制参数的支持（I12 DoD② 达成路径验证）。

背景：成本基准实测 reasoning token 占 73-80%（渠道模型全推理型），
token 口径降本被卡在 ~32%。若渠道支持关闭/压低轻档模型的推理
（reasoning_effort / enable_thinking / chat_template_kwargs 等常见
开关），轻档 token 可大幅下降 → DoD② 有机会达成。

方法：同一 prompt 基线 vs 各候选参数，比较 usage 的 reasoning 与
total token。只报告事实（支持/不支持/无效果），不做价格假设。
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
from pathlib import Path

BASE = os.environ.get("ALETHEIA_LLM_BASE", "https://token.sensenova.cn/v1")
KEY = os.environ.get("ALETHEIA_LLM_KEY", "")
MODELS = ["sensenova-6.8-flash-lite", "deepseek-flash", "glm-5.2"]

#: 候选开关（OpenAI 兼容生态常见形态；值按「尽量关/最低」给）。
CANDIDATES: dict[str, dict] = {
    "baseline": {},
    "reasoning_effort=none": {"reasoning_effort": "none"},
    "reasoning_effort=low": {"reasoning_effort": "low"},
    "enable_thinking=false": {"enable_thinking": False},
    "thinking.type=disabled": {"thinking": {"type": "disabled"}},
    "chat_template_kwargs": {"chat_template_kwargs": {"enable_thinking": False}},
}

PROMPT = "按利用价值排序（只回复排序）：XSS、SQL注入、RCE、信息泄露。"


def call(model: str, extra: dict) -> dict:
    body = {
        "model": model,
        "messages": [{"role": "user", "content": PROMPT}],
        "max_tokens": 1024,
    }
    body.update(extra)
    req = urllib.request.Request(  # noqa: S310 受信 base_url（环境变量/默认常量）
        f"{BASE}/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
        return json.load(resp)


def usage_of(r: dict) -> tuple[int, int]:
    u = r.get("usage", {})
    reasoning = u.get("completion_tokens_details", {}).get("reasoning_tokens", 0)
    return u.get("total_tokens", 0), reasoning


def main() -> int:
    if not KEY:
        print("ALETHEIA_LLM_KEY 未设置", file=sys.stderr)
        return 2
    results: dict[str, dict] = {}
    for model in MODELS:
        results[model] = {}
        for name, extra in CANDIDATES.items():
            try:
                total, reasoning = usage_of(call(model, extra))
                results[model][name] = {"total": total, "reasoning": reasoning}
                print(f"{model:28s} {name:24s} total={total:6d} reasoning={reasoning:6d}")
            except Exception as exc:  # noqa: BLE001 探测须容忍各类 4xx
                results[model][name] = {"error": str(exc)[:120]}
                print(f"{model:28s} {name:24s} ERROR {str(exc)[:80]}")
            time.sleep(1.5)  # 渠道限流礼貌间隔
    out = Path(__file__).with_name("reasoning_probe.json")
    with out.open("w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n结果已写入 {out}")
    # 自动小结：每个模型找出 reasoning 显著低于 baseline 的候选
    print("\n小结（相对 baseline 的 reasoning 降幅 >50% 视为有效）：")
    for model in MODELS:
        base = results[model].get("baseline", {})
        if "total" not in base:
            continue
        for name, r in results[model].items():
            if name == "baseline" or "total" not in r:
                continue
            if base["reasoning"] > 0 and r["reasoning"] < base["reasoning"] * 0.5:
                print(f"  ✅ {model}: {name}（reasoning {base['reasoning']}→{r['reasoning']}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
