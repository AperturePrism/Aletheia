"""I12 成本基准：分级路由 vs 单一前沿模型（真实渠道，CostLedger 记账）。

DoD②「成本较单一前沿模型方案降 ≥ 60%」的可复现实验：

  · 配置 A（单一前沿模型）：全部档位走 glm-5.2（重档）
  · 配置 B（分级路由）：DEFAULT_TIERS（planning/analysis→glm-5.2，
    parse_assist/default→deepseek-flash, rank→sensenova-6.8-flash-lite）
  · 任务集：按真实 agent 负载分布构造（planning:analysis:parse:rank
    = 1:2:4:4，高频子任务占大头 —— I13 定义的两类高频子任务即
    parse_assist 与 rank），prompt 取自 NAS 靶场真实扫描观测
  · 成本口径：token 总量（输入/输出/推理分列）。token 是可复现的
    保守代理 —— 真实货币成本还取决于各模型单价，轻档单价通常更低，
    因此 token 降幅是货币降幅的下界估计。

运行：ALETHEIA_LLM_KEY=... python tests/i12/cost_benchmark.py [--small]
--small 用每类 2 个变体先试跑（约 44 次调用）；默认全量（每类 5 变体，
110 任务 × 2 配置 = 220 次真实调用）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agents" / "src"))

from aletheia.providers.provider import (
    DEFAULT_TIER_EXTRAS,
    DEFAULT_TIERS,
    CostLedger,
    OpenAICompatProvider,
)

BASE = os.environ.get("ALETHEIA_LLM_BASE", "https://token.sensenova.cn/v1")
HEAVY = "glm-5.2"  # 「单一前沿模型方案」的全量模型（重档）

#: 任务 prompt（基于 NAS 靶场 Juice Shop 的真实扫描观测构造，
#: 每档位 5 个变体 —— 变体防渠道级缓存，语义同型）。
TASKS: dict[str, list[str]] = {
    "planning": [
        "目标 10.40.23.191:3000 运行 Juice Shop（Node/Express）。用一句话给出下一步侦察动作。",
        "已观测目标开放 3000/tcp（http）。用一句话规划服务指纹识别的下一步。",
        "侦察阶段完成端口发现。用一句话说明下一阶段应该做什么。",
        "目标的 Web 框架已识别。用一句话规划漏洞发现阶段的首个动作。",
        "扫描发现单主机单端口。用一句话判断是否需要扩大范围并给出动作。",
    ],
    "analysis": [
        "nmap 观测：host 10.40.23.191 up，3000/tcp open http（Juice Shop）。用两句话分析攻击面。",
        "观测到目标 HTTP 服务标题为 OWASP Juice Shop。分析该指纹对漏洞利用的意义（两句话）。",
        "工具输出折叠模板 'port {port}/tcp open {service}' 命中 1 次。分析信息量并指出缺失项（两句话）。",
        "靶场为单容器部署、无 WAF 特征。分析测试优先级应如何排布（两句话）。",
        "图谱新增 ASSET(10.40.23.191) 与 SERVICE(3000/http) 实体。分析实体关系的含义（两句话）。",
    ],
    "parse_assist": [
        "从输出中提取开放端口：'3000/tcp open http'。只回复端口号。",
        "从输出提取服务名：'service: nginx 1.18.0 on port 80'。只回复服务与版本。",
        "提取观测中的主机地址：'host 10.40.23.5 up'。只回复 IP。",
        "提取实体类型：图谱节点 attrs={addr, port, proto}。只回复实体类别名。",
        "提取折叠统计：'port 80 open x3, port 22 open x1'。只回复端口计数对。",
    ],
    "rank": [
        "按利用价值排序（只回复排序）：XSS、SQL注入、RCE、信息泄露。",
        "按侦察优先级排序（只回复排序）：端口扫描、目录枚举、指纹识别。",
        "按攻击面大小排序（只回复排序）：管理后台、静态资源、API 端点。",
        "按可利用性排序（只回复排序）：弱口令、过期组件、配置错误。",
        "按取证价值排序（只回复排序）：凭据、会话令牌、错误信息。",
    ],
}

#: 负载分布（权重）：planning:analysis:parse:rank = 1:2:4:4
WEIGHTS = {"planning": 1, "analysis": 2, "parse_assist": 4, "rank": 4}


def build_workload(variants_per_tier: int) -> list[tuple[str, str]]:
    """按权重展开任务负载（tier, prompt）。"""
    work: list[tuple[str, str]] = []
    for tier, w in WEIGHTS.items():
        prompts = TASKS[tier][:variants_per_tier]
        for prompt in prompts:
            work.extend([(tier, prompt)] * w)
    return work


def run_config(
    name: str,
    tiers: dict[str, str],
    work: list[tuple[str, str]],
    mt: dict[str, int],
    tier_extras: dict[str, dict] | None = None,
) -> dict:
    """跑一个配置。路由语义 = tiers 映射（Router.chat 的内部实现同款：
    model_for(tier) → provider.chat）；每个档位独立 Provider+Ledger，
    使 task_tier 记账口径正确（单 Provider 的 task_tier 是构造期固定的）。
    """
    key = os.environ["ALETHEIA_LLM_KEY"]
    by_tier_provider: dict[str, OpenAICompatProvider] = {}
    ledgers: dict[str, CostLedger] = {}
    for tier in {t for t, _ in work}:
        led = CostLedger()
        ledgers[tier] = led
        by_tier_provider[tier] = OpenAICompatProvider(BASE, key, ledger=led, task_tier=tier)

    t0 = time.monotonic()
    errors = 0
    for tier, prompt in work:
        model = tiers.get(tier, tiers["default"])
        extras = (tier_extras or {}).get(model)
        try:
            by_tier_provider[tier].chat(
                prompt, model=model, max_tokens=mt.get(tier, 2048), extras=extras
            )
        except Exception as exc:  # noqa: BLE001 —— 基准须容忍单次失败并计数
            errors += 1
            print(f"  [{name}] {tier}/{model} 调用失败: {exc}", file=sys.stderr)
            time.sleep(2)
    elapsed = time.monotonic() - t0

    all_entries = [e for led in ledgers.values() for e in led.entries]
    by_model: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    reasoning = 0
    for e in all_entries:
        by_model[e.model] = by_model.get(e.model, 0) + e.usage.total_tokens
        by_tier[e.task_tier] = by_tier.get(e.task_tier, 0) + e.usage.total_tokens
        reasoning += e.usage.reasoning_tokens
    return {
        "config": name,
        "calls": len(work),
        "errors": errors,
        "elapsed_s": round(elapsed, 1),
        "total_tokens": sum(e.usage.total_tokens for e in all_entries),
        "reasoning_tokens": reasoning,
        "by_model": by_model,
        "by_tier": by_tier,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--small", action="store_true", help="每类 2 变体试跑")
    args = ap.parse_args()
    if not os.environ.get("ALETHEIA_LLM_KEY"):
        print("ALETHEIA_LLM_KEY 未设置", file=sys.stderr)
        return 2

    variants = 2 if args.small else 5
    work = build_workload(variants)
    print(f"任务负载：{len(work)} 调用/配置（变体 {variants}，权重 {WEIGHTS}）")

    single = {**dict.fromkeys(WEIGHTS, HEAVY), "default": HEAVY}  # 配置 A：全走重档
    # rank 档 512 会被轻档模型的推理 token 耗尽（试跑实测），统一放宽到 1024
    # —— 两配置用同一 max_tokens 表，对比口径一致。
    mt = {"planning": 4096, "analysis": 2048, "parse_assist": 1024, "rank": 1024, "default": 2048}
    r_a = run_config(f"single-{HEAVY}", single, work, mt)
    r_b = run_config("tiered-router", dict(DEFAULT_TIERS), work, mt)
    optimized = {
        **dict(DEFAULT_TIERS),
        "rank": "deepseek-flash",
    }  # 实测调优：flash-lite 的 reasoning 开销抵消轻档优势
    r_c = run_config("optimized-router", optimized, work, mt)
    # 配置 D：分级路由 + 机械档位关推理（probe_reasoning_control.py 实测
    # 渠道支持）—— 机械任务质量不依赖推理，关掉是纯收益。
    r_d = run_config(
        "tiered-reasoning-off",
        dict(DEFAULT_TIERS),
        work,
        mt,
        tier_extras=dict(DEFAULT_TIER_EXTRAS),
    )

    def drop_pct(r: dict) -> float:
        return round((r_a["total_tokens"] - r["total_tokens"]) / r_a["total_tokens"] * 100, 2)

    report = {
        "workload": {"variants": variants, "weights": WEIGHTS, "calls_per_config": len(work)},
        "single_model": r_a,
        "tiered": r_b,
        "optimized": r_c,
        "tiered_reasoning_off": r_d,
        "token_drop_pct_tiered": drop_pct(r_b),
        "token_drop_pct_optimized": drop_pct(r_c),
        "token_drop_pct_reasoning_off": drop_pct(r_d),
        "dod2_pass_60pct": drop_pct(r_d) >= 60.0,
        "note": "token 口径是货币成本降幅的下界估计（轻档单价通常更低）",
    }
    out = Path(__file__).with_name("last_run.json")
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n报告已写入 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
