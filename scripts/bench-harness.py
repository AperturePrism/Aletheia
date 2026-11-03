#!/usr/bin/env python3
"""用 M9 harness 端到端跑一次**真实**评测（自建基准，非公开基准）。

# 这个脚本交付什么，以及**不**交付什么

交付：
* 用 `harness.driver.run_benchmark` 走完整评测链路（清单完整性 → 逐任务 →
  结构化结果 → 可复现元信息），被测系统是**真实 LLM 在环**的判定器；
* 真实 token 消耗、真实失败归档、真实逐任务结论；
* 可复跑的命令与可复现清单（git sha / 模型 / temperature / seed / 靶场版本）。

**不**交付：公开基准（CyBench / CVE-Bench / XBOW / HTB）的分数 ——
那些需要官方任务清单与 ground truth，见 `benchmarks/README.md` §4。
**本脚本的分数只能叫「自建基准分数」，不得当作行业可比数字。**

# 被测系统是什么

对每个任务：先用 `live_probe` 发真实 HTTP 探测取得**行为观测**，
再把观测交给真实模型要求它**归类**（BL1–BL6 之一）。

`solved` 的判据是"模型给出的归类 == ground truth"。因此本评测测的是
**模型能否把已观测到的异常正确归类**，不是"模型能否自己发现异常"。
这个区分必须写进任何引用本数字的地方 —— 否则会高估系统能力。

# 为什么观测与归类分开

若让模型直接面对原始 HTTP 响应自由发挥，测到的就混入了"模型是否愿意
动手探测"这个与业务逻辑识别无关的变量。分开之后，每个任务的输入
（观测）是确定的，模型的贡献被限制在"归类"这一步，可比较、可复现。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_SRC = _REPO / "agents" / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aletheia.harness.adapter import (  # noqa: E402
    BenchmarkTask,
    ReproducibilityManifest,
    TaskResult,
)
from aletheia.harness.driver import run_benchmark  # noqa: E402
from aletheia.harness.manifest_adapter import ManifestBenchmarkAdapter  # noqa: E402
from aletheia.intent.live_probe import HttpProber  # noqa: E402
from aletheia.providers.provider import (  # noqa: E402
    CostLedger,
    OpenAICompatProvider,
    Router,
)

#: task_id → 对应的真实探测（观测来源固定，保证可复现）。
PROBES = {
    "bl1-order-idor": "probe_bl1",
    "bl2-client-total": "probe_bl2",
    "bl3-skip-payment": "probe_bl3",
    "bl4-quota-reset": "probe_bl4",
    "bl5-header-promote": "probe_bl5",
    "bl6-double-spend": "probe_bl6",
}

#: 允许模型输出的类别集合（与 ground truth 同一命名空间）。
ALLOWED_TYPES = (
    "BL1_IDOR",
    "BL2_TAMPERING",
    "BL3_FLOW_BYPASS",
    "BL4_QUOTA_BYPASS",
    "BL5_PRIVILEGE_CHAIN",
    "BL6_RACE",
    "NONE",
)

CLASSIFY_PROMPT = """你是业务逻辑漏洞分类器。给定一次对 Web 应用的**已观测**探测结果，
判断它属于下列哪一类业务逻辑缺陷。只输出类别代码，不要任何解释。

可选类别：
- BL1_IDOR              越权访问（普通用户读到了他人的资源）
- BL2_TAMPERING         价格/数量篡改（服务端采信了客户端提交的金额）
- BL3_FLOW_BYPASS       流程绕过（状态机允许 X→Z，跳过 Y）
- BL4_QUOTA_BYPASS      配额绕过（计数可被重置或绕过）
- BL5_PRIVILEGE_CHAIN   权限提升链（低权限获得高权限操作）
- BL6_RACE              竞态/TOCTOU（并发下一致性被破坏）
- NONE                  以上都不是

探测观测：
任务描述：{description}
观测结果：{observation}

只输出一个类别代码（例如 BL4_QUOTA_BYPASS）。"""


def _git_sha() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short=7", "HEAD"],  # noqa: S607
            cwd=_REPO,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _build_router(model: str, ledger: CostLedger) -> Router:
    base = os.environ["ALETHEIA_LLM_BASE"]
    key = os.environ["ALETHEIA_LLM_KEY"]
    provider = OpenAICompatProvider(base_url=base, api_key=key, ledger=ledger)
    return Router(
        provider=provider,
        tiers=dict.fromkeys(("planning", "analysis", "parse_assist", "rank", "default"), model),
        tier_extras={},
    )


class LiveClassifierSystem:
    """被测系统：真实探测 + 真实 LLM 归类。"""

    def __init__(self, base: str, router: Router, ledger: CostLedger) -> None:
        self.prober = HttpProber(base=base)
        self.router = router
        self.ledger = ledger
        self.calls = 0

    def __call__(self, task: BenchmarkTask) -> TaskResult:
        probe_name = PROBES.get(task.task_id)
        if probe_name is None:
            return TaskResult(
                task_id=task.task_id,
                solved=False,
                failure_reason=f"no probe mapped for task {task.task_id!r}",
            )

        # 1) 真实探测（观测来源固定）
        probe_result = getattr(self.prober, probe_name)()
        observation = json.dumps(
            {
                "endpoint": probe_result.endpoint_key,
                "violation_hint": probe_result.violation_type,
                "observed": probe_result.data_returned,
                "details": dict(probe_result.details),
            },
            ensure_ascii=False,
        )

        # 2) 真实模型归类（唯一一次 LLM 调用）
        before = self.ledger.total_tokens()
        prompt = CLASSIFY_PROMPT.format(description=task.description, observation=observation)
        try:
            res = self.router.chat("parse_assist", prompt)
            self.calls += 1
        except Exception as exc:  # noqa: BLE001 —— 单任务失败要结构化归档
            return TaskResult(
                task_id=task.task_id,
                solved=False,
                failure_reason=f"llm call failed: {type(exc).__name__}: {exc}",
                tokens=self.ledger.total_tokens() - before,
            )
        used = self.ledger.total_tokens() - before

        # 3) 严格解析：只接受白名单类别，宽松匹配一律不做
        answer = (res.content or "").strip().upper()
        reported = next((t for t in ALLOWED_TYPES if t in answer), "")
        if not reported:
            return TaskResult(
                task_id=task.task_id,
                solved=False,
                reported=(),
                tokens=used,
                failure_reason=f"unparseable classification: {answer[:80]!r}",
            )

        solved = reported in set(task.ground_truth)
        return TaskResult(
            task_id=task.task_id,
            solved=solved,
            reported=(reported,),
            tokens=used,
            failure_reason=""
            if solved
            else f"classified as {reported}, expected {task.ground_truth}",
        )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="自建基准端到端评测（真实 LLM 在环）")
    ap.add_argument("--manifest", default="labs/bizlogic/tasks.json")
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    ap.add_argument("--model", default=os.environ.get("ALETHEIA_LLM_MODEL", "deepseek-v4.1-flash"))
    ap.add_argument(
        "--target-env",
        default="aleth-lab-bizlogic (python:3.12-alpine @sha256:e6dae589c1c05976188fd3bd019afd091445fc533ed2ea29001beddc7368a9c8)",
    )
    ap.add_argument("--out", default="", help="结果 JSON 输出路径（相对仓库根）")
    args = ap.parse_args(argv)

    for var in ("ALETHEIA_LLM_KEY", "ALETHEIA_LLM_BASE"):
        if not os.environ.get(var):
            print(f"缺少环境变量 {var}（真实调用需要）", file=sys.stderr)
            return 2

    adapter = ManifestBenchmarkAdapter(_REPO / args.manifest)
    ledger = CostLedger()
    system = LiveClassifierSystem(args.base, _build_router(args.model, ledger), ledger)

    manifest = ReproducibilityManifest(
        system_version=_git_sha(),
        model=args.model,
        temperature="provider-default（未显式设置，故无法断言为 0）",
        seed="0",
        target_environment=args.target_env,
        observation_coverage="6 个端点，六类业务逻辑缺陷各 1 个",
    )
    missing = manifest.missing_fields()
    if missing:
        print(f"可复现清单缺字段：{missing}", file=sys.stderr)
        return 2

    # ★ 一次调用 = 一次评测 = **一次靶场重启**。
    #
    # 不提供 `--repeats`：我曾加过它，并在真实靶场上踩到了坑 ——
    # 第 2 轮是在**被上一轮改过**的靶场状态上跑的：
    #   · BL3 的订单已是 SHIPPED → 再 ship 仍返回 SHIPPED（同义反复）
    #   · BL6 双花后 bob 余额已是 -600 → 后续转账因余额不足失败，
    #     但"余额为负"这个判据依然成立 ⇒ 看起来"检出成功"，实际什么都没测
    #
    # 也就是说：**重复跑而不重置靶场，会让分数看起来稳定，实则退化为恒真**。
    # 需要多轮时，外层循环必须每轮先 `labs-up.sh`（内部强制 down -v）。
    t0 = time.monotonic()
    run = run_benchmark(adapter, system, manifest, task_timeout_s=120.0)
    solved = sum(1 for r in run.results if r.solved)
    runs = [
        {
            "solved": solved,
            "total": len(run.results),
            "results": [
                {
                    "task_id": r.task_id,
                    "solved": r.solved,
                    "reported": list(r.reported),
                    "tokens": r.tokens,
                    "failure_reason": r.failure_reason,
                }
                for r in run.results
            ],
        }
    ]
    print(f"solved {solved}/{len(run.results)}")

    summary = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "benchmark": adapter.name,
        "kind": "self_built_benchmark",  # ★ 不是公开基准
        "caveat": (
            "这是自建基准（labs/bizlogic）上的分数，**不是**公开基准分数，"
            "不可与 CyBench/CVE-Bench/XBOW/HTB 的结果横向比较。"
            "solved 的语义是「模型对已观测异常的归类正确」，"
            "不是「系统自主发现了异常」。"
        ),
        "reproducibility": {
            "system_version": manifest.system_version,
            "model": manifest.model,
            "temperature": manifest.temperature,
            "seed": manifest.seed,
            "target_environment": manifest.target_environment,
            "observation_coverage": manifest.observation_coverage,
        },
        "llm_calls": system.calls,
        "total_tokens": ledger.total_tokens(),
        "by_tier": ledger.by_tier(),
        "wall_time_s": round(time.monotonic() - t0, 1),
        "runs": runs,
    }

    print(f"\n模型={args.model}  LLM 调用={system.calls}  tokens={ledger.total_tokens()}")
    print(f"按档位: {ledger.by_tier()}")
    if args.out:
        p = _REPO / args.out
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"已写入 {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
