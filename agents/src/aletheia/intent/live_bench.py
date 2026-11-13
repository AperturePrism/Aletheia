"""在真实靶场上跑业务逻辑检测基准（`04` §P2 门禁的"首个可复现数字"）。

用法：

    # 1) 起靶场（docker 在 WSL2 内）
    wsl -d Arch -- bash scripts/labs-up.sh bizlogic
    # 2) 跑基准
    PYTHONPATH=agents/src .venv/Scripts/python.exe -m aletheia.intent.live_bench \
        --base http://127.0.0.1:8080 --out labs/bizlogic/last_run.json

# 输出什么

* `mode` 口径下的 **分母 / 检出 / 漏报 / 误报**（来自 `lab.evaluate_detection`）；
* 每个缺陷的探测证据摘要（请求、状态码、观测到的数据）；
* 一条明确的**证据等级声明**：本次探测未经 Sandbox 签名，
  因此结论只支撑"靶场基准分数"，不支撑"已确认漏洞"。

# 为什么必须打印证据等级声明

`docs/04` 的第一原则是"结论必须由证据显现"。本模块的 `exec_id`
是内容指纹而非签名执行 id，若报告里不区分这两者，读者会把
"本地探测到的现象"当成"证据链确认的结论"。
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
from pathlib import Path

from aletheia.intent.lab import LabMode, evaluate_detection
from aletheia.intent.live_probe import (
    HttpProber,
    bizlogic_ground_truth,
    violations_from,
)

#: 证据等级声明（必须随任何引用本数字的报告一起出现）。
EVIDENCE_DISCLAIMER = (
    "本次探测由 live_probe 直接发起 HTTP 请求，未经 Sandbox 签名，"
    "exec_id 为内容指纹（localprobe:*）而非签名执行 id。"
    "因此这些数字支撑『靶场基准的可复现分数』，"
    "但**不构成红线级（Q3）证据，也不得据此宣称已确认漏洞**。"
)


def run(base: str, *, mode: str = LabMode.WITHOUT_CONTRACT) -> dict:
    """跑一轮基准，返回可序列化的结果。"""
    lab = bizlogic_ground_truth()
    prober = HttpProber(base=base)
    results = prober.probe_all()
    violations = violations_from(results)

    # 注意参数顺序：`evaluate_detection(lab, mode, violations)`。
    # 我第一次写成 (lab, violations, mode)，于是 `mode` 收到的是 list，
    # 在 `mode in d.detectable_in` 处抛 "unhashable type: 'list'"。
    stats = evaluate_detection(lab, mode, violations)

    per_defect = []
    for r in results:
        per_defect.append(
            {
                "violation_type": r.violation_type,
                "endpoint_key": r.endpoint_key,
                "observed": r.data_returned,
                "exec_id": r.exec_id,
                "details": dict(r.details),
            }
        )

    return {
        "generated_at": _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": base,
        "lab": lab.name,
        "mode": mode,
        "detectable": stats.detectable,
        "detected": stats.detected,
        "missed": stats.missed,
        "false_positives": stats.false_positives,
        "rate": (len(stats.detected) / stats.detectable) if stats.detectable else 0.0,
        "per_defect": per_defect,
        "evidence_level": "local_probe_unsigned",
        "evidence_disclaimer": EVIDENCE_DISCLAIMER,
        "probe_log": prober.log,
    }


def render(summary: dict) -> str:
    lines = [
        "== bizlogic 业务逻辑检测基准（真实靶场）==",
        f"目标: {summary['target']}   模式: {summary['mode']}",
        f"分母（该模式可检）: {summary['detectable']}   "
        f"检出: {len(summary['detected'])}   "
        f"漏报: {len(summary['missed'])}   "
        f"误报: {len(summary['false_positives'])}",
        f"检出率: {summary['rate'] * 100:.1f}%",
        "",
        "逐类观测:",
    ]
    for d in summary["per_defect"]:
        mark = "HIT " if d["observed"] else "miss"
        lines.append(f"  [{mark}] {d['violation_type']:<20} {d['endpoint_key']}")
        for k, v in d["details"].items():
            lines.append(f"           {k}={v}")
    if summary["missed"]:
        lines += ["", f"漏报明细: {summary['missed']}"]
    if summary["false_positives"]:
        lines += ["", f"误报明细: {summary['false_positives']}"]
    lines += ["", "证据等级: " + summary["evidence_disclaimer"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """CLI 入口（返回退出码，**不**自行终止进程）。

    ★ 为什么这里不直接终止进程：

    `scripts/check-no-bypass.sh` 的 R6 规则扫描 `agents/`，禁止**进程级
    终止调用**（Python 的退出内建函数、操作系统级强制退出、以及抛出退出
    异常这三种写法）—— 因为 **agent 代码不得自行终止会话**（`docs/09` §R6）。

    本模块是库，不是 agent，但它位于 `agents/` 下，因此同样受该规则约束。
    正确的分工是：

      · 库（本文件）只返回退出码，不决定进程生死；
      · 真正的 CLI 放在 `scripts/bench-bizlogic.py`（与仓库里既有的
        `scripts/extract-release-notes.py` 同一惯例）。

    这样既守住 R6 的意图，也不必削弱门禁规则（`docs/09` §R2）。
    （本注释刻意不写出那三个调用的字面形式 —— 该规则做的是全文正则扫描，
    文档里出现字样同样会命中。这本身也是个值得记住的细节：
    **门禁的扫描范围包含说明文字**。）
    """
    ap = argparse.ArgumentParser(description="bizlogic 业务逻辑检测基准")
    ap.add_argument("--base", default="http://127.0.0.1:8080")
    ap.add_argument(
        "--mode",
        default=LabMode.WITHOUT_CONTRACT,
        choices=[LabMode.WITHOUT_CONTRACT, LabMode.WITH_CONTRACT],
    )
    ap.add_argument("--out", default="", help="结果 JSON 输出路径")
    args = ap.parse_args(argv)

    summary = run(args.base, mode=args.mode)
    print(render(summary))
    if args.out:
        p = Path(args.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n已写入 {p}")
    # 检出率不作为退出码判据：本命令是**测量**工具，不是门禁。
    # 门禁判据见 docs/04 §P2（需要人工结合口径判断）。
    return 0
