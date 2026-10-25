"""G-4 独立复现执行器（M4 §4.2 / docs/04 I7 T4.9）。

判定语义（与 M4 §4.2 原文对齐）：
  · 复现环境**独立于 agent**（后端由系统装配，agent 只提交 ReproSpec）；
  · 环境指纹匹配 —— spec.environment_hash 必须等于执行后端自报指纹，
    不匹配即 fail-closed（"环境不同"不能假装复现成功）；
  · 复现结果与首次执行一致 —— 首次执行的强证据是其副作用观测命中的
    模式（matched_pattern，可审计正则）；重放输出中**同样的模式再次
    命中**才算复现。全文哈希对比对 nmap 这类输出含时延的天然不确定，
    且断言真正依赖的就是模式命中，不是字节。

steps 契约：每条 step 是一条**空格分隔的 argv 命令**（不经 shell 元字符）
—— 与 ReproSpec「确定性命令序列」的语义一致，也避免 shell 注入面
（09 §R5 的同款理由：不存在"任意命令"接口）。
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Protocol

from aletheia.focalplane.ids import uuid7

#: 单次复现的总时限（M4 §8 / I7 DoD：单次复现 < 10 min）。
TOTAL_TIMEOUT_S = 600.0

#: 单步默认时限；spec.estimated_minutes 提供时按其均摊收紧。
STEP_TIMEOUT_S = 120.0

#: 步骤超时的退出码约定（GNU timeout(1) 惯例）。
_EXIT_TIMEOUT = 124


@dataclass(frozen=True)
class StepOutcome:
    """单步执行结果。timeout 时 exit_code=124、stdout 为已捕获部分。"""

    exit_code: int
    stdout: str
    command: str


class ReproBackend(Protocol):
    """复现执行后端。第一版为本机进程（ProcessBackend）；
    P1 的容器快照后端实现同一协议即可替换（M4 §8「复现环境用容器快照复用」）。
    """

    def fingerprint(self) -> str:
        """执行环境指纹（sha256 hex）。G-4 与 spec.environment_hash 比对。"""
        ...

    def run_step(self, argv: list[str], timeout_s: float) -> StepOutcome:
        """在干净上下文中执行一步（无残留状态、无继承敏感环境）。"""
        ...


class ProcessBackend:
    """本机进程后端：每步独立子进程 + 最小固定 env + 一次性临时工作目录。

    「干净」的第一版语义：无 shell、无继承 env（只给 PATH/LANG/LC_ALL）、
    每步独立临时 cwd（用后即删）—— 进程间零状态残留。容器级隔离由
    P1 的 DockerBackend 提供同一 Protocol 实现。
    """

    backend_id = "process:1"

    def fingerprint(self) -> str:
        parts = "|".join(
            [
                self.backend_id,
                sys.platform,
                platform.machine(),
                platform.python_implementation(),
            ]
        )
        return hashlib.sha256(parts.encode()).hexdigest()

    def run_step(self, argv: list[str], timeout_s: float) -> StepOutcome:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "LANG": "C",
            "LC_ALL": "C",
        }
        with tempfile.TemporaryDirectory(prefix="aleth-repro-") as cwd:
            try:
                # 行内 noqa 理由：argv 来自 ReproSpec.steps（M4 §4.2 契约即
                # 「重放确定性命令序列」）—— 与 nmap 适配器同级的受控面；
                # 隔离措施：无 shell、最小 env、一次性 cwd、逐步超时与总预算。
                proc = subprocess.run(  # noqa: S603
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                    cwd=cwd,
                    env=env,
                    check=False,
                )
                return StepOutcome(proc.returncode, proc.stdout, " ".join(argv))
            except subprocess.TimeoutExpired as exc:
                out = exc.stdout or ""
                if isinstance(out, bytes):
                    out = out.decode(errors="replace")
                return StepOutcome(_EXIT_TIMEOUT, out, " ".join(argv))


def argv_of(step: str) -> list[str]:
    """step 字符串 → argv。posix 语义但 Windows 下保留反斜杠路径。"""
    return shlex.split(step, posix=os.name != "nt")


class ReproExecutor:
    """按 ReproSpec 重放并对照副作用模式给出 G-4 结论。"""

    def __init__(self, backend: ReproBackend) -> None:
        self._backend = backend

    def reproduce(
        self,
        *,
        side_effect_patterns: list[str],
        spec_steps: list[str],
        spec_env_hash: str,
        spec_estimated_minutes: float,
    ) -> tuple[bool, str, str]:
        """执行复现。返回 (reproduced, reason, reproduction_exec_id)。

        fail-closed 原则：任何缺失（无 steps / 无比对模式 / 环境指纹
        不匹配 / 步骤失败或超时 / 模式未再命中）都返回 False 与具体
        reason —— 不存在"默认通过"路径。
        """
        exec_id = "repro_" + uuid7()

        if not spec_steps:
            return False, "no reproduction steps in spec; cannot replay", exec_id

        patterns = [p for p in side_effect_patterns if p.strip()]
        if not patterns:
            return (
                False,
                "evidence carries no matched side-effect patterns to reproduce against",
                exec_id,
            )

        actual = self._backend.fingerprint()
        if not spec_env_hash:
            return False, "spec.environment_hash is required (fail-closed)", exec_id
        if spec_env_hash != actual:
            return (
                False,
                f"environment mismatch: spec={spec_env_hash[:16]}… actual={actual[:16]}…",
                exec_id,
            )

        budget = min(TOTAL_TIMEOUT_S, max(spec_estimated_minutes, 0) * 60 or TOTAL_TIMEOUT_S)
        per_step = max(min(STEP_TIMEOUT_S, budget / len(spec_steps)), 1.0)
        deadline = time.monotonic() + budget

        combined: list[str] = []
        for i, step in enumerate(spec_steps):
            if time.monotonic() >= deadline:
                return (
                    False,
                    f"reproduction budget exhausted before step {i + 1}/{len(spec_steps)}",
                    exec_id,
                )
            outcome = self._backend.run_step(argv_of(step), per_step)
            if outcome.exit_code != 0:
                code = (
                    "timeout" if outcome.exit_code == _EXIT_TIMEOUT else f"exit {outcome.exit_code}"
                )
                return (
                    False,
                    f"step {i + 1}/{len(spec_steps)} failed ({code}): {outcome.command}",
                    exec_id,
                )
            combined.append(outcome.stdout)

        replayed = "\n".join(combined)
        missing = [p for p in patterns if not re.search(p, replayed)]
        if missing:
            return (
                False,
                f"patterns not re-observed in replay ({len(missing)}/{len(patterns)} missing): "
                + "; ".join(missing[:3]),
                exec_id,
            )
        return (
            True,
            f"{len(patterns)}/{len(patterns)} side-effect patterns re-observed in replay",
            exec_id,
        )
