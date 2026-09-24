"""CI 工作流的结构完整性测试。

**为什么值得测**：CI 首跑 + 二跑共三次失败，全部源于"某个 job 漏了某步 setup"
或"inline 写了已经过时的做法"。这类问题在本地永远发现不了 ——
本地依赖早已装好，只有干净环境会暴露。

把"每个 job 都用了统一 setup"变成断言后，新增 job 时漏 setup 会立刻红灯，
而不是等下一次 push 到 GitHub 才失败。

对应文档：
    docs/09 R10（不得在未达门禁时进入下一阶段）
    docs/10 §8（检查项一旦写进 CI 门禁，就无法自欺）
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
SETUP_ACTION = REPO_ROOT / ".github" / "actions" / "setup" / "action.yml"

pytestmark = pytest.mark.redline

# 已废弃的 setup 做法。命中即失败 —— 它们都是踩过坑的：
#   · curl 装 uv：装到 ~/.local/bin，不在 runner 的 PATH 里 → uv: command not found
#   · job 内手写 setup-*：新增 job 时会漏
DEPRECATED_SETUP_PATTERNS = [
    (
        r"astral\.sh/uv/install\.sh",
        "curl 安装 uv 会装到 ~/.local/bin（不在 runner PATH），应改用 ./.github/actions/setup",
    ),
    (r"uses:\s*actions/setup-go@", "job 内手写 setup-go，应统一用 ./.github/actions/setup"),
    (r"uses:\s*actions/setup-node@", "job 内手写 setup-node，应统一用 ./.github/actions/setup"),
    (r"uses:\s*actions/setup-python@", "job 内手写 setup-python，应统一用 ./.github/actions/setup"),
    (r"uses:\s*astral-sh/setup-uv@", "job 内手写 setup-uv，应统一用 ./.github/actions/setup"),
]

# workflow 里的 inline npm install。
# 首跑失败根因：Q11 job 只 npm install 了根目录（装的是 buf），
# 漏了 web/ 的前端依赖。修法是让 make build 自带依赖，不再手写。
BANNED_INLINE_PATTERNS = [
    (
        r"^\s*npm install\s*$",
        "inline npm install —— make build 自带 web-build → env-web 依赖，不需要也不应该手写",
    ),
    (
        r"^\s*cd web && npm install",
        "inline 安装 web 依赖 —— 已在 Makefile 的 env-web 目标中，勿重复",
    ),
]


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def test_setup_action_exists() -> None:
    """统一 setup 的 composite action 必须存在。"""
    assert SETUP_ACTION.exists(), f"composite action 缺失：{SETUP_ACTION}"
    doc = _load(SETUP_ACTION)
    assert doc.get("runs", {}).get("using") == "composite", "setup 必须是 composite action"

    steps = doc["runs"]["steps"]
    uses = [s.get("uses", "") for s in steps]
    for required in ("actions/setup-go@", "actions/setup-node@", "actions/setup-python@"):
        assert any(required in u for u in uses), f"composite action 缺少 {required}"


def test_setup_action_has_uv_conditional() -> None:
    """uv 安装必须做成可选输入（with-uv），不是无条件装。

    无条件装会让不需要 Python 的 job 也付安装成本；
    用 curl 装则是上面记录的真实坑。
    """
    doc = _load(SETUP_ACTION)
    uv_steps = [s for s in doc["runs"]["steps"] if "uv" in str(s.get("uses", ""))]
    assert uv_steps, "composite action 中没有 uv 安装步骤"
    assert uv_steps[0].get("if"), "uv 步骤必须带 if 条件（按 with-uv 输入决定是否安装）"
    assert "inputs.with-uv" in uv_steps[0]["if"], (
        f"uv 步骤的 if 应引用 with-uv 输入，实际：{uv_steps[0]['if']}"
    )

    inputs = doc.get("inputs") or {}
    assert "with-uv" in inputs, "缺少 with-uv 输入声明"


@pytest.mark.parametrize("workflow", sorted(WORKFLOW_DIR.glob("*.yml")), ids=lambda p: p.name)
def test_workflows_use_unified_setup(workflow: Path) -> None:
    """每个 workflow 的 job 都必须用统一 setup，且禁止已废弃写法。"""
    text = workflow.read_text(encoding="utf-8")

    for pattern, reason in DEPRECATED_SETUP_PATTERNS:
        hits = [
            f"line {i}" for i, line in enumerate(text.splitlines(), 1) if re.search(pattern, line)
        ]
        assert not hits, f"{workflow.name} 使用了已废弃的 setup 写法：{reason}（{', '.join(hits)}）"

    for pattern, reason in BANNED_INLINE_PATTERNS:
        hits = [
            f"line {i}" for i, line in enumerate(text.splitlines(), 1) if re.search(pattern, line)
        ]
        assert not hits, f"{workflow.name} 含 inline 依赖安装：{reason}（{', '.join(hits)}）"


def test_every_ci_job_has_setup() -> None:
    """CI 里每个 job 都必须显式调用统一 setup。

    security-static job 首跑时完全没有 setup 步骤，导致 uv: command not found。
    这类"忘了写"靠本测试兜住。
    """
    ci = _load(WORKFLOW_DIR / "ci.yml")
    jobs = ci.get("jobs") or {}
    assert jobs, "ci.yml 中没有 job"

    for job_name, job in jobs.items():
        steps = job.get("steps") or []
        uses_setup = any(
            str(step.get("uses", "")).endswith("/.github/actions/setup") for step in steps
        )
        assert uses_setup, (
            f"job '{job_name}' 未调用 ./.github/actions/setup。"
            "每个 job 都必须走统一 setup —— 手写步骤会漏（首跑的真实教训）。"
        )


def test_ci_gates_documented() -> None:
    """ci.yml 必须显式记录尚未自动化的门禁。

    docs/09 §10 第 4 项：未达成项必须说明。
    Q3/Q4/Q5/Q8/Q9 当前无 CI 覆盖，若不在文件里写明，
    读者会以为它们已被覆盖 —— 那正是 P9 文档失真。
    """
    text = (WORKFLOW_DIR / "ci.yml").read_text(encoding="utf-8")
    for gate in ("Q3", "Q4", "Q5", "Q8", "Q9"):
        assert gate in text, (
            f"ci.yml 未提及 {gate}。尚未自动化的门禁必须在文件末尾明确列出，"
            "不能让『看起来全绿』掩盖真实缺口（docs/10 §0 硬要求 3）。"
        )


def test_release_gate_runs_before_build() -> None:
    """Release 的 build 必须依赖 gate（先过门禁才产出二进制）。

    docs/09 R10：不得在未达门禁时进入下一阶段。
    """
    rel = _load(WORKFLOW_DIR / "release.yml")
    build = rel["jobs"]["build"]
    needs = build.get("needs")
    # GitHub Actions 允许 needs 写成标量或列表，归一化成集合再比较。
    if isinstance(needs, str):
        needs = [needs]
    assert needs and "gate" in needs, (
        f"release 的 build job 必须依赖 gate，实际：{build.get('needs')}"
    )
