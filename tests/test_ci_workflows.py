"""CI 工作流的结构完整性测试。

**为什么值得测**：CI 首跑与二跑共三次失败，全部源于"某个 job 漏了某步 setup"
或"inline 写了已经过时的做法"。这类问题在本地永远发现不了 ——
本地依赖早已装好，只有干净环境会暴露。

把"每个 job 都用了统一 setup"变成断言后，新增 job 时漏 setup 会立刻红灯，
而不是等下一次 push 到 GitHub 才失败。

Release 首跑（v0.1.0）又暴露一类：**windows runner 默认 shell 是 PowerShell**，
bash 语法的 step 不声明 `shell: bash` 就 ParserError ——
而 Linux/macOS runner 默认就是 bash，所以只有 Windows 挂。
这类平台差异同样只有真跑才暴露，因此也有对应断言。

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


# ---------------------------------------------------------------------------
# ★ 最小权限（docs/07 §T6「CI 供应链 → CI 凭据最小权限」）
# ---------------------------------------------------------------------------

#: 每个 workflow 允许的**最大**权限。
#:
#: 为什么需要这张表而不是"一律 contents: read"：
#: `release.yml` 创建 Release 与上传资产，**确实需要** `contents: write`。
#: 无差别要求 read 会逼着人加例外注释，而例外注释不会被检查 ——
#: 于是约束退化成"写上就好"。显式列白名单让"某个文件需要什么权限"
#: 成为一处可审阅的事实。
#:
#: 值为 `None` 表示"该文件不得声明 permissions"（暂无此类文件）。
ALLOWED_WORKFLOW_PERMISSIONS: dict[str, dict[str, str]] = {
    "ci.yml": {"contents": "read"},
    # release.yml 需要三项，各有明确理由：
    #   · contents: write —— 创建 Release 与上传资产
    #   · id-token: write —— SLSA provenance 用 OIDC 向 Sigstore 换短期证书
    #     （docs/07 §T6「构建产物签名」）。它**不**授予仓库写权限，
    #     但可换取云凭据，因此仍需登记与审阅。
    #   · attestations: write —— attest-build-provenance 把 attestation
    #     写入 GitHub 的 attestation 存储（v0.6.0 首跑失败的修复：
    #     只有 id-token 时 persist 阶段报 Resource not accessible）。
    #     同样不授予仓库写权限，但写入不可变的构建元数据，需登记。
    "release.yml": {"contents": "write", "id-token": "write", "attestations": "write"},
}

#: 绝不接受的权限（无论哪个 workflow）。
#:
#: `write-all` 与未声明的默认权限是同一类问题：给了远超需要的范围。
#: `id-token: write` 单独列出是因为它可换取云凭据 —— 本项目不需要。
FORBIDDEN_PERMISSION_VALUES = {"write-all"}


@pytest.mark.parametrize("workflow", sorted(WORKFLOW_DIR.glob("*.yml")))
def test_workflow_declares_minimal_permissions(workflow: Path) -> None:
    """★ 每个 workflow 必须**显式**声明 permissions，且不超出白名单。

    背景（`docs/07` §T6「CI 供应链」的缓解措施：
    "CI 凭据最小权限"）：`ci.yml` 此前**没有 permissions 块** ——
    那时每个 job 拿到的是仓库默认权限（历史上是 read-write）。

    为什么这不是形式主义：CI 会执行 PR 里的代码，而 PR 可能来自 fork。
    权限过大时，一个被投毒 PR 的构建脚本就能用 `GITHUB_TOKEN`
    推提交或篡改 Release。最小权限把这条路径的收益降到接近零。

    断言方式：**未声明即失败**（而不是"声明了才检查"）——
    因为"忘了声明"与"故意放宽"的后果相同，都应红灯。
    """
    doc = _load(workflow)
    perms = doc.get("permissions")

    assert perms is not None, (
        f"{workflow.name} 未声明 permissions —— 会拿到仓库默认权限。\n"
        "docs/07 §T6 要求「CI 凭据最小权限」；请显式写 `permissions: contents: read`"
    )

    # `permissions: read-all` / `write-all` 的标量写法。
    if isinstance(perms, str):
        assert perms not in FORBIDDEN_PERMISSION_VALUES, (
            f"{workflow.name} 声明了 `permissions: {perms}` —— 范围远超需要"
        )
        # read-all 也不算最小权限：它给出所有 scope 的读权限，
        # 而 CI 只需要读代码。
        assert perms != "read-all", (
            f"{workflow.name} 用了 `read-all`，应逐项声明（如 contents: read）"
        )
        return

    allowed = ALLOWED_WORKFLOW_PERMISSIONS.get(workflow.name)
    assert allowed is not None, (
        f"{workflow.name} 不在 ALLOWED_WORKFLOW_PERMISSIONS 白名单里。\n"
        "新增 workflow 时请一并登记它**需要**的权限，并说明理由 —— "
        "未经审阅的权限声明容易过宽。"
    )

    for scope, level in perms.items():
        assert scope in allowed, (
            f"{workflow.name} 声明了未登记的权限 `{scope}: {level}`。\n"
            f"已登记：{allowed}。若确实需要，请更新白名单并说明理由。"
        )
        assert level == allowed[scope], (
            f"{workflow.name} 的 `{scope}` 权限是 {level}，"
            f"但登记的（也是最小需要的）是 {allowed[scope]}"
        )


def test_release_needs_write_and_ci_does_not() -> None:
    """★ 对照断言：两个 workflow 的权限必须**不同**。

    若两者相同，说明至少有一处过宽或过窄：
    · CI 要到 write → 过宽（它只读代码）
    · Release 只到 read → 过窄（它创建 Release 与上传资产）

    这条断言的价值是把"权限与职责匹配"变成可检查的事实，
    而不是靠"大概写对了"。
    """
    ci = _load(WORKFLOW_DIR / "ci.yml").get("permissions", {})
    rel = _load(WORKFLOW_DIR / "release.yml").get("permissions", {})
    assert ci != rel, "ci.yml 与 release.yml 的权限完全相同 —— 至少一处与职责不符"
    assert ci.get("contents") == "read", f"ci.yml 应只需读：{ci}"
    assert rel.get("contents") == "write", f"release.yml 需要写：{rel}"


def test_no_workflow_grants_write_all() -> None:
    """任何 workflow 都不得声明 `write-all`。

    单独一条（而非并入上面的参数化用例）是为了让失败信息直接点出
    这个具体的高危写法 —— 它是供应链攻击里收益最大的一类配置。
    """
    for workflow in sorted(WORKFLOW_DIR.glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        assert "write-all" not in text, (
            f"{workflow.name} 出现 `write-all` —— docs/07 §T6 明确要求最小权限"
        )


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


def test_windows_steps_declare_bash_shell() -> None:
    """含 windows runner 的 job，其 bash 语法的 step 必须显式 shell: bash。

    v0.1.0 Release 首跑的实测失败：ParserError 指向一个 .ps1 文件。
    根因：GitHub 的 windows-latest 默认 shell 是 PowerShell，
    而该 step 用的是 bash 语法（行尾续行、POSIX test 的中括号、ls -lh）。
    Linux/macOS runner 默认就是 bash，所以**只有 Windows 挂** ——
    这类平台差异在本地与 Linux CI 上都发现不了。

    判定"用了 bash 语法"的方式：找 bash 特有构造。这不如真解析可靠，
    但对 workflow 这类配置文件够用，且比"等 Windows 挂了再说"早得多。
    """
    rel = _load(WORKFLOW_DIR / "release.yml")
    offenders: list[str] = []

    # bash 特有构造。命中任一并缺 shell: bash 即视为隐患。
    #
    # 注：不把 "反斜杠续行" 列进去 —— YAML 解析后 block scalar 里的续行
    # 已变成真实换行，那个字面量匹配不到。用 POSIX test / coreutils
    # 这些能稳定命中的标记，够了。
    bash_markers = (
        "if [ ",  # POSIX test
        'EXT="',  # bash 变量赋值风格
        "ls -",  # coreutils
        "$((",  # bash 算术
        "|| true",  # bash 惯用法
    )

    for job_name, job in (rel.get("jobs") or {}).items():
        runs_on = str(job.get("runs-on", ""))
        # 只检查会落到 Windows 的 job。
        if "windows" not in runs_on and "matrix.runner" not in runs_on:
            continue

        for step in job.get("steps") or []:
            if "run" not in step:
                continue
            run_text = str(step["run"])
            if not any(m in run_text for m in bash_markers):
                continue
            if step.get("shell") != "bash":
                step_name = step.get("name", "(unnamed)")
                offenders.append(f"job '{job_name}' step '{step_name}'")

    assert not offenders, (
        "以下 step 用了 bash 语法但未声明 shell: bash，在 windows runner 上会 "
        "ParserError（默认 shell 是 PowerShell）：\n  "
        + "\n  ".join(offenders)
        + "\n  修复：加 shell: bash"
    )
