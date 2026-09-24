"""对安全扫描脚本本身做变异验证。

**为什么需要这个测试**（docs/10 §0 的核心问题）：

    自检最大的风险是"自己给自己打高分"。

一个永远返回 0 的扫描脚本比没有脚本更糟 —— 它让"门禁已通过"这句话
看起来有依据。`10` §0 把这类失真命名为「绿灯替代有效」：
测试跑绿了，但没读测试代码，断言可能是空转的。

因此本测试不验证"代码是干净的"，而验证**扫描脚本能抓到违规**：

    注入 → 已知违规代码 → 脚本必须报 FAIL（退出码非 0）

这正是 docs/10 §6 两个强制时点中的第一个：
"写完测试之后、跑测试之前，读一遍测试代码：这些断言真的在验证功能吗？"
"""

from __future__ import annotations

import contextlib
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCAN_SCRIPT = REPO_ROOT / "scripts" / "check-no-bypass.sh"

# 变异用例：每条对应 scripts/check-no-bypass.sh 中的一项规则。
# 字段：规则描述、注入路径、注入内容。每条内容都是**真实的违规形态**，
# 不是随手编的字符串 —— 否则验证不到真实规则。
MUTATIONS: list[tuple[str, str, str]] = [
    (
        "R4 绕过 Evidence Ledger 直赋 CONFIRMED",
        "core/config/mutant_r4.go",
        """package config

// 变异注入：绕过 LedgerService.ValidateAssertion 直赋 CONFIRMED（违反 09 R4）
func mutant() FindingStatus {
	var status FindingStatus
	status = CONFIRMED
	return status
}
""",
    ),
    (
        "R6 agent 自行终止会话",
        "agents/mutant_r6.py",
        '''"""变异注入：agent 自行终止会话（违反 09 R6 / 05 §5.4）"""
import sys


def mutant() -> None:
    sys.exit(0)
''',
    ),
    (
        "P-4 吞掉异常（fail-open）",
        "agents/mutant_p4.py",
        '''"""变异注入：吞掉异常把 fail-closed 变成 fail-open（违反 P-4）"""
def mutant() -> None:
    try:
        risky()
    except: pass
''',
    ),
    (
        "R8 跳过 scope 校验",
        "core/config/mutant_r8.go",
        """package config

// 变异注入：跳过范围校验后继续（违反 09 R8）
func mutant() bool {
	return skipScopeCheck()
}
""",
    ),
    (
        "R5 LLM 输出拼命令行",
        "core/config/mutant_r5.go",
        """package config

import "fmt"

// 变异注入：LLM 输出拼命令行（违反 09 R5）
func mutant(llmOutput string) string {
	return run(fmt.Sprintf("nmap %s", llmOutput))
}
""",
    ),
    (
        "R5 LLM 输出拼命令行（Python f-string）",
        "agents/mutant_r5.py",
        '''"""变异注入：LLM 输出拼命令行（违反 09 R5）"""
def mutant(llm_output: str) -> None:
    run(f"nmap {llm_output}")
''',
    ),
]


def _run_scan() -> subprocess.CompletedProcess[str]:
    """运行扫描脚本，返回进程结果。

    用 errors="replace" 读取输出：脚本里有 ANSI 颜色码，
    Windows 默认的 GBK 编码解不开它们。这不是错误，忽略即可 ——
    这里只关心退出码。
    """
    # S603（untrusted input）/ S607（partial executable path）：
    #   执行的是本仓库自带的 scripts/check-no-bypass.sh，不是外部输入；
    #   bash 故意走 PATH 解析 —— Git Bash 与 Linux 的 bash 路径不同
    #   （/usr/bin/bash vs /bin/bash），写死路径会破坏跨平台。
    #   bandit 是文件级规则，无法按调用点区分来源，因此显式豁免并记录理由。
    #   （docs/09 §R2：豁免需说明理由，不得删除规则本身。）
    return subprocess.run(  # noqa: S603
        ["bash", str(SCAN_SCRIPT)],  # noqa: S607
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=REPO_ROOT,
        check=False,
    )


def _cleanup(paths: list[Path]) -> None:
    for p in paths:
        if p.exists():
            p.unlink()
    # 清掉可能留下的空目录（变异文件若在子目录中）。
    for p in paths:
        # 目录非空（里面还有别的内容）时 rmdir 会失败 —— 那正是期望的行为。
        with contextlib.suppress(OSError):
            p.parent.rmdir()


@pytest.mark.parametrize(
    ("rule", "rel_path", "content"),
    MUTATIONS,
    ids=[m[0] for m in MUTATIONS],
)
def test_scan_detects_injected_violation(
    rule: str,
    rel_path: str,
    content: str,
    tmp_path: Path,
) -> None:
    """注入一条真实违规，扫描脚本必须以非零码退出。

    若这条测试失败，说明对应规则形同虚设 —— 那是比漏洞更严重的问题，
    因为它让其他所有"门禁通过"的结论都失去依据。
    """
    target = REPO_ROOT / rel_path
    created: list[Path] = []
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        created.append(target)

        result = _run_scan()

        assert result.returncode != 0, (
            f"扫描脚本未能发现注入的违规：{rule}\n"
            f"注入位置：{rel_path}\n"
            f"stdout:\n{result.stdout}\n"
            "说明：对应规则已失效。请检查 scripts/check-no-bypass.sh 的 pattern，"
            "而不是绕过本测试（docs/09 §R3）。"
        )
    finally:
        _cleanup(created)


def test_scan_clean_on_untouched_tree() -> None:
    """反向验证：干净树上扫描脚本必须通过。

    没有这条，就会出现"脚本把所有代码都判为违规"也能让上面全绿的情况。
    """
    result = _run_scan()
    assert result.returncode == 0, (
        "扫描脚本在干净树上报告了违规。请逐条核对下列命中，"
        "确认为真实违规则修代码，确认为误报则在该行加注释说明"
        "（不得删除规则）：\n" + result.stdout
    )


def test_scan_script_exists_and_is_bash() -> None:
    """扫描脚本必须存在。缺失时 fail-closed：本测试失败，不允许静默跳过。"""
    assert SCAN_SCRIPT.exists(), (
        f"{SCAN_SCRIPT} 不存在 —— `make check-no-bypass` 会在此时变成空操作，"
        "这正是 docs/09 §R2 禁止的'削弱门禁'。"
    )
    head = SCAN_SCRIPT.read_text(encoding="utf-8")[:200]
    assert "bash" in head, "扫描脚本必须是 bash 脚本（Git Bash / Linux 通用）"


def test_scan_is_wired_into_makefile() -> None:
    """扫描必须挂到 Makefile，否则没人会跑它（docs/10 §8 的 CI 固化原则）。"""
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "check-no-bypass" in makefile, (
        "Makefile 中未找到 check-no-bypass 目标 —— "
        "一个不挂进构建流程的检查等于不存在（docs/10 §8）。"
    )
    assert "scripts/check-no-bypass.sh" in makefile, (
        "Makefile 的 check-no-bypass 目标未实际调用扫描脚本。"
    )


def test_mutations_cover_red_lines() -> None:
    """变异用例必须覆盖 09 的红线中可用静态检测表达的那几条。

    这条测试防止"变异集被悄悄裁掉"—— 如果哪天 MUTATIONS 只剩一两条，
    门禁就不再验证其余红线，而这个变化很难被察觉。
    """
    rules = {rule.split()[0] for rule, _, _ in MUTATIONS}
    required = {"R4", "R5", "R6", "P-4", "R8"}
    assert rules == required, (
        f"变异用例覆盖 {sorted(rules)}，应为 {sorted(required)}。"
        "减少变异用例 = 削弱门禁（docs/09 §R2）。"
    )
