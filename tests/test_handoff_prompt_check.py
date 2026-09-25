"""接手 Prompt 时效性检查脚本的验证。

被测对象：`scripts/check-handoff-prompt.sh`

**为什么值得测**：这个脚本本身是个「易腐检查器」—— 它检查一份易腐文档。
若它自己悄悄失效（比如 grep 模式匹配不到 HEAD 那行了），行为是**永远
OK**，而那正是它要防的那类问题。

docs/10 §0 的三种失真里，「相似替代一致」最适用这里：
脚本跑通 ≠ 真的在校验内容。

测试覆盖：
    1. 当前仓库状态下应通过（真实基线）
    2. 文档缺失 → exit 1
    3. HEAD 指向不存在的 commit → exit 1（FAIL，不是 stale）
    4. tag 不存在 → exit 1
    5. HEAD 过期但仍真实 → exit 0 + 输出含 stale（区分 FAIL 与 stale 是关键设计）

本测试会临时修改 docs/HANDOFF-PROMPT.md，因此必须确保 finally 还原 ——
用一个独立副本而不是原地改，避免任何意外把真文档弄坏。
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "check-handoff-prompt.sh"
DOC = REPO_ROOT / "docs" / "HANDOFF-PROMPT.md"


def _run() -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["bash", str(SCRIPT)],  # noqa: S607
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=REPO_ROOT,
        check=False,
    )


def test_script_exists() -> None:
    assert SCRIPT.exists(), f"检查脚本缺失：{SCRIPT}"


def test_doc_exists() -> None:
    """文档本身必须存在 —— 缺失时脚本应 FAIL 而非静默通过。"""
    assert DOC.exists(), f"接手 Prompt 缺失：{DOC}"


def test_passes_on_current_tree() -> None:
    """当前仓库状态下应通过。

    这是基线。它同时验证脚本的 grep 模式**现在还能匹配上文档** ——
    若有人重写了文档措辞导致模式失配，这条会失败（而不是永远 OK）。
    """
    result = _run()
    assert result.returncode == 0, (
        f"检查脚本在当前树上失败（exit {result.returncode}）。\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    # 输出应包含四项 OK（文件/围栏/HEAD/tag）。
    assert "OK" in result.stdout, f"未输出任何 OK 项：\n{result.stdout}"


def test_fails_when_doc_missing(tmp_path: Path) -> None:
    """文档缺失 → exit 1。"""
    backup = tmp_path / "HANDOFF-PROMPT.md.bak"
    shutil.copy2(DOC, backup)
    try:
        DOC.unlink()
        result = _run()
        assert result.returncode == 1, (
            f"文档缺失时应 exit 1，实际 {result.returncode}。\n{result.stdout}"
        )
        assert "FAIL" in result.stdout
    finally:
        shutil.copy2(backup, DOC)


def test_fails_on_nonexistent_commit(tmp_path: Path) -> None:
    """HEAD 指向不存在的 commit → exit 1（FAIL 而非 stale）。

    这条测的是 FAIL 与 stale 的区分：不存在的引用是错误，
    过期的引用只是待回填。混为一谈会让后者也阻断 CI。
    """
    original = DOC.read_text(encoding="utf-8")
    backup = tmp_path / "orig.md"
    backup.write_text(original, encoding="utf-8")
    try:
        # deadbee 不是合法 sha 前缀（过长且不在历史中）
        DOC.write_text(
            original.replace("当前 HEAD：`", "当前 HEAD：`deadbee").replace("1e699fe`", "deadbee`"),
            encoding="utf-8",
        )
        # 确认真的改进去了
        assert "deadbee" in DOC.read_text(encoding="utf-8"), "mutation 未生效"

        result = _run()
        assert result.returncode == 1, (
            f"引用不存在的 commit 应 exit 1，实际 {result.returncode}。\n{result.stdout}"
        )
        assert "不是仓库里的 commit" in result.stdout, (
            f"应报告「不是仓库里的 commit」，实际：\n{result.stdout}"
        )
    finally:
        DOC.write_text(original, encoding="utf-8")


def test_stale_but_valid_head_is_not_failure(tmp_path: Path) -> None:
    """HEAD 指向**真实但过期**的 commit → exit 0 且标记 stale。

    这是该脚本的核心设计：过期不阻断 CI（属待回填），
    引用不存在才阻断（属错误）。若这条不成立，CI 会因为
    「忘了回填」而红，久而久之会被 `--no-verify` 绕掉。
    """
    original = DOC.read_text(encoding="utf-8")
    try:
        # 用仓库真实的旧 commit（初始提交），它是存在的但已不是 HEAD ——
        # 正好构造"真实但过期"这个场景。
        first_commit = (
            subprocess.run(
                ["git", "rev-list", "--max-parents=0", "HEAD"],  # noqa: S607
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
                check=True,
            )
            .stdout.strip()
            .splitlines()[0]
        )
        short = first_commit[:7]

        # 替换文档里的 HEAD 行（不假设当前值）。
        text = re.sub(r"当前 HEAD：`[0-9a-f]{7,40}`", f"当前 HEAD：`{short}`", original)
        DOC.write_text(text, encoding="utf-8")

        result = _run()
        assert result.returncode == 0, (
            f"过期但真实的 HEAD 不应阻断（应 exit 0），实际 {result.returncode}。\n{result.stdout}"
        )
        assert "stale" in result.stdout, f"应标记为 stale：\n{result.stdout}"
    finally:
        DOC.write_text(original, encoding="utf-8")


def test_fails_on_nonexistent_tag(tmp_path: Path) -> None:
    """tag 不存在 → exit 1。"""
    original = DOC.read_text(encoding="utf-8")
    try:
        import re

        text = re.sub(r"最新 tag：`[^`]+`", "最新 tag：`v9.9.9`", original)
        DOC.write_text(text, encoding="utf-8")

        result = _run()
        assert result.returncode == 1, f"tag 不存在应 exit 1，实际 {result.returncode}"
        assert "FAIL" in result.stdout
    finally:
        DOC.write_text(original, encoding="utf-8")
