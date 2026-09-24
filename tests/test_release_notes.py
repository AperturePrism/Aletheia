"""Release Notes 提取脚本的测试。

被测对象：`scripts/extract-release-notes.py`

**为什么值得测**：这个脚本决定每次 Release 的说明文字从哪来。
它若悄悄失效（比如 CHANGELOG 改了标题层级就匹配不上），后果是：
Release 带一份空白或错误版本的说明上线，而流程看起来"成功了"。

这正是 docs/10 §0 列的第二种失真 —— 「绿灯替代有效」：
命令跑通了，但产出不是你以为的东西。

测试覆盖四类：
    1. 精确版本段命中
    2. minor 形式命中（0.1.0 → 0.1）
    3. Unreleased 兜底
    4. 完全找不到 → exit 2（不是静默空输出）
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "extract-release-notes.py"
CHANGELOG = REPO_ROOT / "docs" / "CHANGELOG.md"


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """运行子进程并以 UTF-8 解码输出。

    必须传 `-X utf8`：Windows 上 Python 默认按 locale（本机 GBK）编码 stdout，
    不指定时中文会变成乱码，断言就会误判为"内容不对"。
    这不是被测脚本的问题，是测试读取方式的问题 —— 但两者都要修，
    否则这条测试在 Linux 绿、在 Windows 红。
    """
    return subprocess.run(  # noqa: S603
        [sys.executable, "-X", "utf8", *argv],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=REPO_ROOT,
        check=False,
    )


def run(version: str, changelog: Path) -> subprocess.CompletedProcess[str]:
    return _run([str(SCRIPT), version, str(changelog)])


def test_script_exists() -> None:
    assert SCRIPT.exists(), f"提取脚本缺失：{SCRIPT}"


def test_extracts_unreleased_when_no_version_section() -> None:
    """仓库当前 CHANGELOG 用 [Unreleased] 承载 I0，应能兜底命中。

    这是当前真实状态：I0 完成但尚未打 tag，所以没有 [0.1.0] 段。
    """
    result = run("0.1.0", CHANGELOG)
    assert result.returncode == 0, f"提取失败：{result.stderr}"

    out = result.stdout
    # 必须提到 I0，而不是抓到了不相干的段落。
    assert "I0" in out, f"提取到的内容不含 I0，疑似抓错段落：\n{out[:300]}"
    assert len(out) > 200, f"提取内容过短（{len(out)} 字符），疑似空壳"


def test_exact_version_section(tmp_path: Path) -> None:
    """CHANGELOG 有精确版本段时应优先命中它，而不是 Unreleased。"""
    doc = tmp_path / "CHANGELOG.md"
    doc.write_text(
        """# Changelog

## [Unreleased]

### 未发布的东西

- 不该被抓到

## [0.2.0]

### 已发布的东西

- 正确内容 A
- 正确内容 B

## [0.1.0]

### 更早的版本

- 旧内容
""",
        encoding="utf-8",
    )

    result = run("0.2.0", doc)
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "正确内容 A" in out, f"未命中 [0.2.0] 段：\n{out}"
    assert "不该被抓到" not in out, "抓到了 Unreleased 段 —— 优先级错误"
    assert "旧内容" not in out, "抓到了 [0.1.0] 段 —— 边界错误（应在下一个 ## 处停止）"


def test_minor_form_fallback(tmp_path: Path) -> None:
    """Keep a Changelog 允许 `## [0.2]`（省略 patch），应能命中。"""
    doc = tmp_path / "CHANGELOG.md"
    doc.write_text(
        """## [Unreleased]

- 不该被抓到

## [0.2]

### minor 段内容

- 目标内容
""",
        encoding="utf-8",
    )
    result = run("0.2.0", doc)
    assert result.returncode == 0, result.stderr
    assert "目标内容" in result.stdout
    assert "不该被抓到" not in result.stdout


def test_missing_section_exits_nonzero(tmp_path: Path) -> None:
    """完全找不到段落必须 exit 2，而不是静默输出空内容。

    这是本条测试的重点：空 Notes 的 Release 比失败的 Release 更糟 ——
    失败会被看见，空白不会。
    """
    doc = tmp_path / "CHANGELOG.md"
    doc.write_text("## [1.0.0]\n\n- 无关内容\n", encoding="utf-8")
    result = run("7.7.7", doc)
    assert result.returncode == 2, (
        f"期望 exit 2（找不到段落），实际 {result.returncode}。"
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    # 错误信息要说明该做什么，而不是只说 "error"。
    assert "CHANGELOG" in result.stderr


def test_output_file_mode(tmp_path: Path) -> None:
    """写文件模式：stdout 保持干净，内容进文件。"""
    out = tmp_path / "notes.md"
    result = _run([str(SCRIPT), "0.1.0", str(CHANGELOG), str(out)])
    assert result.returncode == 0, result.stderr
    assert out.exists(), "未写出文件"
    text = out.read_text(encoding="utf-8")
    assert "I0" in text


def test_missing_changelog_exits_one(tmp_path: Path) -> None:
    """CHANGELOG 文件本身不存在 → exit 1，与"段落找不到"的 2 区分开。"""
    result = run("0.1.0", tmp_path / "nonexistent.md")
    assert result.returncode == 1


@pytest.mark.parametrize("version", ["v0.1.0", "0.1.0"])
def test_v_prefix_normalized(version: str) -> None:
    """带不带 v 前缀都应归一化处理 —— tag 是 v0.1.0，CHANGELOG 是 0.1.0。"""
    result = run(version, CHANGELOG)
    assert result.returncode == 0, result.stderr
