"""仓库卫生测试：构建产物不得污染工作区。

# 为什么需要这个文件

2026-11-02 检查发现一个**每次构建都会复发**的问题：

    $ make build          # 或 make gate
    $ git status
     M cmd/alethd/webdist/index.html

根因是设计上的一个必然副作用（不是偶发脏文件）：

* `.gitignore` 用 `cmd/alethd/webdist/*` + `!.../index.html` **跟踪**了
  一份 index.html，本意是"当占位页，保证 go:embed 有文件可嵌"；
* 但 `scripts/embed-web.sh` 会 `rm -rf webdist` 再复制 `web/dist` 的产物，
  于是被跟踪的 index.html **每次都被覆盖** → 工作区必脏。

连带三个后果：

1. **提交的单二进制 UI 是旧的**：仓库里那份 index.html 是 2026-10-12 的
   构建产物，引用的 `/assets/index-CxouJY5H.js` 早已不存在；
2. **`git commit -a` 会误提交**真实构建产物，破坏"未构建时明确告知"
   的设计意图；
3. **占位机制形同虚设**：真正的占位页
   `cmd/alethd/webplaceholder/index.html` 虽然入库，但构建流程从不使用它。

修法：占位页独立存放且不被构建覆盖，`cmd/alethd/webdist/` 整目录忽略。

# 这些断言为什么是"契约级"的

本项目反复踩过同一类坑：**检查项与它声称保证的事实脱节**
（`docs/10` §0）。上面三条后果都不会让任何测试变红 —— 它们只是让
工作区变脏、让用户看到一个跑不起来的假 UI。因此需要显式断言，
否则同一个错误会被再次引入。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
EMBED_DIR = REPO_ROOT / "cmd" / "alethd" / "webdist"
PLACEHOLDER = REPO_ROOT / "cmd" / "alethd" / "webplaceholder" / "index.html"
EMBED_SCRIPT = REPO_ROOT / "scripts" / "embed-web.sh"

pytestmark = pytest.mark.redline


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    """在仓库根执行 git（cwd 固定，避免测试从别处运行时误判）。

    noqa 理由（docs/09 §R2：不得用 ignore 掩盖真实问题，但需对误报说明）：
    · S603 要求"审计不可信输入"——这里可变参数只来自本文件内的字面量，
      不存在外部输入；
    · S607 要求可执行文件的绝对路径——`git` 由 PATH 提供，是测试环境
      的既定契约（CI 与本地都必须有 git，否则整个仓库无法工作）。
      写死绝对路径反而会让测试在别的机器上失败。
    """
    return subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


# ---------------------------------------------------------------------------
# 构建产物必须是"完全被忽略"的
# ---------------------------------------------------------------------------


def test_webdist_is_fully_gitignored() -> None:
    """★ `cmd/alethd/webdist/index.html` 必须被 git 忽略。

    这是本轮修复的核心。此前它被 `!` 规则**反向跟踪**，于是
    `make build` 一次就脏一次。断言用 `git check-ignore` 而不是
    读 `.gitignore` 文本 —— 后者无法表达"规则叠加后的实际效果"
    （正是 `*` + `!` 的组合骗过了所有人的眼睛）。
    """
    target = EMBED_DIR / "index.html"
    result = _git("check-ignore", "-q", str(target))
    assert result.returncode == 0, (
        f"{target.relative_to(REPO_ROOT)} 未被忽略 —— "
        "构建产物会被跟踪，导致每次 make build 后工作区变脏"
    )


def test_webdist_dir_is_not_tracked() -> None:
    """★ webdist 目录下不得有任何被 git 跟踪的文件。

    与上一条互补：`check-ignore` 只看忽略规则，而这里的
    `git ls-files` 看**索引里实际有什么** —— 若历史遗留的跟踪状态
    没被清除（`git rm --cached` 漏做），忽略规则不会自动生效。
    """
    result = _git("ls-files", "cmd/alethd/webdist/")
    tracked = [ln for ln in result.stdout.splitlines() if ln.strip()]
    assert not tracked, "webdist 下仍有被跟踪的文件（应已 git rm --cached）：\n  " + "\n  ".join(
        tracked
    )


def test_embed_output_is_reproducible_after_build() -> None:
    """构建产物存在时，它必须是**当前**构建的输出（不是仓库里的旧文件）。

    本条不重跑构建（那会依赖 node 环境），而是断言：
    如果 webdist/index.html 存在且 web/dist 也存在，则两者内容一致 ——
    即"嵌进去的确实是 web/dist 的东西"。
    """
    dist_index = REPO_ROOT / "web" / "dist" / "index.html"
    embed_index = EMBED_DIR / "index.html"
    if not (dist_index.exists() and embed_index.exists()):
        pytest.skip("web/dist 或 webdist 不存在（未构建），跳过一致性检查")
    assert embed_index.read_text(encoding="utf-8") == dist_index.read_text(encoding="utf-8"), (
        "webdist/index.html 与 web/dist/index.html 不一致 —— 嵌入的是旧构建"
    )


# ---------------------------------------------------------------------------
# 占位页必须真实存在、入库、且是**真占位页**
# ---------------------------------------------------------------------------


def test_placeholder_exists_and_is_tracked() -> None:
    """占位页必须存在且入库（`go:embed all:webdist` 需要至少一个文件）。"""
    assert PLACEHOLDER.exists(), (
        f"占位页缺失：{PLACEHOLDER.relative_to(REPO_ROOT)} —— "
        "未构建 WebUI 时 go:embed 将无文件可嵌，编译直接失败"
    )
    result = _git("ls-files", str(PLACEHOLDER.relative_to(REPO_ROOT)))
    assert result.stdout.strip(), "占位页未入库 —— 干净克隆后编译会失败"


def test_placeholder_is_a_real_notice_not_a_stale_build() -> None:
    """★ 占位页必须是**真占位页**，不能是旧构建产物。

    历史教训：仓库里那份"占位页"其实是 2026-10-12 的构建产物，
    引用了早已不存在的 `/assets/index-CxouJY5H.js` —— 用户打开后
    看到的是白屏，而不是"WebUI 未构建，请 make build"的提示。

    断言两件事：
      1. 文案明确告知未构建；
      2. 不引用任何打包产物 `/assets/...`（那正是旧构建产物的特征）。
    """
    html = PLACEHOLDER.read_text(encoding="utf-8")
    assert "未构建" in html, "占位页未告知「未构建」——用户会以为是程序坏了"
    assert "make build" in html, "占位页未给出构建命令"
    assert "/assets/" not in html, (
        "占位页引用了 /assets/ 打包产物 —— 它其实是构建产物而非占位页，未构建时会白屏"
    )


def test_embed_script_uses_placeholder_fallback() -> None:
    """★ embed 脚本必须在 web/dist 缺失时复制占位页。

    此前脚本只是 `echo WARN; exit 1`，把"保证有文件可嵌"的责任
    推给了"仓库里跟踪一份 index.html"—— 而那正是弄脏工作区的根源。
    断言脚本确实引用了 webplaceholder 路径，堵住这个回退。
    """
    script = EMBED_SCRIPT.read_text(encoding="utf-8")
    assert "webplaceholder" in script, (
        "embed-web.sh 未使用占位页 —— web/dist 缺失时 go:embed 会没有文件可嵌"
    )
