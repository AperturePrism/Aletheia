#!/usr/bin/env bash
# 把 WebUI 构建产物复制到 Go 的 embed 目录。
#
# 为什么单独一个脚本（而非 Makefile recipe）：
#   Makefile 的 recipe 用 `\` 续接多行 shell，Git Bash 下对 if/else 与
#   引号的处理极易出错（报 "unexpected EOF while looking for matching `"'"）。
#   脚本有正常的语法检查，出错了行号准确。
#
# 用法：scripts/embed-web.sh
# 退出码：0 = 已嵌入（含占位页面的情况）；1 = 致命错误。

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WEB_DIST="web/dist"
EMBED_DIR="cmd/alethd/webdist"

echo "== WebUI 产物复制到 embed 目录 =="

# 每次重建 embed 目录：残留的旧资产会让"看起来是最新构建"但实际是旧的。
rm -rf "$EMBED_DIR"
mkdir -p "$EMBED_DIR"

if [ -f "$WEB_DIST/index.html" ]; then
    cp -r "$WEB_DIST"/. "$EMBED_DIR"/
    count=$(find "$EMBED_DIR" -type f | wc -l)
    echo "  embedded web/dist → $EMBED_DIR ($count files)"
else
    # ★ 未构建时嵌入**入库的真占位页**（2026-11-02 修正）。
    #
    # 此前这里只打印 WARN 然后 exit 1，靠"仓库里跟踪了一份旧的
    # webdist/index.html"来保证 go:embed 有文件可嵌。那个做法有两个问题：
    #   1. 被跟踪的 index.html 每次构建都会被覆盖 → 工作区必脏；
    #   2. 它其实是**旧构建产物**（引用早已不存在的 /assets/index-*.js），
    #      既不是占位页也跑不起来，等于给用户一个"假 UI"。
    #
    # 现在改为从 cmd/alethd/webplaceholder/ 复制真占位页：
    # 它明确写着"WebUI 尚未构建 / 请执行 make build"，且不受构建影响。
    #
    # 仍然 exit 1：未构建 WebUI 是**降级**，要让调用方知道（P-4 fail-closed
    # 的同一精神 —— 不静默给一个空壳）。Makefile 里 go-build 对此有显式容忍。
    PLACEHOLDER="cmd/alethd/webplaceholder"
    if [ -f "$PLACEHOLDER/index.html" ]; then
        cp -r "$PLACEHOLDER"/. "$EMBED_DIR"/
        echo "  WARN: $WEB_DIST 不存在 —— 已嵌入占位页（会明确告知 WebUI 未构建）"
        echo "        请先执行 make web-build 以获得真实 UI。"
    else
        # 连占位页都没有 → 这是仓库损坏（该文件入库），不能静默。
        echo "  ERROR: $WEB_DIST 与 $PLACEHOLDER/index.html 均不存在" >&2
        echo "         占位页应入库（go:embed all:webdist 需要至少一个文件）。" >&2
        exit 1
    fi
    exit 1
fi
