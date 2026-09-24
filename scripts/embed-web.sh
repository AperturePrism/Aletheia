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
    # 占位页面（cmd/alethd/webdist 下的 index.html）由 `make go-build` 的
    # 前置步骤恢复。这里显式说明，避免使用者以为构建成功但 UI 是旧的。
    echo "  WARN: $WEB_DIST 不存在 —— 请先执行 make web-build"
    echo "        当前将使用占位页面（它会明确告知 WebUI 未构建）。"
    exit 1
fi
