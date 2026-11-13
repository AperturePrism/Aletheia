#!/usr/bin/env bash
# 保证 cmd/alethd/webdist 存在且非空（go:embed all:webdist 的硬要求）。
#
# 为什么需要：396146a 起 webdist 整目录被 .gitignore（构建产物不弄脏
# 工作区），占位页改由 cmd/alethd/webplaceholder/（已入库）在构建时
# 复制。make go-build 经 embed-web.sh 自然就位；但 test-go / lint /
# coverage / redline 这些不经过 go-build 的路径，在干净 checkout（CI）
# 上会因 embed 空目录直接编译失败 —— main 回归（PR #24 首次暴露）。
#
# 用法：scripts/webdist-ensure.sh（Makefile 目标 webdist-ensure 调用）
# 退出码：0 = 就位（已有真实 UI 或已复制占位页）；1 = 致命错误。

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TARGET="cmd/alethd/webdist/index.html"
PLACEHOLDER="cmd/alethd/webplaceholder/index.html"

if [ -f "$TARGET" ]; then
    echo "webdist-ensure: index.html 已存在（真实 UI 或既有占位页），跳过"
    exit 0
fi

if [ ! -f "$PLACEHOLDER" ]; then
    echo "FATAL: $PLACEHOLDER 不存在 —— 占位页源文件缺失（仓库损坏？）" >&2
    exit 1
fi

mkdir -p cmd/alethd/webdist
cp "$PLACEHOLDER" "$TARGET"
echo "webdist-ensure: 占位页就位（真实 UI 需 make web-build && make go-build）"
