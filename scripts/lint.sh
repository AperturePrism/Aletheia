#!/usr/bin/env bash
# Q7：Lint / 静态检查 —— 无 error。
#
# docs/04 §6 Q7 原文：
#     Lint / 静态检查 ｜ 无 error ｜ 阻断合并
#
# 为什么单独一个脚本：Makefile 的 recipe 用 `\` 续接 shell 时，
# Git Bash 对 if/else 与引号的处理极不可靠（报
# "unexpected EOF while looking for matching `"'"）。
# 脚本有正常的语法检查，错误行号准确，且可被 CI 与本地直接调用。
#
# 覆盖四侧：
#   1. Go    —— go vet + gofmt（含生成代码）
#   2. Python—— ruff check + ruff format --check
#   3. Web   —— ESLint + tsc --noEmit
#   4. proto —— buf lint
#
# 用法：scripts/lint.sh
# 退出码：0 = 全部通过；1 = 存在 error。

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

fail=0

pass() { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
fail_msg() {
    printf '  \033[31mFAIL\033[0m %s\n' "$1"
    shift
    printf '%s\n' "$@" | sed 's/^/         /'
    fail=1
}

# 平台相关的 Python 路径。
if [ -f ".venv/Scripts/python.exe" ]; then
    PY=.venv/Scripts/python.exe
else
    PY=.venv/bin/python
fi

# ---- 1. Go ----
echo "== 1/4 Go: go vet =="
# 显式限定 ./cmd/... ./core/...，不用 ./... ——
# web/node_modules 下的第三方 Go 包没有自己的 go.mod，会被算进本模块。
# 理由详见 go.mod 的「Go 模块边界」段。
if out=$(go vet ./cmd/... ./core/... 2>&1); then
    pass "go vet"
else
    fail_msg "go vet" "$out"
fi

echo "== 1/4 Go: gofmt =="
# gofmt -l 列出需要格式化的文件（不修改）。空输出 = 全部合规。
# 同样限定 core 与 cmd（与 Makefile 的 GO_PKGS 范围一致）。
unformatted=$(gofmt -l core cmd 2>/dev/null)
if [ -n "$unformatted" ]; then
    fail_msg "gofmt：以下文件格式不一致" "$unformatted" \
        "        修复：gofmt -w <file>"
else
    pass "gofmt"
fi

# ---- 2. Python ----
echo "== 2/4 Python: ruff check =="
if out=$("$PY" -m ruff check . 2>&1); then
    pass "ruff check"
else
    fail_msg "ruff check" "$out"
fi

echo "== 2/4 Python: ruff format --check =="
if out=$("$PY" -m ruff format --check . 2>&1); then
    pass "ruff format"
else
    fail_msg "ruff format" "$out" "        修复：ruff format ."
fi

# ---- 3. Web ----
echo "== 3/4 Web: ESLint =="
if out=$(cd web && npm run lint 2>&1); then
    pass "eslint"
else
    fail_msg "eslint" "$out"
fi

echo "== 3/4 Web: tsc --noEmit =="
if out=$(cd web && npm run typecheck 2>&1); then
    pass "tsc --noEmit"
else
    fail_msg "tsc" "$out"
fi

# ---- 4. proto ----
echo "== 4/4 proto: buf lint =="
if out=$(node_modules/.bin/buf lint proto/ 2>&1); then
    pass "buf lint"
else
    fail_msg "buf lint" "$out"
fi

echo ""
if [ "$fail" -ne 0 ]; then
    cat <<'MSG'
Lint 未通过。依据 docs/04 §6：Q7 失败 → 阻断合并。

注意：不得通过"加 ignore 注释"绕过真实问题。
若确为误报，请在该行加 -- noqa: <规则号> 并说明理由（见 docs/09 §R2）。
MSG
    exit 1
fi

echo "Q7 lint 全部通过。"
