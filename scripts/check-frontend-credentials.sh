#!/usr/bin/env bash
# Q12：前端无法直接访问真实凭据（静态检查侧）。
#
# docs/04 §6 Q12 原文：
#     前端无法直接访问真实凭据（凭据经 Gateway 脱敏）｜ 静态检查 + 抓包验证
# docs/07 §T5.3：
#     界面直接持有真实 IP/凭据 → 通过浏览器扩展/调试工具泄漏。
#     凭据一律经 Privacy Gateway 脱敏后才进前端。
#
# 本脚本只覆盖"静态检查"那一半。抓包验证需要跑通完整会话（I3 起）。
#
# 检查两类：
#   1. 硬编码凭据（password/secret/token/api_key 直接赋字面量）
#   2. 硬编码的内部 IP/域名（前端不应知道真实目标）
#
# 退出码：0 = 未发现；1 = 发现疑似硬编码。

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WEB_SRC="web/src"
fail=0

echo "== Q12：前端凭据静态检查 =="

# 1) 硬编码凭据。
# 排除明显的占位/示例值：placeholder、example、dummy、REDACTED、fake、
# invalid（测试用的 example.invalid 域名）、CHANGE_ME。
hits=$(grep -rnE \
    '(password|passwd|secret|api[_-]?key|access[_-]?token|bearer)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{6,}' \
    --include='*.ts' --include='*.tsx' "$WEB_SRC" 2>/dev/null \
    | grep -viE 'placeholder|example|dummy|redacted|fake|invalid|change.?me|your[-_]' \
    || true)

if [ -n "$hits" ]; then
    printf '  \033[31mFAIL\033[0m 前端源码中发现疑似硬编码凭据：\n'
    printf '%s\n' "$hits" | sed 's/^/         /'
    fail=1
else
    printf '  \033[32mOK\033[0m   无硬编码凭据\n'
fi

# 2) 硬编码内部网络地址。
# 允许 127.0.0.1（默认监听地址，见 docs/06 §5.1）与 example.invalid / example.com
# （文档示例域名）。其余私有 IP 一律视为泄漏。
ip_hits=$(grep -rnE \
    '\b(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b' \
    --include='*.ts' --include='*.tsx' "$WEB_SRC" 2>/dev/null \
    | grep -vE '127\.0\.0\.1' \
    || true)

if [ -n "$ip_hits" ]; then
    printf '  \033[31mFAIL\033[0m 前端源码中出现内网 IP（应经 Gateway 脱敏为 token）：\n'
    printf '%s\n' "$ip_hits" | sed 's/^/         /'
    fail=1
else
    printf '  \033[32mOK\033[0m   无内网 IP\n'
fi

# 3) 不得出现把真实值写进 localStorage/sessionStorage 的模式。
# T5.3 的另一个面：浏览器存储可被同机进程与扩展读取。
store_hits=$(grep -rnE \
    '(localStorage|sessionStorage)\.setItem\([^,]+,\s*[^)]*(password|credential|secret|token)' \
    --include='*.ts' --include='*.tsx' "$WEB_SRC" 2>/dev/null \
    || true)

if [ -n "$store_hits" ]; then
    printf '  \033[31mFAIL\033[0m 前端把凭据写入浏览器存储（可被同机进程读取）：\n'
    printf '%s\n' "$store_hits" | sed 's/^/         /'
    fail=1
else
    printf '  \033[32mOK\033[0m   凭据未写入浏览器存储\n'
fi

echo ""
if [ "$fail" -ne 0 ]; then
    cat <<'MSG'
Q12 未通过。依据 docs/07 §T5.3 与 docs/04 §6：Q12 失败 → 阻断合并。
MSG
    exit 1
fi

echo "Q12 静态检查通过。"
