#!/usr/bin/env bash
# Q2 门禁（docs/04 §6）：解析器行覆盖率 ≥ 90%。
#
# 口径：core/ingest/**（适配器 + 解析器）与 core/spectrum/**（归一化 + 折叠）。
# core/ingest/testutil 是测试辅助包（只被其他包的测试调用），不属于
# 「解析器」范畴，从统计中排除；排除由本脚本完成，不依赖调用方传参。
#
# 输出：总量与低于 75% 的函数清单（便于定位短板）。
# 注意：go 命令必须限定 GO_PKGS 集合（docs/iterations/I0-交接.md 环境坑 #3）。
set -uo pipefail
cd "$(dirname "$0")/.."

THRESHOLD="${1:-90}"
PROFILE="$(mktemp)"
FILTERED="$(mktemp)"
trap 'rm -f "$PROFILE" "$FILTERED"' EXIT

if ! go test ./core/ingest/... ./core/spectrum/ -coverprofile="$PROFILE" > /tmp/coverage-go-tests.log 2>&1; then
    echo "FAIL (Q2): 解析器测试未通过，覆盖率没有意义。"
    tail -20 /tmp/coverage-go-tests.log
    exit 1
fi

# 排除测试辅助包后再汇总。
grep -v "core/ingest/testutil" "$PROFILE" > "$FILTERED"

TOTAL="$(go tool cover -func="$FILTERED" | tail -1 | awk '{print $NF}' | tr -d '%')"
if [ -z "$TOTAL" ]; then
    echo "FAIL (Q2): cannot compute coverage total."
    exit 1
fi

echo "解析器行覆盖率（排除 testutil）：${TOTAL}%（阈值 ${THRESHOLD}%）"
go tool cover -func="$FILTERED" | awk -v t=75 '$3+0 < t && $3 != "" {print "  LOW:", $1, $2, $3}'

PASS="$(awk -v t="$THRESHOLD" -v v="$TOTAL" 'BEGIN{print (v+0 >= t+0) ? 1 : 0}')"
if [ "$PASS" != "1" ]; then
    echo "FAIL (Q2): 解析器覆盖率 ${TOTAL}% < ${THRESHOLD}%。"
    exit 1
fi
echo "OK (Q2): 解析器覆盖率达标。"
