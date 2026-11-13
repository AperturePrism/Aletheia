#!/usr/bin/env bash
# multi-hop 靶场 ground truth：第二跳确实存在，且内网服务宿主直连不到。
#
# 用法：scripts/labs-up.sh multi-hop && bash labs/multi-hop/verify.sh
set -uo pipefail

BASE="http://127.0.0.1:8090"
GRN=$'\033[32m'; RED=$'\033[31m'; NC=$'\033[0m'
fails=0
okx() { printf '  %sPASS%s %s\n' "$GRN" "$NC" "$1"; }
bad() { printf '  %sFAIL%s %s\n' "$RED" "$NC" "$1"; fails=$((fails+1)); }

code() { timeout 8 curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }
body() { timeout 8 curl -s "$@" 2>/dev/null; }

echo "== multi-hop 靶场 ground truth =="

# 1) front 必须可达
[ "$(code "$BASE/health")" = "200" ] \
  && okx "front 可达（$BASE/health → 200）" \
  || bad  "front 不可达 —— 先跑 scripts/labs-up.sh multi-hop"

# 2) ★ 核心不变量：internal 的端口**没有**发布到宿主 ⇒ 直连必须失败
#    这里探测宿主 9000（若被误发布则能连上，说明靶场设计被破坏）
if (exec 3<>/dev/tcp/127.0.0.1/9000) 2>/dev/null; then
  exec 3>&- 2>/dev/null || true
  bad "宿主可以直连 9000 —— internal 端口被意外发布了，多跳退化成两个独立目标"
else
  okx "宿主直连 internal(9000) 失败 —— 符合设计（未发布端口）"
fi

# 3) 第二跳：经 front 代理拿到内部资产
resp=$(body "$BASE/proxy?path=/secret")
if printf '%s' "$resp" | grep -q 'MULTIHOP-6c1f9a'; then
  okx "经 front 第二跳拿到内部 flag（/proxy?path=/secret）"
else
  bad "第二跳未取到内部资产：$resp"
fi

# 4) 代理白名单必须生效（不能是通用转发器）
r=$(code "$BASE/proxy?path=/etc/passwd")
[ "$r" = "400" ] \
  && okx "代理白名单生效（非白名单路径 → 400）" \
  || bad "代理未限制路径（/etc/passwd → $r），靶场可能成为通用跳板"

echo
if [ "$fails" -eq 0 ]; then
  echo "  结果：4/4 符合设计 —— 可作为多跳基准。"
  exit 0
fi
echo "  结果：$fails 条不符合设计"
exit 1
