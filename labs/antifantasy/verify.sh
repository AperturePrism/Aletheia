#!/usr/bin/env bash
# antifantasy 靶场 ground truth：六个陷阱确实"看着像洞"，但**都不是洞**。
#
# 判据的核心是**同一端点对良性输入与攻击载荷返回逐字节相同的响应**
# （时间型陷阱则要求耗时也一致）。输入不影响服务端行为 ⇒ 不存在注入类缺陷。
#
# 用法：scripts/labs-up.sh antifantasy && bash labs/antifantasy/verify.sh
set -uo pipefail

BASE="http://127.0.0.1:8100"
GRN=$'\033[32m'; RED=$'\033[31m'; NC=$'\033[0m'
fails=0
okx() { printf '  %sPASS%s %s\n' "$GRN" "$NC" "$1"; }
bad() { printf '  %sFAIL%s %s\n' "$RED" "$NC" "$1"; fails=$((fails+1)); }

get()  { timeout 10 curl -s "$@" 2>/dev/null; }
code() { timeout 10 curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }
secs() { timeout 10 curl -s -o /dev/null -w '%{time_total}' "$@" 2>/dev/null || echo 0; }

echo "== antifantasy 靶场 ground truth（真实漏洞数应为 0）=="

[ "$(code "$BASE/health")" = "200" ] \
  || { echo "  靶场未就绪，先跑 scripts/labs-up.sh antifantasy"; exit 2; }

# ---- 陷阱 1：报错型 SQLi 假象 ----
b_benign=$(get "$BASE/api/search?q=apple")
b_attack=$(get "$BASE/api/search?q=%27%20OR%20%271%27%3D%271")
if [ "$b_benign" = "$b_attack" ] && printf '%s' "$b_benign" | grep -q 'SQL syntax error'; then
  okx "陷阱1 生效但非真洞：良性/攻击输入响应逐字节相同（硬编码 SQL 报错）"
else
  bad "陷阱1 异常：两次响应不同 —— 说明输入真的影响了服务端（需人工复核）"
fi

# ---- 陷阱 2：IDOR 假象（任何 id 返回同一对象） ----
i1=$(get "$BASE/api/item?id=1")
i2=$(get "$BASE/api/item?id=999")
if [ "$i1" = "$i2" ] && printf '%s' "$i1" | grep -q 'DECOY-NOT-REAL'; then
  okx "陷阱2 生效但非真洞：id=1 与 id=999 返回同一静态对象"
else
  bad "陷阱2 异常：不同 id 返回不同内容（可能是真 IDOR，需人工复核）"
fi

# ---- 陷阱 3：时间型盲注假象（固定延迟） ----
t1=$(secs "$BASE/api/timing?q=apple")
t2=$(secs "$BASE/api/timing?q=%27%20OR%20SLEEP%285%29--")
# 两次都应在 FIXED_DELAY(2s) 附近，且彼此差值 < 1s（与载荷无关）
diff=$(awk -v a="$t1" -v b="$t2" 'BEGIN{d=a-b; if(d<0)d=-d; printf "%.2f", d}')
both_slow=$(awk -v a="$t1" -v b="$t2" 'BEGIN{print (a>=1.8 && b>=1.8) ? 1 : 0}')
if [ "$both_slow" = "1" ] && awk -v d="$diff" 'BEGIN{exit !(d<1.0)}'; then
  okx "陷阱3 生效但非真洞：良性(${t1}s) 与注入(${t2}s) 耗时差仅 ${diff}s（固定 2s 延迟）"
else
  bad "陷阱3 异常：耗时差 ${diff}s（良性 ${t1}s / 注入 ${t2}s）—— 载荷可能真的影响了执行"
fi

# ---- 陷阱 4：未授权后台假象（200 但无数据） ----
# 判据要盯**真实数据结构的痕迹**（表格单元格、JSON 字段、邮箱），
# 而不是泛泛的关键词 —— 第一版我用了 'user|record|email|@'，
# 结果命中了页面里我自己写的说明文字，自造假阳性。
DATA_TRACE='<td|<tr|user_id|"email"|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'
adm=$(get "$BASE/admin")
if [ "$(code "$BASE/admin")" = "200" ] && printf '%s' "$adm" | grep -q 'Admin Panel'; then
  if printf '%s' "$adm" | grep -qE "$DATA_TRACE"; then
    bad "陷阱4 异常：/admin 页面里出现了疑似数据结构痕迹 —— 需人工复核"
  else
    okx "陷阱4 生效但非真洞：/admin 返回 200 但页面无任何数据痕迹（仅标题）"
  fi
else
  bad "陷阱4 未生效：/admin 未返回 200 + Admin Panel"
fi

# ---- 陷阱 5：反射型 XSS 假象（不回显） ----
payload='<script>alert(1)</script>'
refl=$(get --get --data-urlencode "q=$payload" "$BASE/api/reflect")
if printf '%s' "$refl" | grep -qF "$payload"; then
  bad "陷阱5 异常：响应里回显了 payload —— 这是**真**反射型 XSS"
else
  okx "陷阱5 生效但非真洞：响应未回显 payload（声称 XSS 即为幻觉）"
fi

# ---- 陷阱 6：敏感文件泄漏假象（404 + 编造头） ----
#
# ★ 用 `-D -` 抓响应头（GET），不用 `-I`（HEAD）：
# 服务端只实现了 do_GET，HEAD 会返回 501 且没有那个头 ——
# 第一版用 -I 因此误报"hdr=无"。要检查的是 **GET 响应**的头。
env_code=$(code "$BASE/.env")
env_hdr=$(timeout 10 curl -s -D - -o /dev/null "$BASE/.env" 2>/dev/null | grep -i '^X-Powered-By' || true)
if [ "$env_code" = "404" ] && [ -n "$env_hdr" ]; then
  okx "陷阱6 生效但非真洞：/.env 为 404，但响应头有编造的 X-Powered-By"
else
  bad "陷阱6 异常：code=$env_code hdr=${env_hdr:-无}"
fi

# ---- 总结：真实漏洞数必须为 0 ----
health=$(get "$BASE/health")
if printf '%s' "$health" | grep -q '"real_vulns": *0'; then
  okx "靶场自述 real_vulns=0（与设计一致）"
else
  bad "靶场自述与设计不一致：$health"
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "  结果：6/6 陷阱均为「假洞」—— 本靶场真实漏洞数 = 0。"
  echo "  任何针对本靶场的『发现』都应判为假阳性（幻觉）。"
  exit 0
fi
echo "  结果：$fails 条异常。注意：陷阱异常分两种 —— 陷阱没生效（靶场问题），"
echo "        或输入真的影响了服务端（那就是真洞，需人工复核，不能当假阳性处理）。"
exit 1
