#!/usr/bin/env bash
# docs/10 §3 P3「安全机制绕过」的自动化检测。
#
# 为什么单独一个脚本而不是 Makefile 内联：
#   ① Makefile 的多行 shell 循环可读性差、出错信息难定位；
#   ② 脚本可以被 CI 与开发者本地直接调用，不只经由 make；
#   ③ 脚本可以单独被测（tests/test_security_scan.py 会跑它并做变异验证）。
#
# 检测的五项对应 docs/10 §3 P3 的典型表现：
#   R4 无绕过 Evidence Ledger 的 finding 路径
#   R5 LLM 未参与命令行生成
#   R6 无 agent 自行终止会话的路径
#   P-4 无吞掉的异常（fail-closed）
#   R7 无 Privacy Gateway 的 UI 开关
#
# 排除范围（重要，否则全是假阳性）：
#   · 生成代码（aletheia_pb2*.py / *.pb.go / web/src/gen）——
#     它们由 proto/ 生成，本就包含契约注释中的"禁止 SystemExit 之类"字样。
#     对生成代码做源码级扫描没有意义，要控的是 proto/ 本身。
#   · node_modules / .venv / bin / dist。
#   · docs/、tests/ 下的说明性文本 —— 本项目的文档大量引用红线编号
#     （"09 §R6：禁止 SystemExit"），那不是违规代码。
#
# 退出码：0 = 全部通过；1 = 发现违规。

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

# grep 的公共排除参数。生成代码、第三方代码、文档都不在扫描范围内。
EXCLUDES=(
    --exclude-dir=node_modules
    --exclude-dir=.venv
    --exclude-dir=bin
    --exclude-dir=dist
    --exclude-dir=.git
    --exclude-dir=__pycache__
    --exclude='*_pb2.py'
    --exclude='*_pb2_grpc.py'
    --exclude='*_pb2.pyi'
    --exclude='*.pb.go'
    --exclude='*.md'
)

fail=0

report_ok() { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
report_fail() {
    printf '  \033[31mFAIL\033[0m %s\n' "$1"
    shift
    printf '%s\n' "$@" | sed 's/^/         /'
    fail=1
}

# scan <描述> <目录...> -- <grep 模式>
# 用法：scan "描述" core agents -- 'pattern'
scan() {
    local desc="$1"; shift
    local dirs=()
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
        dirs+=("$1"); shift
    done
    shift  # 去掉 --

    local pattern="$1"
    local out
    out=$(grep -rnE "${EXCLUDES[@]}" "$pattern" "${dirs[@]}" 2>/dev/null || true)
    if [ -n "$out" ]; then
        report_fail "$desc" "$out"
    else
        report_ok "$desc"
    fi
}

echo "== R4：无绕过 Evidence Ledger 的 finding 路径 =="
# 直接构造 CONFIRMED。唯一合法路径是 LedgerService.ValidateAssertion（05 §5.3）。
scan "禁止直接把 status 赋成 CONFIRMED" core agents web/src -- \
    'status[[:space:]]*=[[:space:]]*(CONFIRMED|3)\b'

echo "== R5：LLM 未参与命令行生成 =="
# argv 必须由参数化 Schema 确定性渲染（05 §2.1）。
# 覆盖两种语言各自的字符串拼接形态：
#   Python f-string / .format()  →  run(f"nmap {llm_output}")
#   Go fmt.Sprintf               →  run(fmt.Sprintf("nmap %s", llmOutput))
# 只查其中一种会让另一种成为漏网之门 —— 而这个项目是双语言的。
scan "禁止用 LLM 输出拼接命令行（f-string / format）" core agents -- \
    '(Run|run|Execute|exec)\([A-Za-z]?f?"[^"]*\{(llm|model_output|llm_output|completion|response)'
scan "禁止用 LLM 输出拼接命令行（fmt.Sprintf）" core agents -- \
    'Sprintf\("[^"]*%[sv][^"]*",[^)]*(llm|model_output|llm_output|completion|response)'

echo "== R6：agent 无自行终止会话的权限 =="
scan "Python 侧禁止 sys.exit / os._exit / raise SystemExit" agents -- \
    '(^|[^#].*)(sys\.exit|os\._exit|raise SystemExit)'
scan "非入口代码禁止 os.Exit" core -- \
    'os\.Exit\('

echo "== P-4：失败即熔断，不降级（无吞异常）=="
scan "禁止 except: pass / except: continue" core agents -- \
    'except[^\n]*:[[:space:]]*(pass|continue)\b'

echo "== R7：Privacy Gateway 不可通过 UI 关闭 =="
scan "前端禁止出现 Privacy Gateway 关闭开关" web/src -- \
    'privacy.*(off|disable)|disable.*privacy|gateway.*off'

echo "== R8：ScopeKernel 不提供 '跳过越界继续' 路径 =="
# 项目文档中提及"不得跳过"是允许的（那是设计约束的说明），
# 这里只匹配代码标识符层面的 skip/ignore 调用。
scan "禁止 scope 跳过 / 忽略调用" core agents -- \
    '(skip|ignore|bypass)[A-Za-z_]*(Scope|scope)[A-Za-z_]*|scope[A-Za-z_]*(Skip|Ignore|Bypass)'

echo "== 09 §6 #11：解析必须确定性，禁止让 LLM 解析工具输出 =="
scan "禁止把工具输出交给 LLM 解析" core agents -- \
    '(parse|extract|decode)_output_with_(llm|model)'

echo ""
if [ "$fail" -ne 0 ]; then
    cat <<'MSG'
检测到违规。依据 docs/10 §4 严重度分级：
  出现任意 🔴 P0 → 判定为「必须回滚」，不得继续开发新功能。

上面的命中需要逐条甄别（可能是注释中的反面说明，也可能是真实违规）。
若确为误报，请在该行加注释说明理由，而非删除本脚本的规则 ——
删除规则 = 削弱门禁（docs/09 §R2）。
MSG
    exit 1
fi

echo "全部通过。"
