#!/usr/bin/env bash
# 治理模型的护栏检查：确认 11 号文档的裁决结论没有被现实违背。
#
# 背景：docs/11-指令文档与冻结架构冲突分析.md §5 记录了项目负责人的裁决（C + D）：
#   · 治理模型按 08/09 执行（无凭证不启动、scope 不可热改、报告必含合规声明）
#   · 指令文档降级为「方法论参考」，不得作为治理依据
#
# 这个裁决是**口头 + 文档记录**，没有代码强制。如果将来有人按指令文档的
# §0.1「默认授权」改 alethd，让它在没凭证时也能启动，那么：
#   · docs/11 会说"裁决是这样"
#   · 代码会是另一个行为
#   · 两者都看起来合理，对不上就成了 P9 文档失真（P0）
#
# 本脚本把裁决里**可用代码验证的那几条**固化为检查。
# 检查不到的部分（如"报告必含合规声明"）明确标注为待对应迭代补齐，
# 不用一个永远通过的假检查覆盖。
#
# 退出码：0 = 护栏完好；1 = 发现违背。

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ANALYSIS="docs/11-指令文档与冻结架构冲突分析.md"
CTF_DOC="docs/instruction.ctf.md"
DEV_DOC="docs/dev-optimized-ai-digao.md"

DAEMON="cmd/alethd/main.go"
CONFIG="core/config/config.go"

fail=0

pass() { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
fail_msg() {
    printf '  \033[31mFAIL\033[0m %s\n' "$1"
    shift
    printf '%s\n' "$@" | sed 's/^/         /'
    fail=1
}
note() { printf '  \033[33mnote\033[0m %s\n' "$1"; }

echo "== 治理模型护栏（docs/11 §5 裁决：C + D）=="

# ---- 1. 裁决文档本身必须存在且状态为已裁决 ----
if [ ! -f "$ANALYSIS" ]; then
    fail_msg "裁决文档缺失" "$ANALYSIS"
else
    if grep -q "已裁决（C + D）" "$ANALYSIS"; then
        pass "裁决文档存在且状态为已裁决"
    else
        fail_msg "裁决文档状态不是「已裁决」" \
            "  期望：文件头含 状态：**已裁决（C + D）**" \
            "  实际：$(grep -m1 '状态：' "$ANALYSIS" || echo '未找到状态行')"
    fi
fi

# ---- 2. 两份指令文档必须带状态横幅 ----
for f in "$CTF_DOC" "$DEV_DOC"; do
    if [ ! -f "$f" ]; then
        note "$f 不存在（未入库则无此检查）"
        continue
    fi
    if grep -q "入库状态：方法论参考" "$f"; then
        pass "$(basename "$f") 已标注方法论参考状态"
    else
        fail_msg "$(basename "$f") 缺少状态横幅" \
            "  期望头部含「> ⚠️ **入库状态：方法论参考。**」" \
            "  缺此横幅会让读者误以为其治理条款适用于本项目（docs/11 §5 C）"
    fi
done

# ---- 3. alethd 必须仍然「无凭证不启动」 ----
# docs/11 §5：治理模型按 08 §1.1 执行，不接受按指令文档 §0.1「默认授权」放宽。
if [ ! -f "$DAEMON" ]; then
    fail_msg "daemon 入口缺失" "$DAEMON"
else
    if grep -q "errAuth" "$DAEMON" && grep -q "authPath == \"\"" "$DAEMON"; then
        pass "alethd 保留「无凭证不启动」（08 §1.1）"
    else
        fail_msg "alethd 的 Authorization Anchor 检查疑似被移除" \
            "  期望：$DAEMON 含 authPath == \"\" 判定并返回 errAuth" \
            "  这是 docs/11 §5 冲突 B 的裁决结果，不得按指令文档 §0.1 放宽"
    fi
fi

# ---- 4. 默认监听必须仍是回环 ----
# docs/11 §5 冲突 C 的间接体现：边界是物理约束，不是可随指令改的偏好。
if grep -qE 'DefaultListenAddr\s*=\s*"127\.0\.0\.1"' "$CONFIG"; then
    pass "默认监听仍为 127.0.0.1（Q13）"
else
    fail_msg "DefaultListenAddr 不是 127.0.0.1" \
        "  见 $CONFIG —— 安全默认（02 §11.3 D19）"
fi

# ---- 5. daemon 必须没有「临时批准越界」入口 ----
# docs/07 §T5.5 / 08 §5.4：绝不提供该功能，它会成为绕过 Authorization Anchor 的后门。
approve_hits=$(grep -rniE "approve.?violation|temporar(y|ily).?approv|allow.?this.?violation" \
    --include='*.go' --include='*.py' --include='*.ts' --include='*.tsx' core cmd web/src 2>/dev/null || true)
if [ -n "$approve_hits" ]; then
    fail_msg "发现疑似「临时批准越界」入口（docs/07 §T5.5 明令禁止）" "$approve_hits"
else
    pass "无「临时批准越界」入口（07 §T5.5）"
fi

echo ""
note "以下两项本脚本**无法**检查，按 docs/10 §0 硬要求 3 如实标注："
note "  · 「报告必含合规声明」（08 §7）→ I11 报告生成器落地时补检查"
note "  · 「scope 不可热改」（08 §5.4）→ I3 ScopeKernel 落地时补检查"
note "  届时在 docs/11 §5.1 中补登记，不要用一个永真检查提前覆盖。"

echo ""
if [ "$fail" -ne 0 ]; then
    cat <<'MSG'
治理模型护栏发现违背。依据 docs/11 §5 的裁决（项目负责人 2026-09-24 确认）：
  Aletheia 的系统行为按 08/09 执行——
    无凭证不启动 · scope 不可热改 · 报告必含合规声明
  不接受按指令文档（instruction.ctf.md / dev-optimized-ai-digao.md）放宽。

若认为裁决本身需要修改，正确路径是提请项目负责人重新裁决并更新 docs/11，
而不是在代码里先改。
MSG
    exit 1
fi

echo "治理模型护栏完好。"
