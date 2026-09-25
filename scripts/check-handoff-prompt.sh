#!/usr/bin/env bash
# 检查 docs/HANDOFF-PROMPT.md 是否与仓库当前状态脱节。
#
# 为什么值得一个检查：接手 Prompt 是**易腐文档**。它里面写了当前 HEAD、
# 最新 tag、"下一步做什么"。迭代推进后若忘了回填，接手方会照着过期的
# 计划开工 —— 而且那份文档看起来非常可信，比没有文档更危险。
#
# 这与 docs/10 §0 的「绿灯替代有效」同类：形式完好，内容已失效。
#
# 检查三件事：
#   1. 文件存在，且两个分隔线都在（提示词正文完整）
#   2. 里面写的 HEAD sha 是**仓库真实历史中的一个 commit**（存在但可过期 ——
#      过期只警告，因为这属于"待回填"而非"错误"）
#   3. 里面写的最新 tag 是仓库真实存在的 tag
#
# 退出码：0 = 一致或仅警告；1 = 结构损坏 / 引用了不存在的 commit 或 tag

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DOC="docs/HANDOFF-PROMPT.md"
fail=0

pass() { printf '  \033[32mOK\033[0m   %s\n' "$1"; }
fail_msg() {
    printf '  \033[31mFAIL\033[0m %s\n' "$1"
    shift
    printf '%s\n' "$@" | sed 's/^/         /'
    fail=1
}
warn() { printf '  \033[33mstale\033[0m %s\n' "$1"; }

echo "== 接手 Prompt 时效性检查 =="

if [ ! -f "$DOC" ]; then
    fail_msg "接手 Prompt 缺失" "  期望：$DOC（模板与维护说明在同文件中）"
    echo ""
    echo "缺少接手 Prompt 会让"下一个工具/新人不知道从哪开始"。"
    exit 1
fi
pass "文件存在"

# ---- 1. 结构完整：两个分隔线都要在 ----
sep_count=$(grep -c '^```$' "$DOC" 2>/dev/null || echo 0)
# 提示词正文用 ``` 围栏包裹，首尾各一个 → 至少 2 个
if [ "$sep_count" -lt 2 ]; then
    fail_msg "提示词正文围栏不完整" \
        "  期望至少 2 个 \`\`\` 围栏（首尾各一），实际 $sep_count 个" \
        "  收件人可能需要手动裁剪内容，围栏就是为了让他能整段复制"
else
    pass "提示词正文围栏完整（$sep_count 个）"
fi

# ---- 2. HEAD sha 必须是真实 commit ----
doc_head=$(grep -oE '当前 HEAD：`[0-9a-f]{7,40}`' "$DOC" | grep -oE '[0-9a-f]{7,40}' | head -1)
if [ -z "$doc_head" ]; then
    warn "未在文档中找到「当前 HEAD：\`<sha>\`」—— 无法校验时效性"
else
    if git cat-file -e "${doc_head}^{commit}" 2>/dev/null; then
        real_head=$(git rev-parse --short=7 HEAD)
        if [ "$doc_head" = "$real_head" ]; then
            pass "HEAD 与仓库当前一致（$doc_head）"
        else
            warn "HEAD 已过期：文档写 $doc_head，仓库当前 $real_head" \
                 "        （不是错误，属待回填。回填方法见文档末尾「维护提示」）"
        fi
    else
        fail_msg "文档中的 HEAD 不是仓库里的 commit" \
            "  文档写：$doc_head" \
            "  git cat-file 找不到该 commit —— 可能是抄错了，或历史被重写" \
            "  这比过期更糟：过期至少指向真实历史，错误指向不存在的东西"
    fi
fi

# ---- 3. tag 必须真实存在 ----
doc_tag=$(grep -oE '最新 tag：`[^`]+`' "$DOC" | sed 's/.*：`//; s/`$//' | head -1)
if [ -z "$doc_tag" ]; then
    warn "未在文档中找到「最新 tag」—— 无法校验"
else
    if git rev-parse -q --verify "refs/tags/$doc_tag" >/dev/null 2>&1; then
        latest_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
        if [ "$doc_tag" = "$latest_tag" ]; then
            pass "tag 与仓库最新一致（$doc_tag）"
        else
            warn "tag 已过期：文档写 $doc_tag，仓库最新 ${latest_tag:-（无）}"
        fi
    else
        fail_msg "文档中的 tag 不存在于仓库" \
            "  文档写：$doc_tag" \
            "  git rev-parse 找不到该 tag"
    fi
fi

echo ""
if [ "$fail" -ne 0 ]; then
    cat <<'MSG'
接手 Prompt 检查未通过。

注意 FAIL（结构损坏 / 引用不存在）与 stale（已过期）的区别：
  FAIL  → 文档本身有问题，必须修
  stale → 文档正确但待回填，迭代结束后更新「当前状态」与 HEAD/tag 即可

过期的接手 Prompt 比缺失更危险 —— 缺失会让人来问，过期会让人照着错的做。
MSG
    exit 1
fi

echo "接手 Prompt 检查通过（stale 项不计失败，但应在迭代末回填）。"
