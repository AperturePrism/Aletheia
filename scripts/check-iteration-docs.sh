#!/usr/bin/env bash
# 检查迭代交付物齐全：交接文档 + 自检报告。
#
# docs/09 §10 规定的 10 项交付物中，第 3、4、9、10 项是硬要求。
# 其中前两项（DoD 达成报告 / 偏差说明）写在自检报告与交接文档里，
# 所以这里检查**文件的物理存在**：
#
#   docs/iterations/I{n}-交接.md
#   docs/iterations/I{n}-自检报告.md
#
# 为什么会漏：代码在仓库里，这两份文档容易被"下次补"。
# 而 docs/10 §3 P10「交付物缺失」最常见的遗漏正是它们 ——
# 尤其中间隔了几天之后再补，当时的上下文已经想不起来了。
#
# 用法：
#   scripts/check-iteration-docs.sh I0          # 检查指定迭代
#   scripts/check-iteration-docs.sh --all       # 检查仓库中所有已声明完成的迭代
#
# "已声明完成"的判定：docs/04-开发总纲 中出现了「I{n} 实际达成情况」小节 ——
# 那意味着该迭代已经走完，交付物应当齐全。
#
# 退出码：0 = 齐全；1 = 有缺失。

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ITER_DIR="docs/iterations"
PLAN="docs/04-开发总纲-阶段规划与依赖.md"
HANDOFF_TEMPLATE="$ITER_DIR/README.md"

fail=0

echo "== 迭代交付物齐全性检查（docs/09 §10 第 9、10 项）=="

if [ ! -f "$HANDOFF_TEMPLATE" ]; then
    printf '  \033[31mFAIL\033[0m 交接文档模板缺失：%s\n' "$HANDOFF_TEMPLATE"
    fail=1
else
    printf '  \033[32mOK\033[0m   交接文档模板存在\n'
fi

check_iteration() {
    local id="$1"
    local missing=()

    for f in "$ITER_DIR/${id}-交接.md" "$ITER_DIR/${id}-自检报告.md"; do
        if [ ! -f "$f" ]; then
            missing+=("$f")
        else
            # 文件存在还要看是否为空壳（只有标题没有内容）。
            local lines
            lines=$(wc -l <"$f")
            if [ "$lines" -lt 30 ]; then
                missing+=("$f（仅 ${lines} 行，疑似空壳）")
            fi
        fi
    done

    if [ ${#missing[@]} -eq 0 ]; then
        printf '  \033[32mOK\033[0m   %s 交接文档 + 自检报告齐全\n' "$id"
    else
        printf '  \033[31mFAIL\033[0m %s 缺失交付物：\n' "$id"
        printf '       %s\n' "${missing[@]}"
        printf '       模板：%s\n' "$HANDOFF_TEMPLATE"
        fail=1
    fi
}

if [ "${1:-}" = "--all" ]; then
    if [ ! -f "$PLAN" ]; then
        echo "FAIL: 找不到 $PLAN"
        exit 1
    fi
    # 从 04 中抽取已回填的迭代编号。
    mapfile -t ids < <(grep -oE '^#### I[0-9]+ 实际达成情况' "$PLAN" | grep -oE 'I[0-9]+' | sort -u)
    if [ ${#ids[@]} -eq 0 ]; then
        printf '  \033[33mnote\033[0m  %s 中尚无已回填的迭代\n' "$PLAN"
    fi
    for id in "${ids[@]}"; do
        check_iteration "$id"
    done
elif [ -n "${1:-}" ]; then
    # 规范化为 I{N} 形式。
    id="$1"
    case "$id" in
        I*) ;;
        *) id="I$id" ;;
    esac
    check_iteration "$id"
else
    echo "用法：$0 <I{n}> ｜ $0 --all"
    echo "示例：$0 I0"
    exit 2
fi

echo ""
if [ "$fail" -ne 0 ]; then
    cat <<'MSG'
交付物缺失。依据 docs/10 §3 P10（严重度 🟠 P1）：缺交付物不得进入下一迭代。

生成的文档不要求长，但必须有实质内容。两份文档分工：
  交接.md     给下一位开发者的操作手册（环境实测、下一步第一条命令）
  自检报告.md 本次的红线逐条核查记录（每条附命令与原始输出）
MSG
    exit 1
fi

echo "交付物齐全。"
