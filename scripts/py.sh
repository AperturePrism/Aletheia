#!/usr/bin/env bash
# 解析出可用的 Python 解释器；必要时自动创建仓库 .venv。
#
# 为什么放在脚本里而不是 Makefile 内联（三个连续设计错误的教训）：
#
#   错误 1（CI 四跑）：Makefile 写死 .venv/bin/python。
#       venv 不存在时 → Error 127。
#
#   错误 2（CI 五跑）：改成按优先级回退到 PATH 上的 python3。
#       但 CI 的系统 python3 没装 pytest → 回退只是把 127 换成更隐密的
#       "No module named pytest"。**更健壮的回退可能比明确的失败更危险**，
#       它让人以为测试在跑。
#
#   错误 3（CI 六跑）：加 $(error) 守卫 → 所有 job 全挂。
#       根因：`PY = $(shell ...)` 在 Makefile **解析时**求值，
#       而 `make env`（创建 .venv）发生在 **recipe 执行时**。
#       顺序错了 —— 解析时 .venv 还没建。
#       **$(shell) 的结果不能依赖任何 recipe 的副作用**，这是 Make 的硬约束。
#
# 正解：解析延到 recipe 内（那时 env 已就绪），并让 venv 缺失时**自动创建**。
#
# 输出：无。直接 exec 解析到的解释器，把后续参数原样透传。
# 退出码：即被 exec 的解释器的退出码；解析失败为 1（含具体原因）。
#
# 用法（Makefile 里 PY 指向本脚本，后续参数即解释器参数）：
#   PY := bash scripts/py.sh
#   PYTEST := $(PY) -m pytest
#   → 实际执行：bash scripts/py.sh -m pytest tests/ -q
#
# 注意本脚本必须 **exec** 而不是 echo 解释器路径：
# echo 方案会让 Makefile 把 "bash scripts/py.sh" 当作解释器名，
# pytest 参数全被脚本吞掉（六跑之后第一次尝试时的真实错误）。

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# 候选解释器，按优先级。仓库 venv 优先（含 Windows/MSYS 布局）。
CANDIDATES=(
    ".venv/Scripts/python.exe"
    ".venv/bin/python"
    "python3"
    "python"
)

# 逐个验证：不仅要存在，还必须能 import pytest。
# 只判存在就重回错误 2 的老路。
for c in "${CANDIDATES[@]}"; do
    if ! command -v "$c" >/dev/null 2>&1 && [ ! -x "$c" ]; then
        continue
    fi
    if "$c" -c "import pytest" >/dev/null 2>&1; then
        exec "$c" "$@"
    fi
done

# 没有可用解释器。最后手段：用 uv 建一个 venv（CI 与开发者机器都有 uv）。
# 这不是静默降级 —— 建出来的 venv 会装上 dev 依赖，跑的是真测试。
if command -v uv >/dev/null 2>&1; then
    if uv sync --group dev >/dev/null 2>&1; then
        # uv 建好后重新解析一次（Windows 与 Linux 布局不同）。
        for c in ".venv/Scripts/python.exe" ".venv/bin/python"; do
            if [ -x "$c" ] && "$c" -c "import pytest" >/dev/null 2>&1; then
                exec "$c" "$@"
            fi
        done
    fi
fi

cat >&2 <<'MSG'
py.sh: 找不到可用的 Python + pytest。

已尝试：
  · 仓库 .venv（Windows 与 Linux 两种布局）
  · PATH 上的 python3 / python（要求能 import pytest）
  · 用 uv 创建 venv 并安装 dev 依赖

本脚本不静默降级到一个跑不起来的解释器 ——
那会把 "No module named pytest" 伪装成测试结果。
MSG
exit 1
