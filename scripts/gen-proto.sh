#!/usr/bin/env bash
# 从 proto/ 生成三侧代码：Go、TypeScript、Python。
#
# 三侧同源于 proto/aleth/v1/aletheia.proto —— 这是 docs/05 §0 C1
# 「契约定死，实现可变」的物理体现：契约只有一份，语言只是投影。
#
# 工具链（I0 定，见 docs/09 §5 #3 的依赖说明）：
#   Go / TS : buf（remote plugins，版本 pinned 在 proto/buf.gen.yaml）
#   Python  : grpc_tools.protoc（grpcio-tools 包）
#
# 退出码：0 = 成功；1 = 失败。

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUF="node_modules/.bin/buf"
if [ -f ".venv/Scripts/python.exe" ]; then
    PY=.venv/Scripts/python.exe
else
    PY=.venv/bin/python
fi

PROTO_FILE="proto/aleth/v1/aletheia.proto"

if [ ! -f "$PROTO_FILE" ]; then
    echo "gen-proto: proto contract missing: $PROTO_FILE" >&2
    exit 1
fi

# ---- 前置校验：契约自身必须能通过 buf lint ----
# 生成之前先 lint：一个有语法错误或命名违规的契约，生成出来的代码
# 会把问题带到三侧，而那时的错误信息离根因很远。
echo "  [1/3] buf lint（契约自身静态检查）"
"$BUF" lint proto/

# ---- Go + TypeScript ----
echo "  [2/3] buf generate → core/api + web/src/gen"
"$BUF" generate proto/ --template proto/buf.gen.yaml

# ---- Python ----
echo "  [3/3] grpcio-tools → agents/src/aletheia/gen"
"$PY" -m grpc_tools.protoc -Iproto \
    --python_out=agents/src/aletheia/gen \
    --grpc_python_out=agents/src/aletheia/gen \
    "$PROTO_FILE"

# 生成出来的包目录需要 __init__.py 才能被 import。
# protoc 不生成它们（它只管 .py 本体），这一步是 Python 侧的要求。
find agents/src/aletheia/gen -type d | while read -r d; do
    [ -f "$d/__init__.py" ] || touch "$d/__init__.py"
done

echo "  done."
