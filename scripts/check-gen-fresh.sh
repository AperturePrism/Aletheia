#!/usr/bin/env bash
# Q14：生成物必须与契约一致。
#
# docs/04 §6 Q14 原文：
#     前端 TS 类型由 Protobuf 生成（无手工维护的重复类型）｜ 生成脚本在 CI 中校验
#
# 做法：重新生成一次，比对前后差异。
#
#   ① 若 `make proto` 产生了变更 → 有人改了契约没重新生成，或手改了生成物。
#      两种情况都是 P1 契约漂移（docs/10 §3），必须阻断。
#   ② 若无变更 → 生成物与契约一致。
#
# 为什么用"重新生成 + diff"而不是"检查生成物是否存在"：
#   文件存在不代表内容最新。一次静默过期的生成物会让 Go/Python/TS 三侧
#   分别理解同一个契约为不同形状 —— 而这个项目最大的架构风险正是双语言漂移
#   （docs/05 §0 C1）。
#
# 退出码：0 = 一致；1 = 不一致。

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GEN_DIRS=(core/api web/src/gen agents/src/aletheia/gen)

if [ -f ".venv/Scripts/python.exe" ]; then
    PY=.venv/Scripts/python.exe
else
    PY=.venv/bin/python
fi

echo "== Q14：协定生成物一致性校验 =="

# ---- 1. 记录当前生成物指纹 ----
before=""
for d in "${GEN_DIRS[@]}"; do
    [ -d "$d" ] || continue
    # 按路径排序后再哈希，保证与文件系统遍历顺序无关。
    files=$(find "$d" -type f | LC_ALL=C sort)
    for f in $files; do
        before="$before$(md5sum "$f" 2>/dev/null)"$'\n'
    done
done
before_hash=$(printf '%s' "$before" | md5sum | cut -d' ' -f1)

# ---- 2. 重新生成 ----
echo "  重新生成 Go / TypeScript / Python ..."
if ! bash scripts/gen-proto.sh >/tmp/aleth-gen-proto.log 2>&1; then
    echo "FAIL (Q14)：重新生成失败。日志："
    sed 's/^/    /' /tmp/aleth-gen-proto.log
    exit 1
fi

# ---- 3. 比对 ----
after=""
for d in "${GEN_DIRS[@]}"; do
    [ -d "$d" ] || continue
    files=$(find "$d" -type f | LC_ALL=C sort)
    for f in $files; do
        after="$after$(md5sum "$f" 2>/dev/null)"$'\n'
    done
done
after_hash=$(printf '%s' "$after" | md5sum | cut -d' ' -f1)

if [ "$before_hash" != "$after_hash" ]; then
    echo "FAIL (Q14)：生成物与 proto/ 契约不一致。"
    echo ""
    echo "  变更内容："
    diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") | head -20 | sed 's/^/    /'
    echo ""
    cat <<'MSG'
  两种可能，都要处理：
    a) 改了 proto/aleth/v1/aletheia.proto 但没执行 make proto
       → 这同时可能是 R1 违规（docs/09：契约变更须走 contract: PR + 双人 review）
    b) 手工改了生成物（web/src/gen、core/api、agents/src/aletheia/gen）
       → 生成物不可手改，改动必须落在 proto/ 上

  修复：make proto
MSG
    exit 1
fi

echo "OK (Q14)：生成物与契约一致（$after_hash）"
