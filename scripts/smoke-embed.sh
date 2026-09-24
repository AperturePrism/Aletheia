#!/usr/bin/env bash
# Q11 冒烟测试：WebUI 产物可嵌入 Go 二进制并正常服务。
#
# docs/04 §I0 DoD 原文：
#     **WebUI 产物可嵌入单一二进制并正常服务**
# docs/04 §6 Q11：
#     WebUI 产物可嵌入 Go 二进制并正常服务 ｜ 构建成功 + 冒烟测试通过
#
# 为什么单独一个脚本：Makefile 的 recipe 里无法可靠使用 heredoc
# （Make 的行续接与 heredoc 交互会产生难以定位的解析错误），
# 而脚本可以单独跑、单独测。
#
# 用法：scripts/smoke-embed.sh [path-to-alethd]
# 默认测试 bin/alethd。

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ALETHD_BIN="${1:-bin/alethd}"
PORT="${ALETH_SMOKE_PORT:-7723}"

if [ ! -x "$ALETHD_BIN" ] && [ ! -f "$ALETHD_BIN" ]; then
    echo "FAIL (Q11): $ALETHD_BIN 不存在。先执行 make go-build。"
    exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/roe.yaml" <<'ROE'
version: 1
authorization:
  granted_by: "本地冒烟测试（非真实授权）"
  granted_to: "AperturePrism 冒烟测试"
  contact: "smoke@example.invalid"
  ticket_id: "SMOKE-I0"
  valid_from:  "2020-01-01T00:00:00Z"
  valid_until: "2035-01-01T00:00:00Z"
targets:
  include:
    - cidr: "10.255.255.0/24"
  exclude: []
actions:
  allow: [recon]
  limits:
    max_requests_per_second: 1
    max_concurrent_tasks: 1
data_handling:
  pii_handling: "mask"
  no_external_transmission: true
ROE

cat > "$tmpdir/alethd.yaml" <<CFG
server:
  addr: 127.0.0.1
  port: $PORT
storage:
  data_dir: $tmpdir/data
logging:
  level: info
  format: json
CFG

echo "== Q11 冒烟测试 =="
echo "  binary : $ALETHD_BIN"
echo "  port   : $PORT"
echo "  roe    : $tmpdir/roe.yaml（本地占位凭证，非真实授权）"

# 前台启动，输出到日志文件，2s 后请求。
"$ALETHD_BIN" --authorization "$tmpdir/roe.yaml" --config "$tmpdir/alethd.yaml" \
    > "$tmpdir/alethd.log" 2>&1 &
pid=$!

# 等待端口就绪（最多 10s，每次 0.2s）。
ready=0
for _ in $(seq 1 50); do
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "FAIL (Q11): alethd 进程提前退出。日志："
        sed 's/^/    /' "$tmpdir/alethd.log"
        exit 1
    fi
    if curl -fsS --max-time 2 "http://127.0.0.1:$PORT/" > /dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.2
done

if [ "$ready" -ne 1 ]; then
    echo "FAIL (Q11): 端口 $PORT 未在 10s 内就绪。日志："
    sed 's/^/    /' "$tmpdir/alethd.log"
    kill "$pid" 2>/dev/null || true
    exit 1
fi

body="$(curl -fsS --max-time 5 "http://127.0.0.1:$PORT/" 2>/dev/null || true)"
if [ -z "$body" ]; then
    echo "FAIL (Q11): WebUI 返回空响应。"
    kill "$pid" 2>/dev/null || true
    exit 1
fi

# killer check：响应里必须出现 Aletheia 标识（占位页或真实 UI 都有）。
if ! grep -qi "aletheia" <<<"$body"; then
    echo "FAIL (Q11): 响应不像 WebUI（未找到 Aletheia 标识）。"
    kill "$pid" 2>/dev/null || true
    exit 1
fi

# 顺带验证 Q13：daemon 不得监听 0.0.0.0。
# netstat 在 Git Bash 下可用；失败不阻断 Q11，只告警。
if command -v netstat >/dev/null 2>&1; then
    if netstat -an 2>/dev/null | grep -q "0.0.0.0:$PORT"; then
        echo "FAIL (Q13): alethd 监听在 0.0.0.0（应仅 127.0.0.1）。"
        kill "$pid" 2>/dev/null || true
        exit 1
    fi
fi

kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

echo ""
echo "OK (Q11): WebUI 经嵌入式二进制正常服务（字节数：$(wc -c <<<"$body")）"
