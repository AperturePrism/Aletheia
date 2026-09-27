#!/usr/bin/env bash
# Q8 稳定性测试 harness（docs/04 §2 P0 门禁第 1 条、§6 Q8）。
#
# 判定标准（04 §2 原文）：连续 24h 稳定性测试无崩溃、无内存泄漏（RSS 增长 < 5%）。
#
# 做法：
#   1. 生成临时授权凭证（有效期覆盖本次运行；目标为 RFC 5737 文档网段，
#      不含任何真实目标信息 —— 09 §8.3）与 focalplane Ed25519 密钥对；
#   2. 启动被测系统：focalplane server（Python，L3 账本）+ alethd（Go，
#      L0 + 代理），二者均挂后台；
#   3. 按 --interval 周期注入负载（probe.py：真实 gRPC 契约往返）并采样
#      两个进程的 RSS；
#   4. 运行结束按三条判定：零崩溃 / 探针成功率 100% / RSS 增长 < 5%，
#      摘要写入 tests/stability/last_run.json。
#
# 用法：
#   tests/stability/run.sh                     # 24h 全量（默认 86400s）
#   tests/stability/run.sh --duration 60       # 冒烟（1 分钟）
#   tests/stability/run.sh --duration 300 --interval 5
#
# 退出码：0 = 通过；1 = 判定失败或环境错误。

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# ---- 参数 ----
DURATION=86400
INTERVAL=30
# 预热窗口（秒）：RSS 判据只比较**窗口结束后**的稳态区间。
# 依据 modules/M6 §12：Go/Python runtime 启动阶段的堆扩张属正常行为，
# 计入基线会让判据对任何长时服务恒为假阳性（实测 alethd 约 5 分钟内
# 完成堆扩张后进入平台期，故默认取 10 分钟＝2 倍余量）。
WARMUP=600
# 端口在此**单点定义**：同时写入 alethd.yaml 与 probe 调用参数。
# 上一版把 gRPC 端口写在 yaml 里、probe.py 里又硬编码了旧的 7723，
# 两处漂移导致探针 100% 失败（7723 是 HTTP/WebUI，不是 gRPC）。
HTTP_PORT=7723   # WebUI / HTTP 调试通道
GRPC_PORT=7724   # alethd gRPC 服务 —— IngestService 探针目标
FP_PORT=7728     # focalplane —— LedgerService 探针目标
while [ $# -gt 0 ]; do
    case "$1" in
        --duration) DURATION="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        --warmup) WARMUP="$2"; shift 2 ;;
        *) echo "unknown arg: $1"; exit 2 ;;
    esac
done
if [ "$DURATION" -lt 10 ]; then
    echo "duration must be >= 10s"; exit 2
fi
if [ "$WARMUP" -lt 0 ]; then
    echo "warmup must be >= 0"; exit 2
fi

# ---- 工具链 ----
# 复用 scripts/py.sh 的解释器解析（含 Windows/Linux 布局与自动建 venv），
# 避免本脚本重复维护候选列表（I0 环境坑 #5/#7 的教训：解析逻辑只写一处）。
PY=$(bash scripts/py.sh -c "import sys; print(sys.executable)")
if [ -z "$PY" ]; then echo "python not found; run make env"; exit 2; fi
ALETHD="bin/alethd"
if [ ! -x "$ALETHD" ] && [ -f "$ALETHD.exe" ]; then ALETHD="$ALETHD.exe"; fi
if [ ! -x "$ALETHD" ]; then echo "bin/alethd not found; run make build"; exit 2; fi

RUN_DIR="tests/stability/last_run"
mkdir -p "$RUN_DIR"

# 只清理**会污染本轮结果**的文件，不做整目录删除。两条理由：
#
# 1) 必须删的是账本：ledger.db* 残留会让本轮的 evidence_id 与上一轮重复，
#    M4 的幂等/伪造检测会拒掉前 N 轮 Append —— 表现成「probe 全程失败」，
#    看起来像被测系统的稳定性问题，实为脏状态污染（误导性结论）。
#    其余产物（csv / log / yaml / json / 临时密钥）都是覆盖写或每轮重建。
# 2) 整目录删除在受限环境可能被拒：单次批量删除文件数有上限
#    （实测 >50 触发 SAFE_DELETE_BULK_CONFIRM_REQUIRED），而 `rm -rf`
#    的失败会被 `-f` 吞掉 —— 静默失败正是上面那个误导性结论的来源。
#
# 删除后**回验**：失败必须显式中止，不允许带着脏账本继续跑。
rm -f "$RUN_DIR"/ledger.db "$RUN_DIR"/ledger.db-shm "$RUN_DIR"/ledger.db-wal
if [ -e "$RUN_DIR/ledger.db" ]; then
    echo "错误：无法清理 $RUN_DIR/ledger.db（可能仍有 focalplane 进程占用）。" >&2
    echo "      残留账本会使 evidence_id 重复，本轮结果不可信，已中止。" >&2
    echo "      处置：确认进程已退出后重试，或手动删除该文件。" >&2
    exit 2
fi

# ---- 1. 临时凭证与密钥（每次运行独立，不入库）----
NOW=$(date -u +%Y-%m-%dT%H:%M:%S+00:00)
UNTIL=$("$PY" -c "import datetime; print((datetime.datetime.now(datetime.UTC)+datetime.timedelta(days=89)).strftime('%Y-%m-%dT%H:%M:%S+00:00'))")
cat > "$RUN_DIR/roe.yaml" <<EOF
version: 1
authorization:
  granted_by: "STABILITY-HARNESS"
  granted_to: "alethd (stability run)"
  contact: "security@stability.test"
  ticket_id: "STAB-$(date -u +%Y%m%d)"
  document_hash: "sha256:$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  valid_from: "$NOW"
  valid_until: "$UNTIL"
targets:
  include:
    - cidr: "192.0.2.0/24"
    - host: "app.stability.test"
  exclude:
    - cidr: "192.0.2.255/32"
actions:
  allow: [recon, scan]
  deny: [dos, destructive]
EOF

KEYPAIR=$("$PY" - <<'PYEOF'
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
k = Ed25519PrivateKey.generate()
print(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex())
print(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
PYEOF
)
PRIV_HEX=$(echo "$KEYPAIR" | sed -n 1p)
PUB_HEX=$(echo "$KEYPAIR" | sed -n 2p)
echo "$PRIV_HEX" > "$RUN_DIR/probe_key.hex"

cat > "$RUN_DIR/alethd.yaml" <<EOF
focalplane:
  addr: "127.0.0.1:$FP_PORT"
server:
  port: $HTTP_PORT
  grpc_port: $GRPC_PORT
storage:
  data_dir: "$RUN_DIR/data"
  evidence_dir: "$RUN_DIR/data/evidence"
EOF

# ---- 2. 启动被测系统 ----
START_TS=$(date +%s)
# agents/src 必须显式入 PYTHONPATH：venv 只装依赖，项目包经 pythonpath 约定。
# 两个原生 Windows Python 的硬要求（二者都是实测踩出来的）：
#   1) 路径须为 **Windows 形式**：MSYS 只在 exec 时转换**命令行参数**，
#      **不转换环境变量** —— 直接把 MSYS 的 /d/... 放进 PYTHONPATH 会得到
#      `ModuleNotFoundError: No module named 'aletheia'`。
#   2) 分隔符是 os.pathsep（Windows ';' / POSIX ':'），不是固定的 ':'。
# 这里直接赋值而非追加：harness 要求干净、可复现的环境，不继承调用者已有的
# PYTHONPATH（I0 交接 §2：干净环境是唯一诚实的验证）。
if command -v cygpath >/dev/null 2>&1; then
    AGENTS_SRC=$(cygpath -w "$REPO_ROOT/agents/src")
else
    AGENTS_SRC="$REPO_ROOT/agents/src"
fi
export PYTHONPATH="$AGENTS_SRC"
"$PY" -m aletheia.focalplane.server \
    --db "$RUN_DIR/ledger.db" \
    --addr "127.0.0.1:$FP_PORT" \
    --pubkey-hex "$PUB_HEX" > "$RUN_DIR/focalplane.log" 2>&1 &
FP_PID=$!
"$ALETHD" -c "$REPO_ROOT/$RUN_DIR/alethd.yaml" \
    --authorization "$REPO_ROOT/$RUN_DIR/roe.yaml" > "$RUN_DIR/alethd.log" 2>&1 &
AD_PID=$!
cleanup() {
    kill "$FP_PID" "$AD_PID" 2>/dev/null
    wait "$FP_PID" "$AD_PID" 2>/dev/null
}
trap cleanup EXIT

echo "== Q8 稳定性测试：duration=${DURATION}s interval=${INTERVAL}s warmup=${WARMUP}s =="
echo "  focalplane pid=$FP_PID  alethd pid=$AD_PID"

# ---- 3. 负载注入 + 采样循环 ----
CSV="$RUN_DIR/timeseries.csv"
echo "ts,probe,fp_rss_kb,ad_rss_kb" > "$CSV"
# 探针日志在循环内追加；此处显式截断，避免与上一轮残留串在一起
#（混在一起的日志会让「哪一轮失败、为什么失败」不可判读）。
PROBE_LOG="$RUN_DIR/probe.log"
: > "$PROBE_LOG"
PROBE_FAIL=0
RSS_FAIL=0
CRASHES=0
ELAPSED=0
SEQ=0

# RSS 采样走 tests/stability/rss.py（跨平台，失败显式非零退出）。
# 刻意**不**回退到 shell 的 powershell / /proc 分支：采样不到必须记为
# 失败，而不是变成空值 → 增长 0.0% → 「RSS 增长 < 5%」恒真的假绿灯。
#
# native_pid：Git Bash（MSYS2）下 `$!` 拿到的是 MSYS 虚拟 PID，采样器要的是
# OS 原生 PID。映射文件 /proc/<pid>/winpid 只对 MSYS 程序可见（原生 Python
# 读不到），所以这层转换必须留在 shell 侧。非 MSYS 环境无此文件，原样返回。
native_pid() {
    local w
    w=$(cat "/proc/$1/winpid" 2>/dev/null | tr -d '\r\n')
    if [ -n "$w" ]; then echo "$w"; else echo "$1"; fi
}

read_rss() { # $1=shell pid；成功回显 KB，失败回显空串
    "$PY" tests/stability/rss.py --pid "$(native_pid "$1")" 2>/dev/null || true
}

# 时长基准用**真实墙钟**而非累加 INTERVAL：每轮除 sleep 外还有探针与采样
# 开销（本机实测每轮 +10s 量级），累加会让标称 24h 实际跑成 30h+，
# 与 Q8「连续 24h」的字面语义不符。
DEADLINE=$((START_TS + DURATION))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    sleep "$INTERVAL"
    ELAPSED=$(( $(date +%s) - START_TS ))
    SEQ=$((SEQ + 1))
    TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    if ! kill -0 "$FP_PID" 2>/dev/null; then
        echo "CRASH: focalplane exited at $TS"; CRASHES=$((CRASHES + 1))
        break
    fi
    if ! kill -0 "$AD_PID" 2>/dev/null; then
        echo "CRASH: alethd exited at $TS"; CRASHES=$((CRASHES + 1))
        break
    fi

    if "$PY" tests/stability/probe.py \
        --alethd "127.0.0.1:$GRPC_PORT" \
        --focalplane "127.0.0.1:$FP_PORT" \
        --key-hex "$RUN_DIR/probe_key.hex" --seq "$SEQ" >> "$PROBE_LOG" 2>&1; then
        PROBE=ok
    else
        PROBE=fail
        PROBE_FAIL=$((PROBE_FAIL + 1))
    fi

    # 采不到 RSS 记 RSS_FAIL：内存判据缺证据时不得给出通过结论。
    FP_KB=$(read_rss "$FP_PID")
    AD_KB=$(read_rss "$AD_PID")
    if [ -z "$FP_KB" ]; then RSS_FAIL=$((RSS_FAIL + 1)); fi
    if [ -z "$AD_KB" ]; then RSS_FAIL=$((RSS_FAIL + 1)); fi

    echo "$TS,$PROBE,$FP_KB,$AD_KB" >> "$CSV"
    echo "  [$TS] probe=$PROBE fp_rss=${FP_KB:-NA}KB ad_rss=${AD_KB:-NA}KB"
done

cleanup

# ---- 4. 判定（真源 modules/M6 §12 DoD + 04 §2/§6 Q8：零崩溃、RSS 增长 < 5%）----
# judge 需要知道本轮实际跑了多久，以便把 duration_s 写进摘要（此前恒为 null）。
END_TS=$(date +%s)
ACTUAL_DURATION=$((END_TS - START_TS))
"$PY" - "$RUN_DIR" "$CRASHES" "$PROBE_FAIL" "$RSS_FAIL" "$ACTUAL_DURATION" "$WARMUP" <<'PYEOF'
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

run_dir, crashes, probe_fail, rss_fail, duration, warmup = (
    sys.argv[1],
    int(sys.argv[2]),
    int(sys.argv[3]),
    int(sys.argv[4]),
    int(sys.argv[5]),
    int(sys.argv[6]),
)
rows = []
csv = Path(run_dir) / "timeseries.csv"
for line in csv.read_text(encoding="utf-8").splitlines()[1:]:
    ts, probe, fp, ad = line.strip().split(",")
    rows.append((ts, probe, fp, ad))


def _epoch(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


# 预热窗口：只保留 t0 + warmup 之后的样本作为**稳态区间**。
# 理由见 modules/M6 §12 —— runtime 启动阶段的堆扩张是正常行为，计入基线
# 会让判据对任何长时服务恒为假阳性。t0 取首个样本时间
#（≈ 启动时刻 + interval），对窗口长度的误差为 1 个 interval 量级，可忽略。
if rows:
    t0 = _epoch(rows[0][0])
    steady = [r for r in rows if _epoch(r[0]) - t0 >= warmup]
else:
    steady = []


def growth(col):
    """稳态区间的首尾均值增长率（%）。稳态样本不足 / 全空 → None（**无法判定**）。

    刻意不返回 0.0：0.0 会让「增长 < 5%」这条断言无条件成立，等于用一条
    永真断言冒充内存泄漏检查（docs/10 §0 的「绿灯替代有效」）。**「缺证据」
    与「无泄漏」不是一回事** —— 故稳态样本 < 4 时判 FAIL 而非 PASS。
    """
    vals = [int(r[col]) for r in steady if r[col] not in ("", "None")]
    if len(vals) < 4:
        return None
    head = sum(vals[:2]) / 2   # 稳态区间最早 2 个样本
    tail = sum(vals[-2:]) / 2  # 运行末 2 个样本
    if head <= 0:
        return None
    return (tail - head) / head * 100


fp_growth = growth(2)
ad_growth = growth(3)
probe_total = len(rows)
ok = (
    crashes == 0
    and probe_fail == 0
    and rss_fail == 0
    and probe_total > 0
    and fp_growth is not None
    and ad_growth is not None
    and fp_growth < 5.0
    and ad_growth < 5.0
)
summary = {
    "result": "PASS" if ok else "FAIL",
    "duration_s": duration,
    "warmup_s": warmup,
    "samples": probe_total,
    "steady_samples": len(steady),
    "crashes": crashes,
    "probe_failures": probe_fail,
    "rss_sample_failures": rss_fail,
    "fp_rss_growth_pct": None if fp_growth is None else round(fp_growth, 2),
    "ad_rss_growth_pct": None if ad_growth is None else round(ad_growth, 2),
    "thresholds": {"rss_growth_pct": 5.0, "crashes": 0, "probe_failures": 0},
}
(Path(run_dir) / "last_run.json").write_text(
    json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
)
print(json.dumps(summary, ensure_ascii=False))
sys.exit(0 if ok else 1)
PYEOF
JUDGE=$?
if [ "$JUDGE" -ne 0 ]; then
    echo "FAIL (Q8)：稳定性判定未通过。摘要：$RUN_DIR/last_run.json"
    echo "  诊断入口：$RUN_DIR/probe.log（探针失败明细）、$RUN_DIR/timeseries.csv（采样序列）"
    # 区分「无法判定」与「真的没通过」：前者说明窗口不足，不代表系统不可靠。
    STEADY=$("$PY" -c "import json,sys; print(json.load(open(sys.argv[1]))['steady_samples'])" \
        "$RUN_DIR/last_run.json" 2>/dev/null)
    if [ -n "$STEADY" ] && [ "$STEADY" -lt 4 ]; then
        echo "  注：steady_samples=${STEADY} < 4 —— 属「**无法判定**」而非「未通过」："
        echo "      运行时长不足以覆盖预热窗口（--warmup ${WARMUP}s）。请加长 --duration 后重试。"
    fi
    exit 1
fi
echo "OK (Q8)：稳定性测试通过（duration=${ACTUAL_DURATION}s warmup=${WARMUP}s samples=$SEQ）。"
