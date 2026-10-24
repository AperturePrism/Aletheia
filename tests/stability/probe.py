"""Q8 稳定性探针（tests/stability/probe.py）。

稳定性 harness 的一轮负载注入：对 alethd 与 focalplane 各做一次真实
gRPC 往返，验证「进程活着且契约调用成功」。失败以非零退出码向上报告，
由 run.sh 累计。

探针只验证 **契约往返**（RPC 成功即算通过），不校验业务结论 —— 业务
正确性由单元/契约测试覆盖，这里关注的是长时运行的可用性。

**端口**：两个探针目标端口都是 run.sh 显式传入的（`--alethd` / `--focalplane`），
不要依赖这里的默认值做真实运行。alethd 的 gRPC 与 HTTP/WebUI **分端口**
（`server.grpc_port` vs `server.port`）—— 早先 probe 默认连着 HTTP 端口
7723，导致 gRPC 探针 100% 失败，故此处默认值同步为 gRPC 端口 7724。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import grpc
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aletheia.gen.aleth.v1 import aletheia_pb2 as pb
from aletheia.gen.aleth.v1.aletheia_pb2_grpc import LedgerServiceStub

# G-1 执行绑定的签名输入域，必须与 focalplane/execverifier.py 的
# EXEC_ID_SIGN_DOMAIN 完全一致（域分离，见 docs/CHANGELOG R-1）。
_SIGN_DOMAIN = b"aleth/exec-id/v1\x00"

# 单次 RPC 超时（秒）。长跑 harness 里**任何**无超时的 RPC 都是隐患：
# 对端一次无响应就会永久挂住，24h 测试会停在那里却不报错 —— 表现为
# 「跑到某一轮就不动了」，而不是判定失败。取值按「探测可用性」的用途
# 放宽，不追求低延迟。
_RPC_TIMEOUT_S = 10


def _load_privkey(hex_path: Path) -> Ed25519PrivateKey:
    raw = bytes.fromhex(hex_path.read_text(encoding="utf-8").strip())
    return Ed25519PrivateKey.from_private_bytes(raw)


def main() -> int:
    ap = argparse.ArgumentParser(description="stability probe: one round of contract round-trips")
    ap.add_argument(
        "--alethd",
        default="127.0.0.1:7724",
        help="alethd gRPC 地址（server.grpc_port，非 HTTP 端口）",
    )
    ap.add_argument("--focalplane", default="127.0.0.1:7728")
    ap.add_argument(
        "--key-hex", required=True, help="probe Ed25519 私钥（hex），与 focalplane 公钥同对"
    )
    ap.add_argument("--seq", type=int, default=0, help="本轮序号（写入 evidence 使每轮负载唯一）")
    ap.add_argument(
        "--idempotent",
        action="store_true",
        help="Append 用幂等重放语义（重启后重放历史轮次返回既有记录）",
    )
    args = ap.parse_args()

    failures: list[str] = []

    # ---- alethd：IngestService 契约往返 ----
    try:
        ch = grpc.insecure_channel(args.alethd)
        from aletheia.gen.aleth.v1.aletheia_pb2_grpc import IngestServiceStub

        stub = IngestServiceStub(ch)
        resp = stub.ListAdapters(pb.ListAdaptersRequest(), timeout=_RPC_TIMEOUT_S)
        if resp.total < 1:
            failures.append("alethd ListAdapters returned 0 adapters")
        stub.ValidateTool(pb.ValidateToolRequest(tool_name="nmap"), timeout=_RPC_TIMEOUT_S)
        ch.close()
    except grpc.RpcError as exc:
        failures.append(f"alethd RPC failed: {exc.code()}")

    # ---- focalplane：证据 append 往返（G-1 验签路径真实执行）----
    try:
        ch = grpc.insecure_channel(args.focalplane)
        stub = LedgerServiceStub(ch)
        priv = _load_privkey(Path(args.key_hex))

        exec_id = f"exec_stab_{args.seq:08d}"
        entry = pb.EvidenceEntry()
        entry.evidence_id = "ev_" + exec_id[5:]
        entry.exec_id = exec_id
        entry.tool.tool_name = "stability-probe"
        entry.raw.content_hash = "0" * 64
        entry.raw.storage_uri = f"/tmp/stability/{args.seq}"
        signed = pb.SignedExecId()
        signed.exec_id = exec_id
        signed.signature = priv.sign(_SIGN_DOMAIN + exec_id.encode("utf-8")).hex()

        result = stub.Append(
            pb.AppendEvidenceRequest(
                entry=entry, signed_exec_id=signed, idempotent=args.idempotent
            ),
            timeout=_RPC_TIMEOUT_S,
        )
        if result.error.code != 0:
            failures.append(f"focalplane Append error: {result.error.message}")
        if result.self_hash == "":
            failures.append("focalplane Append returned empty self_hash")
        ch.close()
    except grpc.RpcError as exc:
        failures.append(f"focalplane RPC failed: {exc.code()}")

    if failures:
        for f in failures:
            print(f"PROBE_FAIL: {f}", file=sys.stderr)
        return 1
    print("PROBE_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
