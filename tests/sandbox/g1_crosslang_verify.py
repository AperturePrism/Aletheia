"""G-1 跨语言验签往返 e2e（NAS 部署验证的核心断言）。

链路：alethd 的 SandboxService.SignExecId（Go，Ed25519 签发）→
focalplane 的 Ed25519Verifier（Python，M4 独立验签实现）核对。
通过 = Go 侧签名域与 Python 侧字节级一致在真实部署中得到证明，
M4「独立验签」的跨语言前提成立。

前置：
  · alethd 以含 SandboxService 的构建运行（PR #20 起）；
  · sandbox.exec_key_file 指向的密钥与 --pubkey-hex 是同对
    （NAS 用既有 probe_key.hex / probe_pub.hex）。
  · focalplane 以对应公钥运行（验签对端真实在线时同时可走 Append 路径）。

用法：docker exec <容器> sh -c 'cd /work && PYTHONPATH=/app/app python /work/g1_crosslang_verify.py --pubkey-hex $(cat /work/probe_pub.hex)'
"""

from __future__ import annotations

import argparse
import sys

import grpc

from aletheia.focalplane.execverifier import Ed25519Verifier
from aletheia.gen.aleth.v1 import aletheia_pb2 as pb
from aletheia.gen.aleth.v1.aletheia_pb2_grpc import SandboxServiceStub

ALETHD = "127.0.0.1:7724"

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--pubkey-hex", required=True, help="Sandbox Ed25519 公钥（与 alethd 私钥同对）"
    )
    ap.add_argument("--alethd", default=ALETHD)
    args = ap.parse_args()

    stub = SandboxServiceStub(grpc.insecure_channel(args.alethd))
    verifier = Ed25519Verifier(args.pubkey_hex)

    # 1. 预签发往返：SignExecId → focalplane 验签器核对
    a = stub.SignExecId(
        pb.SignExecIdRequest(session_id="g1x", task_id="g1x", purpose="cross-lang verify"),
        timeout=15,
    )
    check(
        "SignExecId 签发（Go 侧）", bool(a.exec_id) and bool(a.signature), f"exec={a.exec_id[:20]}…"
    )
    v = verifier.verify(a.exec_id, a.signature)
    check("Python 侧 focalplane 验签通过（跨语言 G-1）", v.passed, v.reason)

    # 2. 伪造对照：篡改 exec_id 后验签必须失败（域绑定有效）
    v_bad = verifier.verify(a.exec_id + "x", a.signature)
    check("篡改 exec_id 验签被拒（域绑定）", not v_bad.passed)

    # 3. 唯一性：两次签发不同 exec_id
    b = stub.SignExecId(pb.SignExecIdRequest(purpose="uniqueness"), timeout=15)
    check("exec_id 唯一签发", a.exec_id != b.exec_id)

    # 4. （可选）focalplane 在线时走完整 Append 路径：签名经 M4 Append 的
    #    G-1 验签真实入库 —— 这是生产路径（非仅验签器单测形态）。
    try:
        from aletheia.gen.aleth.v1.aletheia_pb2_grpc import LedgerServiceStub

        ledger = LedgerServiceStub(grpc.insecure_channel("127.0.0.1:7728"))
        entry = pb.EvidenceEntry()
        entry.evidence_id = "ev_g1x_" + a.exec_id[5:20]
        entry.exec_id = a.exec_id
        entry.tool.tool_name = "g1-crosslang"
        entry.raw.content_hash = "e" * 64
        entry.raw.storage_uri = "cas://g1x"
        signed = pb.SignedExecId()
        signed.exec_id = a.exec_id
        signed.signature = a.signature
        r = ledger.Append(
            pb.AppendEvidenceRequest(entry=entry, signed_exec_id=signed, idempotent=True),
            timeout=15,
        )
        check(
            "签名经 focalplane Append 的 G-1 验签入库（生产路径）",
            r.error.code == 0 and r.self_hash != "",
            f"self_hash={r.self_hash[:12]}… err={r.error.message[:60]}",
        )
    except grpc.RpcError as exc:
        print(f"SKIP  focalplane Append 路径（{exc.code()}）—— 仅验签器断言已足够")

    print()
    if failures:
        print(f"G1 CROSS-LANG FAILED: {failures}")
        return 1
    print("G1 CROSS-LANG OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
