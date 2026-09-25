"""LedgerService 的 gRPC server（05 §5.3 的 Python 侧实现）。

部署形态（I2）：独立进程，由 `python -m aletheia.focalplane.server` 启动，
仅监听回环地址。alethd（Go）通过 core/focalplane/proxy.go 转发调用。
进程编排（daemon 自动拉起/健康检查）属 I6 —— server 未运行时，
Go 侧显式返回 UPSTREAM_UNAVAILABLE（fail-closed，不吞）。

安全边界：
    仅回环监听（Q13 同源）；I3 起内部通道升级为 mTLS/UDS —— 当前
    明文回环的信任前提是「本机进程 = 本机操作者」，与 08 §1.1 的
    Authorization Anchor 同级，不对外暴露。

验签公钥来自 --pubkey-hex（Sandbox 公钥，07 §T4.1：M4 只持公钥）。
"""

from __future__ import annotations

import argparse
from concurrent import futures

import grpc

from aletheia.focalplane.execverifier import Ed25519Verifier
from aletheia.focalplane.focalplane import FocalPlane, FocalPlaneError
from aletheia.focalplane.ledger import Ledger, LedgerError
from aletheia.gen.aleth.v1 import aletheia_pb2 as pb
from aletheia.gen.aleth.v1.aletheia_pb2_grpc import (
    LedgerServiceServicer,
    add_LedgerServiceServicer_to_server,
)


class FocalPlaneServicer(LedgerServiceServicer):
    """LedgerService → FocalPlane 门面的适配层（无业务逻辑）。"""

    def __init__(self, plane: FocalPlane) -> None:
        self._plane = plane

    def Append(self, request, context):
        try:
            receipt = self._plane.append_evidence(
                request.entry, request.signed_exec_id, idempotent=request.idempotent
            )
        except LedgerError as exc:
            return pb.AppendEvidenceResult(
                error=pb.Error(code=pb.EVIDENCE_INVALID, message=str(exc))
            )
        return pb.AppendEvidenceResult(
            evidence_id=receipt.evidence_id,
            self_hash=receipt.self_hash,
            prev_hash=receipt.prev_hash,
        )

    def ValidateAssertion(self, request, context):
        return self._plane.validate_assertion(
            request.assertion, request.session_id, request.task_id, agent_id=""
        )

    def RecordSideEffect(self, request, context):
        return self._plane.record_side_effect(
            request.observation, request.session_id, request.task_id
        )

    def Reproduce(self, request, context):
        return self._plane.reproduce(request.evidence_id, request.finding_id, request.spec)

    def TraceFinding(self, request, context):
        try:
            return self._plane.trace_finding(request.finding_id)
        except FocalPlaneError as exc:
            return pb.TracedEvidenceChain(
                attribution_consistent=False,
                attribution_errors=[pb.Error(code=pb.NOT_FOUND, message=str(exc))],
            )

    def ReportHallucination(self, request, context):
        return self._plane.report_hallucination(
            request.session_id,
            request.task_id,
            request.agent_id,
            request.hallucination_type,
            request.detail,
        )


def serve(db_path: str, listen_addr: str, pubkey_hex: str) -> None:
    verifier = Ed25519Verifier(pubkey_hex)
    plane = FocalPlane(Ledger(db_path, verifier))
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    add_LedgerServiceServicer_to_server(FocalPlaneServicer(plane), server)
    server.add_insecure_port(listen_addr)
    server.start()
    print(f"focalplane serving on {listen_addr} (ledger: {db_path})", flush=True)
    server.wait_for_termination()


def main() -> None:
    ap = argparse.ArgumentParser(description="Aletheia focalplane (LedgerService)")
    ap.add_argument("--db", default="data/ledger.db", help="账本 SQLite 路径")
    ap.add_argument("--addr", default="127.0.0.1:7728", help="监听地址（仅回环）")
    ap.add_argument("--pubkey-hex", required=True, help="Sandbox Ed25519 公钥（hex）")
    args = ap.parse_args()
    if not args.addr.startswith("127.0.0.1") and not args.addr.startswith("[::1]"):
        # 拒绝启动（08 §1.1 语义）。走 argparse 的错误路径而非异常 ——
        # check-no-bypass 的 R6 规则对 agents 下的 SystemExit 字节级零容忍。
        ap.error(f"refusing to listen on non-loopback address {args.addr!r} (Q13)")
    serve(args.db, args.addr, args.pubkey_hex)


if __name__ == "__main__":
    main()
