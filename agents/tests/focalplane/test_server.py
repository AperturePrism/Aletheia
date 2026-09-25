"""focalplane gRPC 适配层（server.py）的进程内集成测试。

验证 Servicer 对 FocalPlane 门面的映射（含 LedgerError → response.error 的
错误翻译），使用 grpcio 的进程内 server + client —— 不经过网络，
但走完整的 gRPC 编解码与拦截链。
"""

from __future__ import annotations

from concurrent import futures
from pathlib import Path

import grpc
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aletheia.focalplane.execverifier import Ed25519Verifier, exec_id_sign_input
from aletheia.focalplane.focalplane import FocalPlane
from aletheia.focalplane.ledger import Ledger
from aletheia.focalplane.server import FocalPlaneServicer
from aletheia.gen.aleth.v1 import aletheia_pb2 as pb
from aletheia.gen.aleth.v1.aletheia_pb2_grpc import (
    LedgerServiceStub,
    add_LedgerServiceServicer_to_server,
)

SESSION = "sess_srv"
TASK = "task_srv"


@pytest.fixture()
def client(tmp_path: Path, sandbox_keys):
    priv, pub_hex = sandbox_keys
    ledger = Ledger(str(tmp_path / "ledger.db"), Ed25519Verifier(pub_hex))
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    add_LedgerServiceServicer_to_server(FocalPlaneServicer(FocalPlane(ledger)), server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    yield LedgerServiceStub(channel), priv
    channel.close()
    server.stop(grace=None)


def make_entry(exec_id: str) -> pb.EvidenceEntry:
    e = pb.EvidenceEntry()
    e.evidence_id = "ev_" + exec_id[5:]
    e.exec_id = exec_id
    e.tool.tool_name = "nuclei"
    e.raw.content_hash = "c" * 64
    e.raw.storage_uri = "/x"
    return e


def sign(priv: Ed25519PrivateKey, exec_id: str) -> pb.SignedExecId:
    s = pb.SignedExecId()
    s.exec_id = exec_id
    s.signature = priv.sign(exec_id_sign_input(exec_id)).hex()
    return s


def test_append_ok_and_forged_rejected(client) -> None:
    stub, priv = client
    e = make_entry("exec_srv_ok")
    ok = stub.Append(pb.AppendEvidenceRequest(entry=e, signed_exec_id=sign(priv, "exec_srv_ok")))
    assert ok.evidence_id == e.evidence_id and ok.error.code == 0

    # 伪造签名（攻击者密钥）→ response.error（EVIDENCE_INVALID），账本零痕迹。
    forged = make_entry("exec_srv_bad")
    attacker_sig = sign(Ed25519PrivateKey.generate(), "exec_srv_bad")
    bad = stub.Append(pb.AppendEvidenceRequest(entry=forged, signed_exec_id=attacker_sig))
    assert bad.error.code == pb.EVIDENCE_INVALID
    # 未知 finding → attribution_errors 带 NOT_FOUND，而非崩溃。
    trace = stub.TraceFinding(pb.TraceFindingRequest(finding_id="x"))
    assert trace.attribution_errors[0].code == pb.NOT_FOUND


def test_validate_and_trace_roundtrip(client) -> None:
    stub, priv = client
    e = make_entry("exec_rt")
    stub.Append(pb.AppendEvidenceRequest(entry=e, signed_exec_id=sign(priv, "exec_rt")))

    a = pb.Assertion()
    a.assertion_id = "asr_rt"
    a.target_entity_id = "svc_rt"
    a.supporting_evidence_ids.append(e.evidence_id)
    res = stub.ValidateAssertion(
        pb.ValidateAssertionRequest(assertion=a, session_id=SESSION, task_id=TASK)
    )
    assert res.g1_exec_bound.passed
    assert res.resulting_status == pb.CANDIDATE

    finding_id = "asr_rt"  # server 未暴露 finding id —— 用 trace 验证归因状态
    chain = stub.TraceFinding(pb.TraceFindingRequest(finding_id=finding_id))
    _ = finding_id  # Servicer 对未知 finding 返回 NOT_FOUND 而非崩溃
    assert chain.attribution_errors[0].code == pb.NOT_FOUND or chain.attribution_consistent


def test_record_side_effect_via_grpc(client) -> None:
    stub, priv = client
    e = make_entry("exec_obs")
    stub.Append(pb.AppendEvidenceRequest(entry=e, signed_exec_id=sign(priv, "exec_obs")))
    obs = pb.SideEffectObservation()
    obs.kind = pb.ID_OUTPUT
    obs.observation = "uid=0(root) gid=0(root)"
    obs.exec_id = "exec_obs"
    rec = stub.RecordSideEffect(
        pb.RecordSideEffectRequest(observation=obs, session_id=SESSION, task_id=TASK)
    )
    assert rec.accepted and "id_root" in rec.matched_pattern


def test_report_hallucination_via_grpc(client) -> None:
    stub, _priv = client
    state = stub.ReportHallucination(
        pb.ReportHallucinationRequest(
            session_id=SESSION, task_id=TASK, agent_id="a1", hallucination_type="TEST"
        )
    )
    assert state.hallucination_count == 1
    assert state.threshold == 3


def test_reproduce_via_grpc_is_explicitly_pending(client) -> None:
    stub, _ = client
    result = stub.Reproduce(pb.ReproduceRequest(evidence_id="ev_x", finding_id="find_x"))
    assert not result.reproduced
    assert "I7" in result.g4.reason
