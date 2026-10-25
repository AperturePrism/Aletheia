"""G-4 真实部署环境验证（NAS focalplane 进程，gRPC 全链路）。

DoD 措辞（docs/04 §I7）：「G-4 独立复现可运行，单次复现 < 10 min」。
本脚本验证执行器在真实部署（容器内常驻 focalplane）可运行：
  1. 经 gRPC Append 登记证据（带签名 exec_id）
  2. RecordSideEffect 登记 ID_OUTPUT 强观测（id_root 模式命中 → accepted）
  3. ValidateAssertion → CANDIDATE
  4. Reproduce（steps 为容器内真实可跑的确定性命令；环境哈希 = 本容器
     ProcessBackend 指纹）→ 断言 reproduced + finding CONFIRMED + 耗时
  5. 失败对照：环境哈希不匹配的 Reproduce → 拒绝

诚实边界：步骤用 echo 还原观测文本 —— 验证的是执行器机制在真实部署
可运行（DoD 的「可运行」），不是真实漏洞重放；后者待 Sandbox 装配
（P1 交付项，见 DEC 文档登记）。
"""

from __future__ import annotations

import sqlite3
import sys
import time
from pathlib import Path

import grpc
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aletheia.focalplane.repro import ProcessBackend
from aletheia.gen.aleth.v1 import aletheia_pb2 as pb
from aletheia.gen.aleth.v1.aletheia_pb2_grpc import LedgerServiceStub

FOCAL = "127.0.0.1:7728"
KEY = "/work/probe_key.hex"
DB = "/work/ledger.db"
SIGN_DOMAIN = b"aleth/exec-id/v1\x00"

#: id_root 模式（patterns.py）的正例观测文本。
OBS = "uid=0(root) gid=0(root) groups=0(root)"
#: 确定性步骤：echo 多参数由 shell 以空格连接，还原出同样的观测形态。
STEPS = ["echo uid=0(root) gid=0(root) groups=0(root)"]

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def main() -> int:
    stub = LedgerServiceStub(grpc.insecure_channel(FOCAL))
    with Path(KEY).open() as f:
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f.read().strip()))
    env_hash = ProcessBackend().fingerprint()

    exec_id = "exec_g4_verify_1"
    entry = pb.EvidenceEntry()
    entry.evidence_id = "ev_g4_verify_1"
    entry.exec_id = exec_id
    entry.tool.tool_name = "g4-verify"
    entry.raw.content_hash = "d" * 64
    entry.raw.storage_uri = "cas://g4/1"

    signed = pb.SignedExecId()
    signed.exec_id = exec_id
    signed.signature = priv.sign(SIGN_DOMAIN + exec_id.encode()).hex()

    r = stub.Append(
        pb.AppendEvidenceRequest(entry=entry, signed_exec_id=signed, idempotent=True), timeout=15
    )
    check("证据入账（G-1 验签路径）", r.error.code == 0, f"self_hash={r.self_hash[:12]}…")

    obs = pb.SideEffectObservation()
    obs.kind = pb.ID_OUTPUT
    obs.observation = OBS
    obs.exec_id = exec_id
    ro = stub.RecordSideEffect(
        pb.RecordSideEffectRequest(observation=obs, session_id="g4v", task_id="g4v"),
        timeout=15,
    )
    check("副作用观测被接受（id_root 命中）", ro.accepted, f"pattern={ro.matched_pattern}")

    a = pb.Assertion()
    a.assertion_id = "as_g4_verify_1"
    a.statement = "svc_3000_juice 存在命令执行，可获 root 身份观测"
    a.type = pb.EXPLOITABILITY
    a.target_entity_id = "svc_3000_juice"
    a.supporting_evidence_ids.append(entry.evidence_id)
    rv = stub.ValidateAssertion(
        pb.ValidateAssertionRequest(assertion=a, session_id="g4v", task_id="g4v"),
        timeout=15,
    )
    check("断言到达 CANDIDATE（G-1/2/3 过）", rv.resulting_status == pb.CANDIDATE)

    con = sqlite3.connect(DB)
    fid = con.execute(
        "SELECT f.finding_id FROM findings f JOIN finding_assertions fa ON f.finding_id=fa.finding_id"
        " WHERE fa.assertion_id='as_g4_verify_1'"
    ).fetchone()[0]
    con.close()
    print(f"      finding_id={fid}")

    # 失败对照先行（此时仍是 CANDIDATE）：环境哈希不匹配 → fail-closed 拒绝
    bad = pb.ReproSpec()
    bad.steps.extend(STEPS)
    bad.environment_hash = "0" * 64
    bad.estimated_minutes = 1.0
    rb = stub.Reproduce(
        pb.ReproduceRequest(evidence_id=entry.evidence_id, finding_id=fid, spec=bad),
        timeout=30,
    )
    check("环境哈希不匹配被拒（fail-closed）", not rb.reproduced and "mismatch" in rb.g4.reason)

    spec = pb.ReproSpec()
    spec.steps.extend(STEPS)
    spec.environment_hash = env_hash
    spec.estimated_minutes = 1.0

    t0 = time.monotonic()
    rr = stub.Reproduce(
        pb.ReproduceRequest(evidence_id=entry.evidence_id, finding_id=fid, spec=spec),
        timeout=620,
    )
    elapsed = time.monotonic() - t0
    check("G-4 复现成功", rr.reproduced, f"{elapsed:.2f}s（DoD < 10min）: {rr.g4.reason}")
    check("exec_id 签发", rr.reproduction_exec_id.startswith("repro_"))

    con = sqlite3.connect(DB)
    status = con.execute("SELECT status FROM findings WHERE finding_id=?", (fid,)).fetchone()[0]
    con.close()
    check("finding 已 CONFIRMED（唯一入口）", status == "CONFIRMED", f"status={status}")

    print()
    if failures:
        print(f"G4 VERIFY FAILED: {failures}")
        return 1
    print("G4 VERIFY OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
