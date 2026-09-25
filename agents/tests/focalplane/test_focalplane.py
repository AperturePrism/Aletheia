"""FocalPlane 门面的测试：四道闸门、状态机、归因双向校验、幻觉计数。

覆盖 modules/M4 §6 的「状态机覆盖 / 归因冲突 / 副作用模式正反例」与
04 §I2 DoD②③。Q3 三类注入用例中，①②的账本层在 test_ledger.py，
③（张冠李戴）与完整闸门链在本文件。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aletheia.focalplane import patterns
from aletheia.focalplane.execverifier import Ed25519Verifier, exec_id_sign_input
from aletheia.focalplane.focalplane import FocalPlane, FocalPlaneError
from aletheia.focalplane.ledger import Ledger
from aletheia.gen.aleth.v1 import aletheia_pb2 as pb


def sign_exec_id(priv: Ed25519PrivateKey, exec_id: str) -> pb.SignedExecId:
    """Sandbox 签发（hex 文本承载，与 conftest 同约定）。"""
    out = pb.SignedExecId()
    out.exec_id = exec_id
    out.signature = priv.sign(exec_id_sign_input(exec_id)).hex()
    return out


SESSION = "sess_test"
TASK = "task_test"
AGENT = "agent_recon"


def make_entry(exec_id: str) -> pb.EvidenceEntry:
    e = pb.EvidenceEntry()
    e.evidence_id = "ev_" + exec_id.replace("exec_", "")
    e.exec_id = exec_id
    e.tool.tool_name = "nuclei"
    e.tool.tool_version = "3.2.7.0"
    e.raw.content_hash = "c" * 64
    e.raw.storage_uri = "/tmp/evidence/x"
    return e


def make_assertion(assertion_id: str, target: str, refs: list[str]) -> pb.Assertion:
    a = pb.Assertion()
    a.assertion_id = assertion_id
    a.statement = f"{target} is exploitable (test assertion)"
    a.type = pb.EXPLOITABILITY
    a.target_entity_id = target
    a.supporting_evidence_ids.extend(refs)
    return a


@pytest.fixture()
def fp(tmp_path: Path, sandbox_keys: tuple[Ed25519PrivateKey, str]):
    priv, pub_hex = sandbox_keys
    ledger = Ledger(str(tmp_path / "ledger.db"), Ed25519Verifier(pub_hex))
    alerts: list = []
    plane = FocalPlane(ledger, on_p0_alert=alerts.append)
    return plane, ledger, priv, alerts


def append_real_evidence(plane: FocalPlane, priv: Ed25519PrivateKey, exec_id: str):
    """登记一条已通过 G-1 验签的真实证据。"""
    e = make_entry(exec_id)
    receipt = plane.append_evidence(e, sign_exec_id(priv, exec_id))
    return e, receipt


class TestGate1ExecutionBinding:
    def test_referencing_nonexistent_evidence_is_hallucination(self, fp) -> None:
        """G-1 失败：引用不存在的证据 = D2 自言自语 → 不产 Finding + 幻觉 +1。"""
        plane, _ledger, _priv, _alerts = fp
        a = make_assertion("asr_1", "svc_1", ["ev_nonexistent"])
        result = plane.validate_assertion(a, SESSION, TASK, AGENT)
        assert result.resulting_status == pb.HYPOTHESIS
        assert not result.g1_exec_bound.passed
        assert result.errors[0].code == pb.EVIDENCE_INVALID
        # 幻觉计数 +1 且 agent 未达熔断阈值（3）。
        state = plane.hallucination_state(SESSION, AGENT)
        assert state.hallucination_count == 1
        assert not state.agent_circuit_open
        # 不产生 Finding 记录（trace 不可能 —— assertion 未注册）。


class TestGate2AndStatusMachine:
    def test_g2_pass_reaches_candidate(self, fp) -> None:
        plane, _ledger, priv, _alerts = fp
        entry, _ = append_real_evidence(plane, priv, "exec_g2")
        a = make_assertion("asr_g2", "svc_1", [entry.evidence_id])
        result = plane.validate_assertion(a, SESSION, TASK, AGENT)
        assert result.g1_exec_bound.passed
        assert result.g2_assertion.passed
        # G-3 未登记观测 → fail（封顶）；G-4 pending → 不可 CONFIRMED。
        assert not result.g3_strength.passed
        assert not result.g4_reproduction.passed
        assert "pending (I7" in result.g4_reproduction.reason
        assert result.resulting_status == pb.CANDIDATE

    def test_g2_fail_is_rejected_with_reason(self, fp) -> None:
        """G-2 失败：证据携带绑定到别的执行的观测 → REJECTED（原因记录供 Refiner）。"""
        plane, _ledger, priv, _alerts = fp
        # 登记一条带「外来 exec 归属观测」的证据（append 幂等保护会拒绝
        # 同 ID 不同内容的重放 —— 所以这是一条独立证据，不做原地改写）。
        e2 = make_entry("exec_with_foreign_obs")
        foreign_obs = pb.SideEffectObservation()
        foreign_obs.kind = pb.ID_OUTPUT
        foreign_obs.observation = "uid=0(root) gid=0(root)"
        foreign_obs.matched_pattern = "id_root"
        foreign_obs.exec_id = "exec_somewhere_else"  # 归属别的执行
        e2.side_effects.append(foreign_obs)
        plane.append_evidence(e2, sign_exec_id(priv, "exec_with_foreign_obs"))

        a = make_assertion("asr_rej", "svc_1", [e2.evidence_id])
        result = plane.validate_assertion(a, SESSION, TASK, AGENT)
        assert result.resulting_status == pb.REJECTED
        assert not result.g2_assertion.passed
        assert "foreign exec" in result.g2_assertion.reason

    def test_confirmed_unreachable_in_i2(self, fp) -> None:
        """G-3 通过也只到 CANDIDATE（G-4 pending）—— I2 的设计边界。"""
        plane, _ledger, priv, _alerts = fp
        entry, _ = append_real_evidence(plane, priv, "exec_conf")
        obs = pb.SideEffectObservation()
        obs.kind = pb.ID_OUTPUT
        obs.observation = "uid=0(root) gid=0(root) groups=0(root)"
        obs.matched_pattern = ""  # 服务端重算，自述无效
        obs.exec_id = "exec_conf"
        rec = plane.record_side_effect(obs, SESSION, TASK)
        assert rec.accepted and "id_root" in rec.matched_pattern

        a = make_assertion("asr_conf", "svc_1", [entry.evidence_id])
        result = plane.validate_assertion(a, SESSION, TASK, AGENT)
        assert result.g3_strength.passed  # 强证据在
        assert not result.g4_reproduction.passed  # I7 前 pending
        assert result.resulting_status == pb.CANDIDATE


class TestGate3PatternLibrary:
    def test_weak_evidence_never_strong(self) -> None:
        """D1 反例：工具输出自述在任何 kind 下都不得命中强证据模式。"""
        weak_samples = [
            "exploit completed successfully",
            "Shellcodes",  # searchsploit 任何输出都含
            "login:",  # 任何服务回显都含
            "All tests passed!",
            "23/23 ports exploited, all root",  # 调研实测的幻觉报告原文
        ]
        for text in weak_samples:
            hits = patterns.audit_text(text)
            assert not hits, f"弱证据 {text!r} 被模式命中：{[p.name for p in hits]}"

    def test_pattern_positive_cases(self) -> None:
        # id(1) root 输出。
        hits = patterns.find_hits(pb.ID_OUTPUT, "uid=0(root) gid=0(root) groups=0(root)")
        assert any(p.name == "id_root" for p in hits)
        # /etc/passwd 行。
        hits = patterns.find_hits(
            pb.ACCOUNT_CREATED, "backdoor:x:1337:1337::/home/backdoor:/bin/sh\n"
        )
        assert any(p.name == "passwd_entry" for p in hits)

    def test_server_recomputes_pattern_not_client_claim(self, fp) -> None:
        """请求自报的 matched_pattern 不被采信 —— 服务端重算（T4 防御）。"""
        plane, _ledger, priv, _alerts = fp
        append_real_evidence(plane, priv, "exec_srv")
        obs = pb.SideEffectObservation()
        obs.kind = pb.ID_OUTPUT
        obs.observation = "totally benign output"  # 不含任何强证据形态
        obs.matched_pattern = "id_root"  # agent 自称命中
        obs.exec_id = "exec_srv"
        rec = plane.record_side_effect(obs, SESSION, TASK)
        assert not rec.accepted
        assert rec.matched_pattern == ""

    def test_observation_without_ledger_exec_rejected(self, fp) -> None:
        """观测的 exec_id 不在账本 → 拒收（观测必须绑定真实执行）。"""
        plane, _ledger, _priv, _alerts = fp
        obs = pb.SideEffectObservation()
        obs.kind = pb.ID_OUTPUT
        obs.observation = "uid=0(root) gid=0(root)"
        obs.exec_id = "exec_not_in_ledger"
        rec = plane.record_side_effect(obs, SESSION, TASK)
        assert not rec.accepted
        assert rec.error.code == pb.EVIDENCE_INVALID


class TestAttribution:
    def test_misattribution_triggers_p0_and_rollback(self, fp) -> None:
        """Q3 类别③：张冠李戴 → ATTRIBUTION_MISMATCH + 回滚 HYPOTHESIS + P0 告警。"""
        plane, _ledger, priv, alerts = fp
        entry, _ = append_real_evidence(plane, priv, "exec_attr")
        # 第一次引用：绑定到 svc_A → CANDIDATE。
        a1 = make_assertion("asr_attr_1", "svc_A", [entry.evidence_id])
        r1 = plane.validate_assertion(a1, SESSION, TASK, AGENT)
        assert r1.resulting_status == pb.CANDIDATE
        # 第二次引用同一证据但指向 svc_B → 张冠李戴。
        a2 = make_assertion("asr_attr_2", "svc_B", [entry.evidence_id])
        r2 = plane.validate_assertion(a2, SESSION, TASK, AGENT)
        assert r2.resulting_status == pb.HYPOTHESIS
        assert r2.errors[0].code == pb.ATTRIBUTION_MISMATCH
        # P0 告警已发出（04 §I2 DoD③）。
        assert any(alert.code == "ATTRIBUTION_MISMATCH" for alert in alerts)
        # 归因语义（05 §1.3 精确化）：冲突断言 a2 自身记 HYPOTHESIS；
        # 既有引用者 a1 是正确引用 —— 状态保留，但证据归因已被质疑，
        # 一并标记人工复核（保守面）。
        f_a1 = plane._state.get_finding(plane._state.finding_id_of_assertion("asr_attr_1"))
        f_a2 = plane._state.get_finding(plane._state.finding_id_of_assertion("asr_attr_2"))
        assert f_a1["status"] == "CANDIDATE" and f_a1["needs_review"]
        assert f_a2["status"] == "HYPOTHESIS" and f_a2["needs_review"]

    def test_confirmed_to_candidate_requires_legitimate_trigger(self, fp) -> None:
        """不可逆约束：CONFIRMED→CANDIDATE 仅允许 ATTRIBUTION_MISMATCH/人工复核。"""
        plane, _ledger, priv, _alerts = fp
        entry, _ = append_real_evidence(plane, priv, "exec_irr")
        a = make_assertion("asr_irr", "svc_1", [entry.evidence_id])
        plane.validate_assertion(a, SESSION, TASK, AGENT)
        finding_id = plane._state.finding_id_of_assertion("asr_irr")
        # 模拟 I7 之后可能存在的 CONFIRMED 态。
        plane._state._conn.execute(
            "UPDATE findings SET status = 'CONFIRMED' WHERE finding_id = ?", (finding_id,)
        )
        plane._state._conn.commit()
        # 非法回滚：无正当理由 → 拒绝。
        with pytest.raises(FocalPlaneError, match="illegal transition"):
            plane._state.transition(finding_id, pb.CANDIDATE, reason="just because", actor="test")
        # 合法回滚（归因冲突）→ 允许。
        plane._state.transition(
            finding_id,
            pb.CANDIDATE,
            reason="ATTRIBUTION_MISMATCH: foreign target",
            actor="test",
        )


class TestTrace:
    def test_trace_finding_full_chain(self, fp) -> None:
        plane, _ledger, priv, _alerts = fp
        entry, _ = append_real_evidence(plane, priv, "exec_trace")
        obs = pb.SideEffectObservation()
        obs.kind = pb.ID_OUTPUT
        obs.observation = "uid=0(root) gid=0(root)"
        obs.exec_id = "exec_trace"
        plane.record_side_effect(obs, SESSION, TASK)
        a = make_assertion("asr_trace", "svc_trace", [entry.evidence_id])
        res = plane.validate_assertion(a, SESSION, TASK, AGENT)
        finding_id = plane._state.finding_id_of_assertion("asr_trace")
        _ = res

        chain = plane.trace_finding(finding_id)
        assert chain.finding_id == finding_id
        assert [a.assertion_id for a in chain.assertions] == ["asr_trace"]
        assert [e.evidence_id for e in chain.evidence] == [entry.evidence_id]
        assert all("id_root" in s.matched_pattern for s in chain.side_effects)
        assert chain.attribution_consistent

    def test_trace_unknown_finding_raises(self, fp) -> None:
        plane, _ledger, _priv, _alerts = fp
        with pytest.raises(FocalPlaneError, match="not found"):
            plane.trace_finding("find_missing")


class TestHallucinationCircuitBreaker:
    def test_agent_threshold_opens_circuit(self, fp) -> None:
        """单个 agent 累计 3 次幻觉 → 熔断（M4 §4.6）。"""
        plane, _ledger, _priv, _alerts = fp
        for i in range(3):
            a = make_assertion(f"asr_h{i}", "svc_1", ["ev_ghost"])
            plane.validate_assertion(a, SESSION, TASK, "agent_bad")
        state = plane.hallucination_state(SESSION, "agent_bad")
        assert state.hallucination_count == 3
        assert state.agent_circuit_open
        # 其他 agent 不受影响。
        other = plane.hallucination_state(SESSION, "agent_ok")
        assert not other.agent_circuit_open

    def test_session_ratio_opens_circuit(self, fp) -> None:
        """会话级幻觉占比 > 10% → 整场熔断。"""
        plane, _ledger, priv, _alerts = fp
        # 11 次断言调用，2 次幻觉 ≈ 18% > 10%。
        for i in range(9):
            e, _ = append_real_evidence(plane, priv, f"exec_ok_{i}")
            a = make_assertion(f"asr_ok_{i}", "svc_1", [e.evidence_id])
            plane.validate_assertion(a, SESSION, TASK, f"agent_{i}")
        for i in range(2):
            a = make_assertion(f"asr_bad_{i}", "svc_1", ["ev_ghost"])
            plane.validate_assertion(a, SESSION, TASK, f"agent_bad_{i}")
        state = plane.hallucination_state(SESSION, "agent_bad_0")
        assert state.agent_circuit_open
        assert "ratio" in state.error.message


class TestReproduce:
    def test_g4_reproduction_explicitly_pending(self, fp) -> None:
        """I2 不伪造复现结论 —— G-4 显式 pending（I7 T4.9）。"""
        plane, _ledger, priv, _alerts = fp
        entry, _ = append_real_evidence(plane, priv, "exec_repro")
        result = plane.reproduce(entry.evidence_id, "find_x", pb.ReproSpec())
        assert not result.reproduced
        assert not result.g4.passed
        assert "I7" in result.g4.reason
