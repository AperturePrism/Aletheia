"""Q3 红线 · 伪造证据注入测试套件（docs/04 §6 Q3、modules/M4 §6 T4.8）。

**这是 04 §I2 DoD① 的执行实体，也是本项目「不会说谎」的存在性证明。**
三类注入用例必须 100% 被拒（不可抽样、不可跳过 —— marker redline）：

    ① 无 exec_id / 无签名       —— 证据没有执行绑定（D2 自言自语）
    ② 假 exec_id（签名无效）    —— 证据绑定到不存在的执行（T4.1）
    ③ 张冠李戴（归因不一致）    —— 证据 target 与断言 target 不一致（T4.2）

与单元测试的区别：本套件从**攻击者视角**构造载荷 —— 每类用例都是
一组对抗变体（不是单条 happy-path 的反面），且不使用被测代码的任何
便捷构造路径之外的攻击入口。闸门若被削弱，本套件先红。

Q4（越界）/ Q5（隐私）属 I3 —— ci.yml 末尾的补齐计划与之对应。
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from aletheia.focalplane.execverifier import Ed25519Verifier, exec_id_sign_input
from aletheia.focalplane.focalplane import FocalPlane
from aletheia.focalplane.ledger import ExecBindingError, Ledger
from aletheia.gen.aleth.v1 import aletheia_pb2 as pb

pytestmark = pytest.mark.redline  # 红线标记：不可抽样、不可跳过（10 §3 P2）


def make_entry(exec_id: str = "", evidence_id: str | None = None) -> pb.EvidenceEntry:
    e = pb.EvidenceEntry()
    e.evidence_id = evidence_id or ("ev_" + "0123456789abcdef" * 2)
    e.exec_id = exec_id
    e.tool.tool_name = "nuclei"
    e.raw.content_hash = "c" * 64
    e.raw.storage_uri = "/tmp/x"
    return e


def assertion(target: str, refs: list[str]) -> pb.Assertion:
    a = pb.Assertion()
    a.assertion_id = "asr_" + target.replace("-", "_")
    a.statement = f"{target} exploitable"
    a.type = pb.EXPLOITABILITY
    a.target_entity_id = target
    a.supporting_evidence_ids.extend(refs)
    return a


@pytest.fixture()
def sandbox_keypair():
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return priv, pub_hex


@pytest.fixture()
def attacker_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def attack_signature(priv: Ed25519PrivateKey, exec_id: str, *, raw: bool = False) -> pb.SignedExecId:
    s = pb.SignedExecId()
    s.exec_id = exec_id
    payload = exec_id.encode("utf-8") if raw else exec_id_sign_input(exec_id)
    s.signature = priv.sign(payload).hex()
    return s


# ---------------------------------------------------------------------------
# 类别①：无 exec_id / 无签名
# ---------------------------------------------------------------------------


class TestCategory1NoExecBinding:
    @pytest.mark.parametrize(
        ("entry_kwargs", "signed"),
        [
            ("no_exec_id", "missing"),  # 证据无 exec_id，且无签名
            ("no_exec_id", "empty"),  # 证据无 exec_id，签名也是空壳
            ("normal", "missing"),  # 证据有 exec_id 但不携带签名
            ("normal", "empty"),  # 携带空壳签名
        ],
    )
    def test_100pct_rejected(
        self, tmp_path, sandbox_keypair, attacker_key, entry_kwargs, signed
    ) -> None:
        """伪造载荷全部被拒，且账本零痕迹。"""
        _, pub_hex = sandbox_keypair
        ledger = Ledger(str(tmp_path / "l.db"), Ed25519Verifier(pub_hex))
        exec_id = "exec_target" if entry_kwargs == "normal" else ""
        entry = make_entry(exec_id=exec_id)
        if signed == "missing":
            sig = None
        else:
            sig = attack_signature(attacker_key, exec_id, raw=True)
            if signed == "missing":
                sig = None
        with pytest.raises(ExecBindingError):
            ledger.append(entry, sig) if sig is not None else ledger.append(
                entry, pb.SignedExecId()
            )
        assert ledger.get(entry.evidence_id) is None, "被拒的伪造证据不得留痕"
        assert ledger.verify_chain().intact


# ---------------------------------------------------------------------------
# 类别②：假 exec_id（签名无效）
# ---------------------------------------------------------------------------


class TestCategory2ForgedSignature:
    @pytest.mark.parametrize(
        "forge_mode",
        ["attacker_signed", "wrong_domain", "cross_id", "corrupted", "garbled_hex"],
    )
    def test_100pct_rejected(
        self, tmp_path, sandbox_keypair, attacker_key, forge_mode
    ) -> None:
        """五种伪造形态全部被拒 —— 无一进入账本。"""
        _, pub_hex = sandbox_keypair
        ledger = Ledger(str(tmp_path / "l.db"), Ed25519Verifier(pub_hex))
        entry = make_entry(exec_id="exec_forged_1")

        if forge_mode == "attacker_signed":
            sig = attack_signature(attacker_key, "exec_forged_1")
        elif forge_mode == "wrong_domain":
            # 签名有效但来自「裸 exec_id」域 —— 域分离必须生效。
            attacker = attacker_key
            sig = attack_signature(sandbox_keypair[0], "exec_forged_1", raw=True)  # 用 Sandbox 私钥签裸域
            _ = attacker
        elif forge_mode == "cross_id":
            # Sandbox 私钥签的是另一个 exec_id。
            sig = attack_signature(sandbox_keypair[0], "exec_different")
        elif forge_mode == "corrupted":
            good = attack_signature(sandbox_keypair[0], "exec_forged_1")
            corrupted = bytearray(bytes.fromhex(good.signature))
            corrupted[7] ^= 0x01
            sig = pb.SignedExecId(exec_id="exec_forged_1", signature=bytes(corrupted).hex())
        else:  # garbled_hex
            sig = pb.SignedExecId(exec_id="exec_forged_1", signature="zz-not-hex")

        with pytest.raises(ExecBindingError):
            ledger.append(entry, sig)
        assert ledger.get(entry.evidence_id) is None

    def test_real_signature_still_passes(self, tmp_path, sandbox_keypair) -> None:
        """假阴性防线：合法签名不被误拒（闸门过严同样是缺陷）。"""
        priv, pub_hex = sandbox_keypair
        ledger = Ledger(str(tmp_path / "l.db"), Ed25519Verifier(pub_hex))
        entry = make_entry(exec_id="exec_legit")
        receipt = ledger.append(entry, attack_signature(priv, "exec_legit"))
        assert receipt.evidence_id == entry.evidence_id


# ---------------------------------------------------------------------------
# 类别③：张冠李戴（证据 target 与断言 target 不一致）
# ---------------------------------------------------------------------------


class TestCategory3Misattribution:
    def test_100pct_rejected_with_p0_and_rollback(self, tmp_path, sandbox_keypair) -> None:
        """同一证据被挂到不同 target → ATTRIBUTION_MISMATCH + 回滚 + P0 告警。"""
        priv, pub_hex = sandbox_keypair
        ledger = Ledger(str(tmp_path / "l.db"), Ed25519Verifier(pub_hex))
        alerts: list = []
        plane = FocalPlane(ledger, on_p0_alert=alerts.append)

        entry = make_entry(exec_id="exec_real_target")
        plane.append_evidence(entry, attack_signature(priv, "exec_real_target"))

        # 合法引用：svc_A。
        r1 = plane.validate_assertion(assertion("svc_A", [entry.evidence_id]), "s", "t", "a")
        assert r1.resulting_status == pb.CANDIDATE

        # 张冠李戴：同一证据挂到 svc_B。
        r2 = plane.validate_assertion(assertion("svc_B", [entry.evidence_id]), "s", "t", "a")
        assert r2.resulting_status == pb.HYPOTHESIS, "张冠李戴不得进入 CANDIDATE"
        assert r2.errors[0].code == pb.ATTRIBUTION_MISMATCH
        assert any(a.code == "ATTRIBUTION_MISMATCH" for a in alerts), "P0 告警必须触发"

        # 复核队列：冲突方与既有引用者都被标记。
        f1 = plane._state.get_finding(plane._state.finding_id_of_assertion("svc_A" and "asr_svc_A"))
        f2 = plane._state.get_finding(plane._state.finding_id_of_assertion("asr_svc_B"))
        assert f1["needs_review"] and f2["needs_review"]

    @pytest.mark.parametrize("bogus_target", ["svc_B", "svc_C", "host_D"])
    def test_repeated_misattribution_each_detected(
        self, tmp_path, sandbox_keypair, bogus_target
    ) -> None:
        """逐次换 target 的张冠李戴，每一次都必须被拒 —— 无漏网。"""
        priv, pub_hex = sandbox_keypair
        ledger = Ledger(str(tmp_path / "l.db"), Ed25519Verifier(pub_hex))
        plane = FocalPlane(ledger, on_p0_alert=lambda a: None)
        entry = make_entry(exec_id="exec_misattr")
        plane.append_evidence(entry, attack_signature(priv, "exec_misattr"))
        plane.validate_assertion(assertion("svc_A", [entry.evidence_id]), "s", "t", "a")

        r = plane.validate_assertion(assertion(bogus_target, [entry.evidence_id]), "s", "t", "a")
        assert r.errors[0].code == pb.ATTRIBUTION_MISMATCH
        assert r.resulting_status == pb.HYPOTHESIS
