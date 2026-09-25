"""T4.1 账本存储 + append-only 接口 + 哈希链 的测试。

对应 modules/M4 §6「账本完整性 / 不可变性」与 04 §I2 DoD
（哈希链篡改检测有效、接口层确认无修改/删除路径）。

篡改检测测试的做法：测试扮演**攻击者**，绕过账本接口直接改 SQLite
行数据 —— verify_chain 必须检出并指出断点。账本自身的防御边界
（接口层无写路径）由 TestNoMutationPath 锁定。
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest
from google.protobuf.timestamp_pb2 import Timestamp

from aletheia.focalplane import ids
from aletheia.focalplane.ledger import (
    DuplicateEvidenceError,
    InvalidEvidenceError,
    Ledger,
    compute_self_hash,
)
from aletheia.gen.aleth.v1 import aletheia_pb2 as pb

FOCALPLANE_DIR = Path(__file__).resolve().parents[2] / "src" / "aletheia" / "focalplane"


def make_entry(evidence_id: str | None = None, exec_id: str = "exec_test_0001") -> pb.EvidenceEntry:
    e = pb.EvidenceEntry()
    e.evidence_id = evidence_id or ids.new_evidence_id()
    e.exec_id = exec_id
    e.tool.tool_name = "nmap"
    e.tool.tool_version = "7.94.0"
    e.tool.argv.extend(["nmap", "-oX", "-", "192.0.2.10"])
    e.tool.argv_hash = "a" * 64
    e.raw.content_hash = "b" * 64
    e.raw.storage_uri = "/tmp/evidence/whatever"
    e.raw.size_bytes = 123
    e.raw.line_count = 9
    return e


class TestAppendAndChain:
    def test_append_and_get_roundtrip(self, tmp_path: Path) -> None:
        led = Ledger(str(tmp_path / "ledger.db"))
        e = make_entry()
        receipt = led.append(e)
        assert receipt.evidence_id == e.evidence_id
        assert receipt.prev_hash == ""  # 首条：空链
        assert receipt.self_hash

        # append 无副作用：调用方对象保持干净（可安全重放）。
        assert not e.HasField("created_at") and not e.self_hash and not e.prev_hash

        back = led.get(e.evidence_id)
        assert back is not None
        # 存储版 = 调用方内容 + 账本赋权字段（created_at / prev_hash / self_hash）。
        expected = pb.EvidenceEntry()
        expected.CopyFrom(e)
        expected.created_at.CopyFrom(back.created_at)
        expected.prev_hash = receipt.prev_hash
        expected.self_hash = receipt.self_hash
        assert back == expected
        led.close()

    def test_chain_links(self, tmp_path: Path) -> None:
        led = Ledger(str(tmp_path / "ledger.db"))
        r1 = led.append(make_entry())
        r2 = led.append(make_entry())
        r3 = led.append(make_entry())
        assert r1.prev_hash == ""
        assert r2.prev_hash == r1.self_hash
        assert r3.prev_hash == r2.self_hash
        assert len({r1.self_hash, r2.self_hash, r3.self_hash}) == 3
        head = led.chain_head()
        assert head is not None and head.seq == 3 and head.self_hash == r3.self_hash
        assert led.length() == 3
        led.close()

    def test_verify_chain_intact(self, tmp_path: Path) -> None:
        led = Ledger(str(tmp_path / "ledger.db"))
        for _ in range(5):
            led.append(make_entry())
        report = led.verify_chain()
        assert report.intact and report.length == 5 and report.broken_seq is None
        led.close()

    def test_verify_chain_empty_ledger(self, tmp_path: Path) -> None:
        led = Ledger(str(tmp_path / "ledger.db"))
        report = led.verify_chain()
        assert report.intact and report.length == 0
        led.close()

    def test_hashes_deterministic(self, tmp_path: Path) -> None:
        # 相同内容 + 相同 prev_hash → 相同哈希（Q6 同源要求）。
        led = Ledger(str(tmp_path / "ledger.db"))
        a = make_entry()
        a_copy = pb.EvidenceEntry()
        a_copy.CopyFrom(a)
        a_copy.evidence_id = a.evidence_id
        # created_at 由账本赋值 —— 计算哈希前两个条目均未带时间戳。
        h1 = compute_self_hash(a, "prev")
        h2 = compute_self_hash(a_copy, "prev")
        assert h1 == h2
        # prev_hash 参与输入：同内容挂不同链位 → 不同哈希（防拼接歧义）。
        assert h1 != compute_self_hash(a, "other-prev")
        led.close()


class TestTamperDetection:
    def test_tamper_middle_record_detected(self, tmp_path: Path) -> None:
        """测试扮演攻击者：绕过接口直接改 SQLite 中的历史记录。"""
        db = str(tmp_path / "ledger.db")
        led = Ledger(db)
        led.append(make_entry())
        r2 = led.append(make_entry())
        led.append(make_entry())
        led.close()

        # 直接改中间条的原始字节（改 exec_id）。
        conn = sqlite3.connect(db)
        row = conn.execute(
            "SELECT entry_bytes FROM evidence WHERE evidence_id = ?", (r2.evidence_id,)
        ).fetchone()
        e = pb.EvidenceEntry()
        e.ParseFromString(row[0])
        e.exec_id = "exec_forged_by_attacker"
        conn.execute(
            "UPDATE evidence SET entry_bytes = ? WHERE evidence_id = ?",
            (e.SerializeToString(deterministic=True), r2.evidence_id),
        )
        conn.commit()
        conn.close()

        led2 = Ledger(db)
        report = led2.verify_chain()
        assert not report.intact, "篡改必须被检出（07 §T4.3）"
        assert report.broken_seq == r2.seq
        led2.close()

    def test_delete_middle_record_detected(self, tmp_path: Path) -> None:
        """删除中间条目 → 后条的 prev_hash 链接断裂。"""
        db = str(tmp_path / "ledger.db")
        led = Ledger(db)
        led.append(make_entry())
        r2 = led.append(make_entry())
        led.append(make_entry())
        led.close()

        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM evidence WHERE evidence_id = ?", (r2.evidence_id,))
        conn.commit()
        conn.close()

        led2 = Ledger(db)
        report = led2.verify_chain()
        assert not report.intact
        led2.close()


class TestIdempotency:
    def test_reappend_idempotent_returns_existing(self, tmp_path: Path) -> None:
        led = Ledger(str(tmp_path / "ledger.db"))
        e = make_entry()
        r1 = led.append(e)
        r2 = led.append(e, idempotent=True)
        assert r1.evidence_id == r2.evidence_id
        assert r1.self_hash == r2.self_hash
        assert led.length() == 1  # 不重复追加
        led.close()

    def test_reappend_non_idempotent_raises(self, tmp_path: Path) -> None:
        led = Ledger(str(tmp_path / "ledger.db"))
        e = make_entry()
        led.append(e)
        with pytest.raises(DuplicateEvidenceError):
            led.append(e)
        led.close()

    def test_same_id_different_content_raises_even_idempotent(self, tmp_path: Path) -> None:
        """同 ID 不同内容 = 伪造信号：幂等也不能吞掉它。"""
        led = Ledger(str(tmp_path / "ledger.db"))
        e1 = make_entry(evidence_id="ev_dup0000000000000000000000000001")
        e2 = make_entry(evidence_id="ev_dup0000000000000000000000000001")
        e2.raw.size_bytes = 999  # 内容不同
        led.append(e1)
        with pytest.raises(DuplicateEvidenceError):
            led.append(e2, idempotent=True)
        assert led.length() == 1
        led.close()


class TestLedgerLevelValidation:
    """账本级校验：失败必须显式（05 §0 C2），不得静默修正。"""

    def test_empty_exec_id_rejected(self, tmp_path: Path) -> None:
        led = Ledger(str(tmp_path / "ledger.db"))
        with pytest.raises(InvalidEvidenceError):
            led.append(make_entry(exec_id=""))
        led.close()

    def test_bad_evidence_id_prefix_rejected(self, tmp_path: Path) -> None:
        led = Ledger(str(tmp_path / "ledger.db"))
        with pytest.raises(InvalidEvidenceError):
            led.append(make_entry(evidence_id="find_notanevidenceid"))
        led.close()

    def test_caller_supplied_hashes_rejected(self, tmp_path: Path) -> None:
        """自带 prev/self hash = 试图指定链位 —— 直接拒绝，不静默覆盖。"""
        led = Ledger(str(tmp_path / "ledger.db"))
        e = make_entry()
        e.self_hash = "f" * 64
        with pytest.raises(InvalidEvidenceError):
            led.append(e)
        led.close()

    def test_caller_supplied_created_at_rejected(self, tmp_path: Path) -> None:
        """时间戳权威在账本：调用方伪造时间线（T4.1 变体）被拒绝。"""
        led = Ledger(str(tmp_path / "ledger.db"))
        e = make_entry()
        ts = Timestamp()
        ts.FromJsonString("1999-01-01T00:00:00Z")
        e.created_at.CopyFrom(ts)
        with pytest.raises(InvalidEvidenceError):
            led.append(e)
        led.close()


class TestNoMutationPath:
    """M4 §6「接口层无 update/delete 路径」—— 静态检查。

    07 §T4.3 的缓解前提：账本只有 append 一条写路径。若有人往本包加
    UPDATE/DELETE，这条测试先红 —— 而不是等一次安全审计才发现。
    """

    def test_no_sql_mutation_statements(self) -> None:
        forbidden = re.compile(
            r"(UPDATE\s+\w+|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|REPLACE\s+INTO)",
            re.IGNORECASE,
        )
        offenders = []
        for py in sorted(FOCALPLANE_DIR.glob("*.py")):
            for i, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
                if forbidden.search(line):
                    offenders.append(f"{py.name}:{i}: {line.strip()}")
        assert not offenders, "账本源码出现 SQL 变更语句：\n" + "\n".join(offenders)

    def test_public_surface_has_no_mutation_apis(self) -> None:
        public = [n for n in dir(Ledger) if not n.startswith("_")]
        banned = {"update", "delete", "remove", "drop", "rewrite", "truncate", "amend"}
        leaked = banned & set(public)
        assert not leaked, f"Ledger 公开接口出现变更语义方法：{leaked}"


class TestIds:
    def test_uuid7_shape(self) -> None:
        u = ids.uuid7()
        assert re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", u
        ), u
        # variant nibble 已由 regex [89ab] 锁定；version nibble 由 `7` 锁定。

    def test_prefixed_ids(self) -> None:
        assert ids.new_evidence_id().startswith("ev_")
        assert ids.new_finding_id().startswith("find_")
        assert ids.new_observation_id().startswith("obs_")

    def test_uuid7_uniqueness(self) -> None:
        assert len({ids.uuid7() for _ in range(1000)}) == 1000
