"""Evidence Ledger：append-only 存储 + prev_hash/self_hash 哈希链。

对应 modules/M4 §4.1（T4.1）、05 §5.2 EvidenceEntry、07 §T4.3（账本历史篡改防御）。

不可变性保证（M4 §4.1 三条，缺一即回到「账本可被改写」的 D1 世界）：

1. **接口层不提供 update / delete** —— 本模块公开接口只有 append 与查询。
   ``agents/tests/focalplane/test_ledger.py`` 的静态检查锁定这一点
   （M4 §6：接口层无修改/删除路径）。
2. **prev_hash 链**使任何中间修改可被 :meth:`Ledger.verify_chain` 检出。
3. 全链定期校验的**调度**属 I7（T4.12）；本模块提供 verify_chain 原语。

存储选 SQLite WAL（M4 §4.1 的两个选项之一）：I2 是单进程嵌入形态，
零运维；schema 不使用 SQLite 特有语法，PostgreSQL 迁移属部署形态决策（I6+）。

哈希设计（防拼接歧义）::

    self_hash = sha256( b"aleth/evidence/v1\\0" | prev_hash | b"\\0" | deterministic_proto_bytes )

计算前把 entry 的 prev_hash / self_hash 字段置空（self_hash 不能自含），
prev_hash 参与输入使「同内容挂到不同链位」得到不同哈希。
deterministic=True 保证 proto map 字段的序列化顺序稳定
（与 core/ingest 的 Q6 结论一致：protobuf map 默认序列化顺序是随机的）。

时间戳权威：``created_at`` 由账本在 append 时刻赋值 —— 调用方自带的
created_at 被拒绝（fail-closed）。伪造时间戳是 T4.1 的变体：
证据的时间线必须由账本这一受信组件书写。
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime

from google.protobuf.timestamp_pb2 import Timestamp

from aletheia.gen.aleth.v1 import aletheia_pb2 as pb

# 哈希域分隔符：算法/用途/版本绑定，防止跨域重放（"same bytes, other meaning"）。
_HASH_DOMAIN = b"aleth/evidence/v1\x00"

_SCHEMA_VERSION = 1


class LedgerError(Exception):
    """账本操作失败基类。所有失败显式向上传播（P-4：不降级、不吞）。"""


class InvalidEvidenceError(LedgerError):
    """证据条目未通过账本级校验（缺 ID / 自带哈希 / 自带时间戳）。"""


class DuplicateEvidenceError(LedgerError):
    """同 evidence_id 已存在且内容不同 —— 伪造或 ID 碰撞，必须显式失败。"""


@dataclass(frozen=True)
class AppendReceipt:
    """Append 成功回执（对应 proto AppendEvidenceResult 的字段集）。"""

    evidence_id: str
    self_hash: str
    prev_hash: str
    seq: int


@dataclass(frozen=True)
class ChainReport:
    """verify_chain 的结论。intact=False 时 broken_seq 指出第一条断链位置。"""

    intact: bool
    length: int
    broken_seq: int | None = None
    reason: str | None = None


def _canonical_bytes(entry: pb.EvidenceEntry, prev_hash: str) -> bytes:
    """计算 self_hash 的确定性输入（见模块 docstring）。"""
    clone = pb.EvidenceEntry()
    clone.CopyFrom(entry)
    clone.prev_hash = ""
    clone.self_hash = ""
    payload = clone.SerializeToString(deterministic=True)
    return (
        _HASH_DOMAIN
        + prev_hash.encode("utf-8")
        + b"\x00"
        + len(payload).to_bytes(8, "big")  # 长度前缀：杜绝拼接歧义
        + payload
    )


def compute_self_hash(entry: pb.EvidenceEntry, prev_hash: str) -> str:
    return hashlib.sha256(_canonical_bytes(entry, prev_hash)).hexdigest()


class Ledger:
    """Evidence Ledger（append-only）。一个实例对应一个账本文件。

    线程模型：gRPC server 的线程池可能并发调用 —— append 以实例锁串行，
    保证 prev_hash 链的原子推进。读操作走同一连接（SQLite 串行模式）。
    """

    def __init__(self, db_path: str) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA trusted_schema=OFF")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                seq          INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id  TEXT NOT NULL UNIQUE,
                exec_id      TEXT NOT NULL,
                entry_bytes  BLOB NOT NULL,
                self_hash    TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ledger_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        row = self._conn.execute(
            "SELECT value FROM ledger_meta WHERE key='schema_version'"
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO ledger_meta(key, value) VALUES ('schema_version', ?)",
                (str(_SCHEMA_VERSION),),
            )
        elif int(row[0]) != _SCHEMA_VERSION:
            raise LedgerError(
                f"ledger schema version {row[0]} != supported {_SCHEMA_VERSION}; "
                "refusing to open (fail-closed)"
            )
        self._conn.commit()

    # ------------------------------------------------------------------
    # append（唯一的写路径）
    # ------------------------------------------------------------------

    def append(self, entry: pb.EvidenceEntry, *, idempotent: bool = False) -> AppendReceipt:
        """追加一条证据并推进哈希链。

        幂等语义（proto [derived] 注释）：``idempotent=True`` 且同 evidence_id
        已存在时返回**既有**记录，不重复追加；同 ID 但内容不同 →
        :class:`DuplicateEvidenceError`（伪造检测，T4.1/T4.3 的组合变体）。
        """
        with self._lock:
            return self._append_locked(entry, idempotent=idempotent)

    def _append_locked(self, entry: pb.EvidenceEntry, *, idempotent: bool) -> AppendReceipt:
        # append **不修改调用方对象**：所有赋值针对内部克隆。
        # 这让「同一条证据重放」成为纯函数行为（调用方对象保持干净）。
        work = pb.EvidenceEntry()
        work.CopyFrom(entry)
        entry = work

        # ---- 账本级校验（先于任何 I/O）----
        if not entry.evidence_id:
            raise InvalidEvidenceError("evidence_id is empty")
        if not entry.evidence_id.startswith("ev_"):
            raise InvalidEvidenceError(
                f"evidence_id {entry.evidence_id!r} violates the ev_ prefix contract (05 §1.1)"
            )
        if not entry.exec_id:
            raise InvalidEvidenceError(
                "exec_id is empty (G-1 would reject it anyway; do not store)"
            )
        if entry.prev_hash or entry.self_hash:
            # 调用方自带哈希 = 试图指定自己在链中的位置 → 拒绝。
            raise InvalidEvidenceError(
                "prev_hash/self_hash are assigned by the ledger; "
                "caller-provided values are rejected (fail-closed)"
            )
        if entry.HasField("created_at"):
            raise InvalidEvidenceError(
                "created_at is assigned by the ledger; caller-provided timestamps rejected"
            )

        existing = self._get_locked(entry.evidence_id)
        if existing is not None:
            if idempotent:
                # 幂等 = 重放：同 ID 且**内容一致**才返回既有记录。
                # 内容不一致是伪造信号（同 ID 覆盖），幂等不得吞掉（T4.1 变体）。
                # 比较基准：把既有记录的账本赋权字段（created_at）代入重放输入，
                # 否则「账本赋值的时间戳」会被误判为内容漂移。
                replay_input = pb.EvidenceEntry()
                replay_input.CopyFrom(entry)
                replay_input.created_at.CopyFrom(existing.created_at)
                replay = compute_self_hash(replay_input, existing.prev_hash)
                if replay != existing.self_hash:
                    raise DuplicateEvidenceError(
                        f"evidence_id {entry.evidence_id!r} exists with different content; "
                        "idempotent replay rejected (forgery signal)"
                    )
                return AppendReceipt(
                    evidence_id=existing.evidence_id,
                    self_hash=existing.self_hash,
                    prev_hash=existing.prev_hash,
                    seq=self._seq_of(entry.evidence_id),
                )
            raise DuplicateEvidenceError(
                f"evidence_id {entry.evidence_id!r} already exists; "
                "re-append without idempotent=True is a forgery signal"
            )

        # ---- 赋权字段并推进链 ----
        now = Timestamp()
        now.GetCurrentTime()
        entry.created_at.CopyFrom(now)

        head = self._head_locked()
        prev_hash = head.self_hash if head is not None else ""
        entry.prev_hash = prev_hash
        entry.self_hash = compute_self_hash(entry, prev_hash)
        payload = entry.SerializeToString(deterministic=True)

        try:
            self._conn.execute(
                "INSERT INTO evidence(evidence_id, exec_id, entry_bytes, self_hash) "
                "VALUES (?, ?, ?, ?)",
                (entry.evidence_id, entry.exec_id, payload, entry.self_hash),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            # 并发下同 ID 竞态：语义与预检一致。
            self._conn.rollback()
            if idempotent and self._get_locked(entry.evidence_id) is not None:
                existing = self._get_locked(entry.evidence_id)
                if existing is None:  # 理论不可达；assert 在 -O 下会被剥掉，用显式失败
                    raise LedgerError(
                        "unreachable: existing row vanished mid-transaction"
                    ) from None
                return AppendReceipt(
                    evidence_id=existing.evidence_id,
                    self_hash=existing.self_hash,
                    prev_hash=existing.prev_hash,
                    seq=self._seq_of(entry.evidence_id),
                )
            raise DuplicateEvidenceError(
                f"evidence_id {entry.evidence_id!r} collision during insert: {exc}"
            ) from exc

        seq = self._seq_of(entry.evidence_id)
        return AppendReceipt(
            evidence_id=entry.evidence_id,
            self_hash=entry.self_hash,
            prev_hash=prev_hash,
            seq=seq,
        )

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------

    def get(self, evidence_id: str) -> pb.EvidenceEntry | None:
        with self._lock:
            return self._get_locked(evidence_id)

    def chain_head(self) -> AppendReceipt | None:
        """当前链尾；空账本返回 None。"""
        with self._lock:
            return self._head_locked()

    def length(self) -> int:
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM evidence").fetchone()
            return int(cur[0])

    def iter_entries(self):
        """按链序遍历全部证据（seq 升序）。"""
        with self._lock:
            rows = self._conn.execute("SELECT entry_bytes FROM evidence ORDER BY seq").fetchall()
        for (blob,) in rows:
            e = pb.EvidenceEntry()
            e.ParseFromString(blob)
            yield e

    def verify_chain(self) -> ChainReport:
        """全链校验：逐条重算 self_hash 并校验 prev_hash 链接。

        篡改检测（T4.3）：任何中间记录被改写后，其重算哈希与存储的
        self_hash 不一致，或与后条的 prev_hash 链接断裂 —— 检出即 P0
        （告警的调度在 I7 T4.12，本方法只负责诚实地报告断点）。
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, entry_bytes, self_hash FROM evidence ORDER BY seq"
            ).fetchall()
        prev_hash = ""
        for seq, blob, stored_hash in rows:
            e = pb.EvidenceEntry()
            e.ParseFromString(blob)
            if e.prev_hash != prev_hash:
                return ChainReport(
                    intact=False,
                    length=len(rows),
                    broken_seq=seq,
                    reason=f"prev_hash mismatch at seq {seq}",
                )
            recomputed = compute_self_hash(e, e.prev_hash)
            if recomputed != stored_hash or recomputed != e.self_hash:
                return ChainReport(
                    intact=False,
                    length=len(rows),
                    broken_seq=seq,
                    reason=f"self_hash mismatch at seq {seq}",
                )
            prev_hash = e.self_hash
        return ChainReport(intact=True, length=len(rows))

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------

    def _get_locked(self, evidence_id: str) -> pb.EvidenceEntry | None:
        row = self._conn.execute(
            "SELECT entry_bytes FROM evidence WHERE evidence_id = ?", (evidence_id,)
        ).fetchone()
        if row is None:
            return None
        e = pb.EvidenceEntry()
        e.ParseFromString(row[0])
        return e

    def _head_locked(self) -> AppendReceipt | None:
        row = self._conn.execute(
            "SELECT seq, evidence_id, self_hash FROM evidence ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        seq, evidence_id, self_hash = row
        # prev_hash 不单独存列 —— 从 entry_bytes 反解，避免双写不一致。
        entry = self._get_locked(evidence_id)
        if entry is None:  # 理论不可达（同事务刚查到行）；显式失败而非 assert
            raise LedgerError(f"unreachable: head row {evidence_id!r} vanished")
        return AppendReceipt(
            evidence_id=evidence_id,
            self_hash=self_hash,
            prev_hash=entry.prev_hash,
            seq=int(seq),
        )

    def _seq_of(self, evidence_id: str) -> int:
        row = self._conn.execute(
            "SELECT seq FROM evidence WHERE evidence_id = ?", (evidence_id,)
        ).fetchone()
        return int(row[0])

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def utc_now_iso() -> str:
    """审计日志用 RFC 3339 UTC 时间戳（05 §1.2）。"""
    return datetime.now(UTC).isoformat()
