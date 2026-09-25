"""契约标识符生成（docs/05 §1.1）。

uuid7 而非 uuid4：uuid7 内含毫秒时间戳，天然按时间有序，便于账本
append-only 与范围查询（05 §1.1 原文）。随机位来自 ``crypto/rand`` 级别的
``secrets`` —— 伪造者无法预测后续 ID（threat-model T4.1 的次级防御）。

docs/10 §P4 对确定性路径的 uuid 豁免同样适用于此处：ID 是审计上下文，
不是解析产物，不参与 Q6 字节级一致性对比。
"""

from __future__ import annotations

import secrets
import time

_HEX = "0123456789abcdef"


def _format_uuid(b: bytes) -> str:
    out = []
    for i, v in enumerate(b):
        if i in (4, 6, 8, 10):
            out.append("-")
        out.append(_HEX[v >> 4])
        out.append(_HEX[v & 0x0F])
    return "".join(out)


def uuid7() -> str:
    """RFC 9562 UUIDv7：48 bit 毫秒时间戳 + 74 bit 密码学随机。"""
    ts = time.time_ns() // 1_000_000
    rand = secrets.token_bytes(10)  # 80 bit 随机，取 74
    b = bytearray(16)
    b[0:6] = ts.to_bytes(6, "big")
    b[6:8] = rand[0:2]
    b[8:] = rand[2:]
    b[6] = (b[6] & 0x0F) | 0x70  # version 7
    b[8] = (b[8] & 0x3F) | 0x80  # RFC 4122 variant
    return _format_uuid(bytes(b))


def new_evidence_id() -> str:
    """ev_{uuid7}（05 §1.1）。"""
    return "ev_" + uuid7()


def new_finding_id() -> str:
    """find_{uuid7}（05 §1.1）。"""
    return "find_" + uuid7()


def new_observation_id() -> str:
    """obs_{uuid7}。SideEffectObservation 在契约中无独立 ID 字段；
    RecordSideEffectResult.observation_id（[derived]）由此生成。"""
    return "obs_" + uuid7()
