"""focalplane —— L3 焦平面与证据账本（modules/M4）。

M4 是系统里唯一有权说「这个发现成立」的模块。本包在 I2 交付
T4.1–T4.8：账本存储 + 哈希链、G-1/G-2/G-3 闸门、Finding 状态机、
归因双向校验、幻觉计数，以及 Q3 伪造证据注入测试套件。
G-4 独立复现与 Termination Arbiter 属 I7（T4.9–T4.12）。
"""

from aletheia.focalplane.execverifier import (
    Ed25519Verifier,
    ExecVerifier,
    GateVerdict,
    exec_id_sign_input,
)
from aletheia.focalplane.ledger import (
    ChainReport,
    DuplicateEvidenceError,
    ExecBindingError,
    InvalidEvidenceError,
    Ledger,
    LedgerError,
    compute_self_hash,
)

__all__ = [
    "ChainReport",
    "DuplicateEvidenceError",
    "Ed25519Verifier",
    "ExecBindingError",
    "ExecVerifier",
    "GateVerdict",
    "InvalidEvidenceError",
    "Ledger",
    "LedgerError",
    "compute_self_hash",
    "exec_id_sign_input",
]
