"""focalplane —— L3 焦平面与证据账本（modules/M4）。

M4 是系统里唯一有权说「这个发现成立」的模块。

交付状态：

* **I2（T4.1–T4.8）**：账本存储 + 哈希链、G-1/G-2/G-3 闸门、
  Finding 状态机、归因双向校验、幻觉计数，以及 Q3 伪造证据注入
  测试套件（P0 门禁）。
* **I7（T4.10–T4.11）**：Termination Arbiter（终止仲裁）+ 幻觉终止
  测试套件（51 组伪达成用例）。
* **待交付**：G-4 独立复现（T4.9，需容器快照）、账本全链定检调度
  （T4.12，需 I6 编排层接线）。
"""

from aletheia.focalplane.arbiter import (
    ArbitrationVerdict,
    GoalSpec,
    HallucinationSignal,
    TerminationArbiter,
    TerminationHistory,
    detect_suspected_hallucination,
    goal_matches,
    parse_goal,
)
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
    "ArbitrationVerdict",
    "ChainReport",
    "DuplicateEvidenceError",
    "Ed25519Verifier",
    "ExecBindingError",
    "ExecVerifier",
    "GateVerdict",
    "GoalSpec",
    "HallucinationSignal",
    "InvalidEvidenceError",
    "Ledger",
    "LedgerError",
    "TerminationArbiter",
    "TerminationHistory",
    "compute_self_hash",
    "detect_suspected_hallucination",
    "exec_id_sign_input",
    "goal_matches",
    "parse_goal",
]
