"""六类契约违背检测（modules/M8 §4.2，T8.6–T8.11）。

# 核心立场

**不检测"什么模式危险"，而检测"实际行为与预期行为的偏离"。**

    POST /transfer {from: A, to: B, amount: 100}

本身完全合法 —— 问题在于"A 是否有权从别人账户转账"。这需要理解
**授权语义**，而非匹配语法模式。

# ★ 强证据要求（M8 §4.3 末句，贯穿全部六类）

> 强证据要求：必须实际取回 B 的资源内容（`DATA_RETURNED` 副作用观测），
> 仅返回 200 状态码**不足以**判定（可能是空壳响应）。

**这是 M4 的 G-3 在业务逻辑场景的应用** —— 避免"只看状态码就判定成功"
这类 D1 幻觉式成功。因此本模块的全部判定入口都要求调用方提供
**副作用观测**，而不是 HTTP 状态码。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aletheia.intent.contract import Endpoint, EndpointContract, Field

# ---------------------------------------------------------------------------
# 违背类别（M8 §4.2 的六类）
# ---------------------------------------------------------------------------


class ViolationType:
    """六类契约违背（M8 §4.2 表格逐行）。"""

    #: BL1 越权访问（IDOR 升级版）—— 主体应仅访问自身资源。
    #: 直击 D7（多会话状态混淆）：agent 常混淆 A/B 账号的 cookie，
    #: 从错误上下文执行动作，最终判定"漏洞不存在"（**假阴性**）。
    BL1_IDOR = "BL1_IDOR"
    #: BL2 价格/数量篡改 —— 金额应由服务端计算。
    BL2_TAMPERING = "BL2_TAMPERING"
    #: BL3 流程绕过 —— 状态机不应允许 X→Z（跳过 Y）。
    BL3_FLOW_BYPASS = "BL3_FLOW_BYPASS"
    #: BL4 配额绕过 —— 计数应单调递增不可重置。
    BL4_QUOTA_BYPASS = "BL4_QUOTA_BYPASS"
    #: BL5 权限提升链 —— 低权限不应获得高权限操作。
    BL5_PRIVILEGE_CHAIN = "BL5_PRIVILEGE_CHAIN"
    #: BL6 竞态（TOCTOU）—— 并发下一致性应保持。
    BL6_RACE = "BL6_RACE"


ALL_VIOLATION_TYPES: tuple[str, ...] = (
    ViolationType.BL1_IDOR,
    ViolationType.BL2_TAMPERING,
    ViolationType.BL3_FLOW_BYPASS,
    ViolationType.BL4_QUOTA_BYPASS,
    ViolationType.BL5_PRIVILEGE_CHAIN,
    ViolationType.BL6_RACE,
)

#: 中文名（报告用）。
VIOLATION_LABELS: dict[str, str] = {
    ViolationType.BL1_IDOR: "越权访问",
    ViolationType.BL2_TAMPERING: "价格/数量篡改",
    ViolationType.BL3_FLOW_BYPASS: "流程绕过",
    ViolationType.BL4_QUOTA_BYPASS: "配额绕过",
    ViolationType.BL5_PRIVILEGE_CHAIN: "权限提升链",
    ViolationType.BL6_RACE: "竞态（TOCTOU）",
}


# ---------------------------------------------------------------------------
# 探测结果与判定
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProbeResult:
    """一次探测的结果。

    **刻意不叫 `Finding`**：本模块**不判定漏洞成立**
    （M8 §3.2 N2：提交 M4 走闸门）。它给出的是"契约违背候选"。
    """

    #: 探测的目标端点。
    endpoint_key: str
    #: 违背类型。
    violation_type: str
    #: HTTP 状态码 —— **仅用于记录，不作为判定依据**。
    status_code: int = 0
    #: 是否实际取回了对方资源的内容（`DATA_RETURNED` 副作用观测）。
    #:
    #: **这是唯一的强证据判据**（M8 §4.3 末句）。
    data_returned: bool = False
    #: 取回内容的证据/摘要（用于审计与去重）。
    data_excerpt: str = ""
    #: 执行该探测的 exec_id（Sandbox 签发 —— 证据可溯源）。
    exec_id: str = ""
    #: 该次探测使用的会话（BL1 的关键：显式绑定 session_id）。
    session_id: str = ""
    #: 额外的结构化详情。
    details: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Violation:
    """一条契约违背（判定后的结论）。"""

    violation_type: str
    endpoint_key: str
    #: 判据说明（可审计 —— 为什么这条构成违背）。
    rationale: str
    #: **强证据**（`DATA_RETURNED` 观测）或空。
    #:
    #: 为空表示"有违背迹象但缺强证据" —— 此时**不得**计为检出结果
    #: （M8 §6 测试要求："越权判定必须基于 DATA_RETURNED 副作用，
    #: 禁止仅凭状态码"）。
    strong_evidence_exec_id: str = ""
    #: 契约字段的置信度（低置信契约上的违背应降权）。
    contract_confidence: float = 1.0
    details: dict[str, str] = field(default_factory=dict)

    @property
    def has_strong_evidence(self) -> bool:
        return bool(self.strong_evidence_exec_id)

    @property
    def label(self) -> str:
        return VIOLATION_LABELS.get(self.violation_type, self.violation_type)


def judge(
    result: ProbeResult,
    *,
    rationale: str,
    contract_confidence: float = 1.0,
) -> Violation | None:
    """把探测结果判定为违背（**强证据门禁**）。

    判定规则（M8 §4.3 末句的机械化）：

    * `data_returned=True` → 构成违背，带强证据；
    * `data_returned=False` → **不计为检出结果**，返回 None。

    调用方若想看"有迹象但缺证据"的情况，应直接读 `ProbeResult`
    （它保留全部原始信息），而不是放松本函数 —— 放松会让检出数字
    虚高，正是本模块要避免的（行业里 70% 的业务逻辑盲区已经够多，
    再叠加假阳性会让数字失去意义）。
    """
    if not result.data_returned:
        return None
    return Violation(
        violation_type=result.violation_type,
        endpoint_key=result.endpoint_key,
        rationale=rationale,
        strong_evidence_exec_id=result.exec_id,
        contract_confidence=contract_confidence,
        details=dict(result.details),
    )


# ---------------------------------------------------------------------------
# BL1 会话隔离探测（T8.6）—— 六类里最重要的一类
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CrossAccessProbe:
    """一次交叉访问探测（M8 §4.3 的访问矩阵的一格）。

    M8 §4.3 给出的矩阵：

            访问者\\资源      A 的资源    B 的资源
            Session A         ✅ 期望     ❌ 期望拒绝
            Session B         ❌ 期望拒绝  ✅ 期望

    "实际结果与期望不一致 ——▶ 契约违背（越权）"。
    """

    #: 执行访问的会话（访问者）。
    session_id: str
    #: 被访问资源的所有者会话。
    resource_owner_session: str
    #: 是否访问了**他人**资源。
    is_cross_access: bool
    #: 探测结果。
    result: ProbeResult

    @property
    def expectation(self) -> str:
        """按矩阵给出期望结果。"""
        return "DENY" if self.is_cross_access else "ALLOW"


def evaluate_cross_access(probe: CrossAccessProbe, endpoint: Endpoint) -> Violation | None:
    """判定一次交叉访问是否构成 BL1 越权（T8.6）。

    判定口径：
      · 交叉访问（访问他人资源）**且**实际取回了数据 → 越权；
      · 同会话访问自己资源 → 不构成违背（正常行为）。

    ★ `resource_owner` 契约字段置信度低时仍判定，但在 `Violation`
    里如实带上 `contract_confidence` —— 由消费者决定是否采信。
    **不在判定阶段降级丢弃**：丢弃会让低置信契约上的真实漏洞消失，
    而那是"漏报"，比"多一条待复核"更糟（M8 §6 要求单独统计漏报率）。
    """
    if not probe.is_cross_access:
        return None
    return judge(
        probe.result,
        rationale=(
            f"会话 {probe.session_id} 访问了会话 "
            f"{probe.resource_owner_session} 的资源并取回数据 —— "
            "违反「主体应仅访问自身资源」（M8 §4.2 BL1）"
        ),
        contract_confidence=endpoint.resource_owner.effective_confidence,
    )


# ---------------------------------------------------------------------------
# BL2 价格/数量篡改（T8.7）
# ---------------------------------------------------------------------------


def evaluate_tampering(
    result: ProbeResult,
    endpoint: Endpoint,
    *,
    client_value: str,
    server_value: str,
) -> Violation | None:
    """判定价格/数量篡改（T8.7）。

    契约：金额应由**服务端计算**（M8 §4.2 BL2 的"契约违背形式"列）。

    判据：端点声明了 `server_computed` 字段，且探测显示该字段在
    响应中被**原样接受**（服务端未重新计算）。

    `client_value != server_value` 时**不**构成违背 —— 那说明服务端
    确实重新计算了（这正是期望行为）。
    """
    computed = endpoint.server_computed.value
    if not isinstance(computed, (tuple, list)) or not computed:
        return None
    if client_value != server_value:
        # 服务端改写了客户端提交的值 → 它确实在服务端计算。不算违背。
        return None
    detail = {
        "client_value": client_value,
        "server_value": server_value,
        "server_computed_fields": ",".join(str(c) for c in computed),
    }
    return judge(
        ProbeResult(
            endpoint_key=result.endpoint_key,
            violation_type=ViolationType.BL2_TAMPERING,
            status_code=result.status_code,
            data_returned=result.data_returned,
            data_excerpt=result.data_excerpt,
            exec_id=result.exec_id,
            session_id=result.session_id,
            details=detail,
        ),
        rationale=(
            f"客户端提交的 {client_value!r} 被服务端原样接受 —— 该字段应由服务端计算（M8 §4.2 BL2）"
        ),
        contract_confidence=endpoint.server_computed.effective_confidence,
    )


# ---------------------------------------------------------------------------
# BL3 非法状态转移（T8.8）
# ---------------------------------------------------------------------------


def illegal_transitions(contract: EndpointContract) -> list[tuple[str, str]]:
    """枚举"未观测到但在语义上可能"的转移（M8 §4.4）。

    口径：`terminal_states` 里的端点若存在**已知前置**，
    则"直接请求该终端端点、跳过前置"是一个待探测的非法转移。

    返回 `(前置端点, 终端端点)` 对，即"被跳过的步骤 + 被直接请求的步骤"。

    **这不是判定**，只是候选枚举 —— M8 §4.4 原文：
    "枚举'未观测到但在语义上可能'的转移"。是否真的构成绕过，
    要由探测（实际跳过前置请求终端并成功）来回答。
    """
    out: list[tuple[str, str]] = []
    for terminal in sorted(contract.terminal_states):
        prereqs = sorted({a for a, b in contract.transitions if b == terminal})
        for p in prereqs:
            out.append((p, terminal))
    return out


def evaluate_flow_bypass(
    result: ProbeResult,
    endpoint: Endpoint,
    *,
    skipped_state: str,
    contract: EndpointContract,
) -> Violation | None:
    """判定流程绕过（T8.8）。

    契约：状态机不应允许 X→Z（跳过 Y）（M8 §4.2 BL3）。

    判据：跳过了前置状态仍成功取回数据。
    """
    if not skipped_state:
        return None
    return judge(
        result,
        rationale=(
            f"跳过状态 {skipped_state!r} 直接请求 {endpoint.key} 并取回数据 —— "
            "违反状态机的合法转移约束（M8 §4.2 BL3）"
        ),
        contract_confidence=contract.overall_confidence(),
    )


# ---------------------------------------------------------------------------
# BL4 配额绕过（T8.9）
# ---------------------------------------------------------------------------


def evaluate_quota_bypass(
    result: ProbeResult,
    endpoint: Endpoint,
    *,
    observed_counts: list[int],
) -> Violation | None:
    """判定配额绕过（T8.9）。

    契约：计数应**单调递增不可重置**（M8 §4.2 BL4 的"契约违背形式"）。

    判据：观测到的计数序列出现**回退**（后一个小于前一个）且仍能取回数据。
    计数回退说明配额被重置。

    `observed_counts` 少于 2 个时无法判断单调性 —— 返回 None（不猜）。
    """
    if len(observed_counts) < 2:
        return None
    reset_at = None
    for i in range(1, len(observed_counts)):
        if observed_counts[i] < observed_counts[i - 1]:
            reset_at = i
            break
    if reset_at is None:
        return None
    return judge(
        ProbeResult(
            endpoint_key=result.endpoint_key,
            violation_type=ViolationType.BL4_QUOTA_BYPASS,
            status_code=result.status_code,
            data_returned=result.data_returned,
            data_excerpt=result.data_excerpt,
            exec_id=result.exec_id,
            session_id=result.session_id,
            details={
                "observed_counts": ",".join(str(c) for c in observed_counts),
                "reset_at_index": str(reset_at),
            },
        ),
        rationale=(
            f"计数序列 {observed_counts} 出现回退（索引 {reset_at}）—— "
            "配额被重置，违反「计数应单调递增不可重置」（M8 §4.2 BL4）"
        ),
        contract_confidence=endpoint.is_counter.effective_confidence,
    )


# ---------------------------------------------------------------------------
# BL5 权限提升链（T8.10）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PermissionEntry:
    """权限矩阵的一格（M8 §3.1 R3：主体 × 资源 × 动作）。"""

    subject: str  # 主体（会话/角色）
    resource: str  # 资源
    action: str  # 动作
    allowed: bool  # 期望是否允许


@dataclass
class PermissionMatrix:
    """权限矩阵（T8.5）。"""

    entries: list[PermissionEntry] = field(default_factory=list)

    def expected(self, subject: str, resource: str, action: str) -> bool | None:
        """查询期望的许可（未登记返回 None —— 不猜）。"""
        for e in self.entries:
            if e.subject == subject and e.resource == resource and e.action == action:
                return e.allowed
        return None

    def low_privilege_subjects(self) -> set[str]:
        """低权限主体集合。

        判据：在任何资源上被拒绝过的主体 —— 这是从矩阵**反推**的，
        而不是靠角色名前缀猜（角色名在不同系统里差异极大）。
        """
        denied: set[str] = set()
        privileged: set[str] = set()
        for e in self.entries:
            if e.allowed:
                privileged.add(e.subject)
            else:
                denied.add(e.subject)
        # 只被拒绝过、从未被允许 → 低权限。
        # 这刻意保守：一个既被允许又被拒绝的主体不列入，避免误判。
        return denied - privileged


def evaluate_privilege_chain(
    result: ProbeResult,
    matrix: PermissionMatrix,
    *,
    subject: str,
    resource: str,
    action: str,
) -> Violation | None:
    """判定权限提升（T8.10）。

    契约：低权限不应获得高权限操作（M8 §4.2 BL5）。

    判据：期望为**拒绝**的主体实际操作成功并取回数据。
    矩阵里未登记的组合返回 None（不猜 —— M8 §4.1：低置信字段降权，
    但"未登记"不是低置信，是**无判据**）。
    """
    expected = matrix.expected(subject, resource, action)
    if expected is None or expected is True:
        return None
    low = matrix.low_privilege_subjects()
    in_low = subject in low
    return judge(
        result,
        rationale=(
            f"主体 {subject!r} 对 {resource!r}/{action!r} 期望被拒绝，"
            f"但实际取回数据 —— 违反权限矩阵（M8 §4.2 BL5）"
            + ("；该主体属低权限集合" if in_low else "")
        ),
        contract_confidence=0.8 if in_low else 0.5,
    )


# ---------------------------------------------------------------------------
# BL6 竞态（T8.11）
# ---------------------------------------------------------------------------


def evaluate_race(
    result: ProbeResult,
    endpoint: Endpoint,
    *,
    concurrent_requests: int,
    successes: int,
    expected_max_successes: int = 1,
) -> Violation | None:
    """判定竞态 / TOCTOU（T8.11）。

    契约：并发下一致性应保持（M8 §4.2 BL6）。

    判据：并发请求的成功数**超出**期望上限。
    例：并发提现 10 次，若余额只够 1 次，成功数 > 1 即超额。

    # 为什么需要多次重试（M8 §8 风险栏）

    "竞态有概率性，需统计显著性"。本函数只判定**单轮**结果 ——
    调用方应当多轮重试并统计成功率，而不是凭一次并发就下结论。
    `details` 里保留了 `concurrent_requests` 与 `successes`，
    供上层做显著性判断。
    """
    if concurrent_requests <= 1:
        return None
    if successes <= expected_max_successes:
        return None
    return judge(
        ProbeResult(
            endpoint_key=result.endpoint_key,
            violation_type=ViolationType.BL6_RACE,
            status_code=result.status_code,
            data_returned=result.data_returned,
            data_excerpt=result.data_excerpt,
            exec_id=result.exec_id,
            session_id=result.session_id,
            details={
                "concurrent_requests": str(concurrent_requests),
                "successes": str(successes),
                "expected_max_successes": str(expected_max_successes),
            },
        ),
        rationale=(
            f"{concurrent_requests} 个并发请求中有 {successes} 个成功，"
            f"超过期望上限 {expected_max_successes} —— "
            "违反并发一致性（M8 §4.2 BL6，TOCTOU）"
        ),
        contract_confidence=endpoint.concurrency_sensitive.effective_confidence,
    )


# ---------------------------------------------------------------------------
# 契约字段的辅助：从 Field 安全取值
# ---------------------------------------------------------------------------


def field_str(f: Field) -> str:
    """把 Field 的 value 转成字符串（None → 空串）。

    存在的理由：`from_traffic` 会用 `None` 表达"未知"（而不是猜 False）。
    消费方直接 `str(f.value)` 会得到字符串 `"None"` —— 一个静默的
    语义污染。这个辅助函数把"未知"统一映射为空串。
    """
    return "" if f.value is None else str(f.value)
