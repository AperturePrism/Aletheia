"""intent —— 业务逻辑意图建模（modules/M8，迭代 I10）。

# 一句话

**不检测"什么模式危险"，而检测"实际行为与预期行为的偏离"。**

# 立项依据（M8 §2：全行业唯一被点名的 0% 区域）

ARTEMIS 研究（2025-12，8,000 台真实企业网络）：

> AI 排名第 2，成功率 82%，击败 10 名人类渗透测试员中的 9 名。
> 但**关键 Web 漏洞中约 70% 属于业务逻辑缺陷，当前没有任何自主 agent
> 能可靠检测**。

为什么所有 agent 都失明：它们做的是**模式匹配**。而
`POST /transfer {from: A, to: B, amount: 100}` 本身完全合法 ——
问题在于"A 是否有权从别人账户转账"。这需要理解**授权语义**。

Aletheia 的第三个"第一"就是给出这部分的**首个可复现检出数字**。

# 本包的结构

* :mod:`contract`   —— 契约模型与抽取（OpenAPI / 流量）（T8.1–T8.4）
* :mod:`violations` —— 六类契约违背检测（T8.6–T8.11）
* :mod:`lab`        —— 自建靶场 + 双模式检出统计（T8.12–T8.13）

# ★ 两条不可妥协的诚实性约束

**1. 强证据门禁**（M8 §4.3 末句 / §6）：

> 必须实际取回对方资源的内容（`DATA_RETURNED` 副作用观测），
> 仅返回 200 状态码**不足以**判定。

`:func:`violations.judge` 是实现点 —— `data_returned=False` 的探测
**不计入检出**。这是 M4 的 G-3 在业务逻辑场景的应用，避免
"只看状态码就判定成功"这类 D1 幻觉式成功。

**2. 双模式分别统计**（M8 §4.5 / §7）：

> **双模式是诚实性的关键** —— 只报"有契约"的数字会高估能力。

`:class:`lab.DetectionReport` 在只有一种模式时会显式警告。

**3. 不声称通用能力**（M8 §3.2 N3）：

契约抽取依赖可获取的输入。对完全黑盒且无文档的目标，只能做流量启发式
推断，覆盖率显著下降。**这一限制必须写入文档与报告。**

# 关于执行侧（T8.6–T8.11 的探测）

本包交付**契约模型 + 判定逻辑 + 靶场 + 统计口径**——全部是确定性的、
可完整测试的。实际的 HTTP 探测执行需要 Sandbox（`exec_id` 签发，M6）
与 Agent 池（I6 未交付部分）。

调用方（接线后的探测执行器）只需把 `ProbeResult` 喂给
`:func:`violations.judge` 及各类 `evaluate_*` 函数即可。
"""

from aletheia.intent.contract import (
    ContractSource,
    Endpoint,
    EndpointContract,
    Field,
    TrafficRecord,
    from_openapi,
    from_traffic,
    infer_state_machine,
    source_confidence,
)
from aletheia.intent.lab import (
    DetectionReport,
    DetectionStats,
    Lab,
    LabDefect,
    LabMode,
    build_default_lab,
    build_report,
    evaluate_detection,
    lab_covers_all_types,
    render_lab_summary,
)
from aletheia.intent.violations import (
    ALL_VIOLATION_TYPES,
    VIOLATION_LABELS,
    CrossAccessProbe,
    PermissionEntry,
    PermissionMatrix,
    ProbeResult,
    Violation,
    ViolationType,
    evaluate_cross_access,
    evaluate_flow_bypass,
    evaluate_privilege_chain,
    evaluate_quota_bypass,
    evaluate_race,
    evaluate_tampering,
    field_str,
    illegal_transitions,
    judge,
)

__all__ = [
    "ALL_VIOLATION_TYPES",
    "VIOLATION_LABELS",
    "ContractSource",
    "CrossAccessProbe",
    "DetectionReport",
    "DetectionStats",
    "Endpoint",
    "EndpointContract",
    "Field",
    "Lab",
    "LabDefect",
    "LabMode",
    "PermissionEntry",
    "PermissionMatrix",
    "ProbeResult",
    "TrafficRecord",
    "Violation",
    "ViolationType",
    "build_default_lab",
    "build_report",
    "evaluate_cross_access",
    "evaluate_detection",
    "evaluate_flow_bypass",
    "evaluate_privilege_chain",
    "evaluate_quota_bypass",
    "evaluate_race",
    "evaluate_tampering",
    "field_str",
    "from_openapi",
    "from_traffic",
    "illegal_transitions",
    "infer_state_machine",
    "judge",
    "lab_covers_all_types",
    "render_lab_summary",
    "source_confidence",
]
