"""契约模型与抽取（modules/M8 §4.1，T8.1–T8.4）。

# 本模块的立场（M8 §2）

ARTEMIS 研究（2025-12，8,000 台真实企业网络）的结论：

> AI 排名第 2，成功率 82%，击败 10 名人类渗透测试员中的 9 名。
> 但**关键 Web 漏洞中约 70% 属于业务逻辑缺陷，当前没有任何自主 agent
> 能可靠检测**。

**这是全行业唯一被明确点名的 0% 区域。**

为什么所有 agent 都失明：现有 agent 做的是**模式匹配**
（"这个参数看起来像 SQL 注入点吗？"）。业务逻辑漏洞没有"危险模式"——

    POST /transfer {from: A, to: B, amount: 100}

本身**完全合法**。问题在于"A 是否有权从别人账户转账"。这需要理解
**授权语义**，而非匹配语法模式。

因此本模块检测的不是"什么模式危险"，而是
**"实际行为与预期行为的偏离"**。

# ★ 诚实性约束（M8 §3.2 N3）

契约抽取依赖可获取的输入。对完全黑盒且无任何文档的目标，本模块只能做
基于流量的**启发式推断**，覆盖率显著下降。

**这一限制必须写入文档与报告，不做过度承诺** —— 因此每个契约字段都带
`source` 与 `confidence`，且报告必须**分场景统计**
（有契约 / 无契约），不得合并汇报（M8 §7 的 DoD 明文要求）。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from itertools import pairwise
from typing import ClassVar

# ---------------------------------------------------------------------------
# 契约来源（M8 §4.1 的抽取优先级）
# ---------------------------------------------------------------------------


class ContractSource:
    """契约字段的来源（M8 §4.1：优先级 OpenAPI > 源码注解 > 流量 > 文档）。

    优先级不只是"可靠性排序"，它决定了**置信度**，
    而置信度决定该字段参与检测时的权重（M8 §4.1 末句：
    "低置信度字段参与检测时降权"）。
    """

    OPENAPI = "openapi"  # 最可靠
    SOURCE_ANNOTATION = "source"  # 源码路由/中间件/权限注解
    TRAFFIC = "traffic"  # 抓包流量推断
    DOCUMENT = "document"  # 文档/需求/工单（最不可靠）

    #: 各来源的基础置信度。
    #:
    #: 数值是设计判断：OpenAPI 是机器可读的强契约（1.0）；
    #: 源码注解需人工维护因而可能过时（0.9）；流量推断是行为观测，
    #: 能反映实际但可能不完整（0.6）；文档最不可靠（0.4）——
    #: 文档描述的是"应该"，而实际实现常与文档脱节。
    CONFIDENCE: ClassVar[dict[str, float]] = {
        OPENAPI: 1.0,
        SOURCE_ANNOTATION: 0.9,
        TRAFFIC: 0.6,
        DOCUMENT: 0.4,
    }


def source_confidence(source: str) -> float:
    return ContractSource.CONFIDENCE.get(source, 0.3)


# ---------------------------------------------------------------------------
# Endpoint Contract（T8.1）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Field:
    """带来源与置信度的契约字段（M8 §4.1 末句要求）。

    存在的理由：契约是从多个来源拼出来的，**不同字段的可信度不同**。
    一个"从 OpenAPI 读到的认证要求"与一个"从流量推断的认证要求"
    不该被同等对待 —— 后者可能只是因为我们恰好没抓到未认证的请求。
    """

    value: object
    source: str = ContractSource.OPENAPI
    confidence: float | None = None

    def __post_init__(self) -> None:
        if self.confidence is None:
            # frozen dataclass 里用 object.__setattr__ 设置派生值。
            object.__setattr__(self, "confidence", source_confidence(self.source))

    @property
    def effective_confidence(self) -> float:
        return self.confidence if self.confidence is not None else 0.3


@dataclass(frozen=True)
class Endpoint:
    """一个端点的行为契约（M8 §4.1 的六项）。"""

    #: 路径（如 `/api/v2/orders/{id}`）。
    path: str
    #: HTTP 方法。
    method: str = "GET"
    #: 是否需要认证。
    auth_required: Field = field(default_factory=lambda: Field(True))
    #: 需要的角色/权限（如 `admin`）。空表示无特定要求。
    required_role: Field = field(default_factory=lambda: Field(""))
    #: 允许访问的资源所有者（"self" 表示仅限自身资源）。
    #:
    #: 这是 BL1（越权访问）的判据来源 —— M8 §4.2 表格的 BL1 原文：
    #: "主体应仅访问自身资源"。
    resource_owner: Field = field(default_factory=lambda: Field("self"))
    #: 服务端应自行计算、不接受客户端提供的参数（BL2 的判据）。
    server_computed: Field = field(default_factory=lambda: Field(()))
    #: 该端点在状态机中的位置（BL3 的判据）。
    state: Field = field(default_factory=lambda: Field(""))
    #: 前置状态（必须先完成的端点）。
    requires_states: Field = field(default_factory=lambda: Field(()))
    #: 计数类端点（BL4 的判据：计数应单调递增不可重置）。
    is_counter: Field = field(default_factory=lambda: Field(False))
    #: 是否可并发调用（BL6 的判据）。
    concurrency_sensitive: Field = field(default_factory=lambda: Field(False))

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"


@dataclass
class EndpointContract:
    """抽取出的契约集合（M8 §4.1 的"契约模型"）。"""

    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    #: 状态机的合法转移（from_state → to_state），T8.3 推断。
    transitions: set[tuple[str, str]] = field(default_factory=set)
    #: 终端状态（流程完成）。
    terminal_states: set[str] = field(default_factory=set)
    #: 抽取过程中的告警（如某来源缺失）。
    warnings: list[str] = field(default_factory=list)

    def add(self, ep: Endpoint) -> None:
        self.endpoints[ep.key] = ep

    def get(self, method: str, path: str) -> Endpoint | None:
        return self.endpoints.get(f"{method.upper()} {path}")

    def sources_used(self) -> set[str]:
        """本次契约用到哪些来源（报告必须声明 —— M8 §9 的诚实要求）。"""
        out: set[str] = set()
        for ep in self.endpoints.values():
            for f in (
                ep.auth_required,
                ep.required_role,
                ep.resource_owner,
                ep.server_computed,
                ep.state,
                ep.requires_states,
                ep.is_counter,
                ep.concurrency_sensitive,
            ):
                out.add(f.source)
        return out

    def overall_confidence(self) -> float:
        """契约的整体置信度（各字段有效置信度的均值）。

        用于报告：一个全部来自 OpenAPI 的契约与一个全靠流量推断的契约，
        它们的检出结果**不该被同等采信**。
        """
        vals: list[float] = []
        for ep in self.endpoints.values():
            for f in (
                ep.auth_required,
                ep.required_role,
                ep.resource_owner,
                ep.server_computed,
                ep.state,
                ep.requires_states,
                ep.is_counter,
                ep.concurrency_sensitive,
            ):
                vals.append(f.effective_confidence)
        return sum(vals) / len(vals) if vals else 0.0


# ---------------------------------------------------------------------------
# OpenAPI 抽取（T8.2 —— 最可靠的来源）
# ---------------------------------------------------------------------------

#: HTTP 方法白名单（OpenAPI 的 path item 里除方法外还有 parameters 等键）。
_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def from_openapi(spec: str | dict) -> EndpointContract:
    """从 OpenAPI/Swagger 文档抽取契约（T8.2）。

    支持 JSON 字符串或已解析的 dict。

    # 抽取的能力与边界

    能可靠抽取的：

    * 路径与方法（OpenAPI 的结构化主体）
    * `security` 声明的认证要求
    * 参数名（用于识别 `user_id` / `order_id` 这类资源标识参数 → BL1）
    * 请求体里**客户端提供**的字段（→ BL2 的候选判据）

    **不能**抽取的（OpenAPI 表达不了的）：

    * "这个参数应该由服务端计算"—— OpenAPI 只说"这是个 number"
    * "这个端点属于状态机哪一步"
    * "资源归属规则"

    后三类需要源码注解（T8.4）或流量推断（T8.3）补充 ——
    这正是 M8 §4.1 要多个来源的原因，也是为什么每个字段带 `confidence`。
    """
    if isinstance(spec, str):
        try:
            doc = json.loads(spec)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid OpenAPI JSON: {exc}") from exc
    else:
        doc = spec

    contract = EndpointContract()
    global_security = doc.get("security")
    paths = doc.get("paths") or {}

    for raw_path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in _HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue

            # 认证：端点级 security 覆盖全局声明。
            sec = op.get("security", global_security)
            auth_required = bool(sec) if sec is not None else bool(global_security)

            # 资源所有者参数：路径/查询参数里形如 xxx_id 的标识符。
            # 这是 BL1 的判据来源。
            params = list(item.get("parameters") or []) + list(op.get("parameters") or [])
            id_params = [
                p.get("name", "")
                for p in params
                if isinstance(p, dict) and str(p.get("name", "")).endswith("_id")
            ]
            # 路径模板里的 {id} 也算。
            tmpl_ids = re.findall(r"\{(\w*_?id)\}", raw_path)
            owner_params = sorted(set(id_params) | set(tmpl_ids))

            # 服务端计算字段：请求体里出现 price/amount/total/discount
            # 这类敏感字段时**标记为候选**（不是判定 —— OpenAPI 无法
            # 表达"这个该由服务端算"，因此置信度按 DOCUMENT 级别给）。
            #
            # 注意：**不**假设 `requestBody` 存在（GET 通常没有），
            # 也不假设 `content` 非空 —— OpenAPI 文档里这些层级都可以缺席。
            computed: list[str] = []
            body = op.get("requestBody") or {}
            for media in (body.get("content") or {}).values():
                schema = (media or {}).get("schema") or {}
                for prop in schema.get("properties") or {}:
                    if prop.lower() in _SENSITIVE_COMPUTED_FIELDS:
                        computed.append(prop)

            contract.add(
                Endpoint(
                    path=raw_path,
                    method=method.upper(),
                    auth_required=Field(auth_required, ContractSource.OPENAPI),
                    resource_owner=Field(
                        "self" if owner_params else "",
                        # 归属规则**不是** OpenAPI 能表达的 ——
                        # 这里只是"存在资源标识参数"的**启发式**。
                        ContractSource.TRAFFIC,
                        confidence=0.5,
                    ),
                    server_computed=Field(
                        tuple(sorted(computed)),
                        # OpenAPI 只能告诉我们"客户端提供了这个字段"，
                        # 不能告诉我们"它不该由客户端提供"。
                        ContractSource.DOCUMENT,
                        confidence=0.4,
                    ),
                )
            )
    return contract


#: 若请求体里出现这些字段，说明**可能**应当由服务端计算（BL2 候选）。
#:
#: 刻意做得窄：宽泛的列表会让 BL2 充满假阳性，而假阳性会淹没真信号。
#: 扩展此列表时应为每条新增补正反例测试（与 M4 的 patterns.py 同一要求）。
_SENSITIVE_COMPUTED_FIELDS = frozenset(
    {
        "price",
        "amount",
        "total",
        "discount",
        "balance",
        "credit",
        "quantity",
        "unit_price",
    }
)


# ---------------------------------------------------------------------------
# 流量推断（T8.3 —— 兜底来源，覆盖率受限）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrafficRecord:
    """一条抓包记录（最小必要字段）。"""

    method: str
    path: str
    status: int = 200
    #: 该请求是否携带认证（cookie / Authorization 头）。
    authenticated: bool = False
    #: 请求体（用于识别客户端可控的敏感字段）。
    body: dict | None = None
    #: 时序序号（用于状态机推断 —— 调用顺序是唯一可用的信号）。
    seq: int = 0


def from_traffic(records: list[TrafficRecord]) -> EndpointContract:
    """从抓包流量推断契约（T8.3）。

    # ★ 覆盖率限制（M8 §3.2 N3 的诚实性要求）

    流量推断**只能**得到：

    * 出现过的端点（**未观测到的端点完全不可见**）
    * "是否有过未认证的成功请求"（有则可推断不要求认证；
      **没有则无法推断要求认证** —— 可能只是我们恰好都带了 cookie）
    * 调用顺序（用于状态机推断）
    * 客户端提交过的敏感字段（BL2 候选）

    **不能**得到资源归属规则、权限矩阵、配额语义。

    因此本函数产出的契约整体置信度偏低（`ContractSource.TRAFFIC` = 0.6），
    且报告必须**分场景统计**（M8 §7 的 DoD 明文要求：
    "无契约黑盒模式的覆盖率单独给出，不合并汇报"）。
    """
    contract = EndpointContract()
    by_key: dict[str, list[TrafficRecord]] = {}
    for r in sorted(records, key=lambda r: r.seq):
        by_key.setdefault(f"{r.method.upper()} {r.path}", []).append(r)

    # 状态机：按 seq 顺序记录相邻端点调用对。
    ordered = sorted(records, key=lambda r: r.seq)
    for a, b in pairwise(ordered):
        ka, kb = f"{a.method.upper()} {a.path}", f"{b.method.upper()} {b.path}"
        if ka != kb:
            contract.transitions.add((ka, kb))

    for key, group in sorted(by_key.items()):
        method, path = key.split(" ", 1)
        # 只有当**观测到未认证的成功请求**时才能确定"不要求认证"。
        saw_unauth_ok = any(not r.authenticated and r.status < 400 for r in group)
        saw_ok = any(r.status < 400 for r in group)
        if saw_unauth_ok:
            auth = Field(False, ContractSource.TRAFFIC)
        elif saw_ok:
            # 观测到的都是认证请求 —— **不能**据此断言要求认证。
            # 用低置信度的"未知"表达，而不是猜 True。
            auth = Field(None, ContractSource.TRAFFIC, confidence=0.3)
        else:
            auth = Field(None, ContractSource.TRAFFIC, confidence=0.2)

        computed: set[str] = set()
        for r in group:
            for k in r.body or {}:
                if k.lower() in _SENSITIVE_COMPUTED_FIELDS:
                    computed.add(k)

        tmpl_ids = re.findall(r"[/{]([\w]*_?id)(?=[}/]|$)", path)
        contract.add(
            Endpoint(
                path=path,
                method=method,
                auth_required=auth,
                resource_owner=Field(
                    "self" if tmpl_ids else "", ContractSource.TRAFFIC, confidence=0.4
                ),
                server_computed=Field(
                    tuple(sorted(computed)), ContractSource.TRAFFIC, confidence=0.5
                ),
            )
        )

    contract.warnings.append(
        "契约由抓包流量推断：未观测到的端点完全不可见，"
        "无法推断资源归属与权限矩阵（M8 §3.2 N3 的已知限制）"
    )
    return contract


# ---------------------------------------------------------------------------
# 状态机推断（T8.3 的一部分，BL3 的判据来源）
# ---------------------------------------------------------------------------


def infer_state_machine(
    contract: EndpointContract,
    *,
    min_observations: int = 1,
) -> None:
    """从已观测的转移推断状态机（就地补充 `contract.transitions`）。

    # 推断口径与它的脆弱性

    规则：一个端点若**从未在某个前置端点之后出现过**，它可能是终端状态；
    若某端点在观测中**总是**出现在另一个之后，后者是前者的前置。

    这个推断**很脆弱**（M8 §8 风险栏："状态机推断错误导致误报"）。
    因此：

    * 推断来源的置信度低（traffic = 0.6）；
    * **低置信度转移只标记不判定** —— 调用方应据此决定是否探测；
    * 若某前置关系只被观测到一次（`min_observations=1` 时），
      它仍进 `transitions` 但应在探测阶段降权。

    真正的"合法状态机"需要契约输入（OpenAPI 的 `x-state-machine`
    扩展或源码注解）—— 本函数只在流量可用时给一个**下界**。
    """
    if not contract.transitions:
        contract.warnings.append("无流量转移观测，状态机推断为空 —— BL3（流程绕过）检测不可用")
        return

    # 终端状态：从未作为转移起点的端点。
    froms = {a for a, _ in contract.transitions}
    tos = {b for _, b in contract.transitions}
    contract.terminal_states = tos - froms

    if len(contract.transitions) < min_observations:
        contract.warnings.append(f"转移观测仅 {len(contract.transitions)} 条，状态机推断置信度不足")
