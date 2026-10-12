"""自建业务逻辑靶场与检出统计（modules/M8 §4.5、§5 T8.12–T8.13）。

# 为什么要自建靶场

M8 §4.5 原文：「行业空白意味着**没有现成靶场可测**。必须自建。」

行业里 70% 的关键 Web 漏洞是业务逻辑缺陷，而"当前没有任何自主 agent
能可靠检测"—— 没有靶场就无法给出可复现的检出数字，
而没有数字，本项目的第三个"第一"就只是一句声明。

# ★ 双模式是诚实性的关键（M8 §4.5 明文）

靶场必须提供"有 OpenAPI"与"无 OpenAPI"两种部署：

> 同一靶场提供"有 OpenAPI"与"无 OpenAPI"两种部署，用于分别统计覆盖率
> **双模式是诚实性的关键** —— 只报"有契约"的数字会高估能力。

因此本模块的统计**强制**按模式分开，且 `DetectionReport` 在缺少任一模式
时会在报告里显式标注（不得合并汇报 —— M8 §7 的 DoD 明文要求）。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aletheia.intent.violations import (
    ALL_VIOLATION_TYPES,
    VIOLATION_LABELS,
    Violation,
)

# ---------------------------------------------------------------------------
# 靶场定义（T8.12）
# ---------------------------------------------------------------------------


class LabMode:
    """靶场部署模式（M8 §4.5 的双模式）。"""

    #: 有 OpenAPI 契约 —— M8 的完整能力。
    WITH_CONTRACT = "WITH_CONTRACT"
    #: 无 OpenAPI —— 只能靠流量启发式，覆盖率显著下降。
    #:
    #: M8 §8 风险栏明确这是"**最可能的现实**"。
    WITHOUT_CONTRACT = "WITHOUT_CONTRACT"


@dataclass(frozen=True)
class LabDefect:
    """靶场里的一个已知缺陷（ground truth）。"""

    defect_id: str
    violation_type: str
    #: 端点（与探测结果的 `endpoint_key` 对齐）。
    endpoint_key: str
    #: 该缺陷在哪种模式下**可被检出**。
    #:
    #: 这是双模式统计的核心：有些缺陷依赖契约（如 BL2 需要知道
    #: "该字段应由服务端计算"），无契约模式下**原理上不可检**。
    detectable_in: frozenset[str] = frozenset({LabMode.WITH_CONTRACT, LabMode.WITHOUT_CONTRACT})
    #: 描述（供报告与人工核对）。
    description: str = ""


@dataclass
class Lab:
    """自建业务逻辑靶场（M8 §4.5 的六项要求）。"""

    name: str
    defects: list[LabDefect] = field(default_factory=list)

    def add(self, defect: LabDefect) -> None:
        self.defects.append(defect)

    def defects_in(self, mode: str) -> list[LabDefect]:
        """该模式下**原理上可检出**的缺陷（分母的来源）。"""
        return [d for d in self.defects if mode in d.detectable_in]

    def coverage_of_types(self) -> set[str]:
        """靶场覆盖了哪几类违背（M8 §7 DoD：BL1–BL6 每类至少 1 个）。"""
        return {d.violation_type for d in self.defects}


def build_default_lab() -> Lab:
    """构造默认靶场（≥10 类缺陷，覆盖 BL1–BL6）。

    业务语义取自真实的电商/银行/审批流场景（M8 §4.5 的"真实度"要求：
    "使用真实业务语义（电商/银行/审批流），非人工玩具"）。

    每个缺陷都标注了**在哪种模式下原理上可检** —— 这是双模式统计的
    基础，也是"不夸大能力"的机械化保证。
    """
    lab = Lab(name="bizlogic-default")
    both = frozenset({LabMode.WITH_CONTRACT, LabMode.WITHOUT_CONTRACT})
    contract_only = frozenset({LabMode.WITH_CONTRACT})

    # ---- BL1 越权访问（3 个 —— 行业里最普遍的业务逻辑缺陷）----
    lab.add(
        LabDefect(
            "BL1-001",
            "BL1_IDOR",
            "GET /api/v2/orders/{order_id}",
            both,
            "订单详情未校验归属，A 会话可读 B 的订单（经典 IDOR）",
        )
    )
    lab.add(
        LabDefect(
            "BL1-002",
            "BL1_IDOR",
            "GET /api/v2/users/{user_id}/profile",
            both,
            "用户资料未校验归属",
        )
    )
    lab.add(
        LabDefect(
            "BL1-003",
            "BL1_IDOR",
            "GET /api/v2/invoices/{invoice_id}/pdf",
            both,
            "发票 PDF 下载未校验归属（导出类端点常被遗漏）",
        )
    )

    # ---- BL2 价格/数量篡改（2 个）----
    lab.add(
        LabDefect(
            "BL2-001",
            "BL2_TAMPERING",
            "POST /api/v2/cart/checkout",
            # ★ 无契约模式下**原理上不可检**：不知道 price 该由服务端算。
            contract_only,
            "结算接受客户端提交的 price（应为服务端根据商品计算）",
        )
    )
    lab.add(
        LabDefect(
            "BL2-002",
            "BL2_TAMPERING",
            "POST /api/v2/coupons/apply",
            contract_only,
            "优惠券折扣率由客户端提交",
        )
    )

    # ---- BL3 流程绕过（2 个）----
    lab.add(
        LabDefect(
            "BL3-001",
            "BL3_FLOW_BYPASS",
            "POST /api/v2/orders/{order_id}/confirm",
            both,
            "可直接确认订单而不经过支付步骤",
        )
    )
    lab.add(
        LabDefect(
            "BL3-002",
            "BL3_FLOW_BYPASS",
            "POST /api/v2/withdrawals/{id}/approve",
            both,
            "审批流可被跳过（直接批准而不经复核）",
        )
    )

    # ---- BL4 配额绕过（2 个）----
    lab.add(
        LabDefect(
            "BL4-001",
            "BL4_QUOTA_BYPASS",
            "POST /api/v2/trial/reset",
            both,
            "免费试用次数可通过重放请求重置",
        )
    )
    lab.add(
        LabDefect(
            "BL4-002",
            "BL4_QUOTA_BYPASS",
            "GET /api/v2/export/csv",
            both,
            "导出配额计数可被并发请求绕过",
        )
    )

    # ---- BL5 权限提升链（2 个）----
    lab.add(
        LabDefect(
            "BL5-001",
            "BL5_PRIVILEGE_CHAIN",
            "POST /api/v2/admin/users/promote",
            both,
            "普通用户可调用管理员接口提升自己",
        )
    )
    lab.add(
        LabDefect(
            "BL5-002",
            "BL5_PRIVILEGE_CHAIN",
            "DELETE /api/v2/admin/audit-log",
            both,
            "审计日志删除接口未校验角色",
        )
    )

    # ---- BL6 竞态（2 个）----
    lab.add(
        LabDefect(
            "BL6-001",
            "BL6_RACE",
            "POST /api/v2/wallet/withdraw",
            both,
            "并发提现可超出余额（TOCTOU）",
        )
    )
    lab.add(
        LabDefect(
            "BL6-002",
            "BL6_RACE",
            "POST /api/v2/coupons/redeem",
            both,
            "同一优惠券可被并发重复核销",
        )
    )

    return lab


# ---------------------------------------------------------------------------
# 检出统计（T8.13）
# ---------------------------------------------------------------------------


@dataclass
class DetectionStats:
    """单一模式下的检出统计（M8 §6 的"分场景统计"）。"""

    mode: str
    #: 该模式下原理上可检的缺陷总数（分母）。
    detectable: int = 0
    #: 检出的缺陷 ID。
    detected: list[str] = field(default_factory=list)
    #: 漏报的缺陷 ID（M8 §6：漏报率必须**单独统计并公开**）。
    missed: list[str] = field(default_factory=list)
    #: 误报（检出了 ground truth 里没有的违背）。
    false_positives: list[str] = field(default_factory=list)

    @property
    def detection_rate(self) -> float:
        """检出率 = 检出 / 可检（分母是**该模式下可检数**，不是全量）。

        这是双模式统计的核心口径：无契约模式下有些缺陷**原理上不可检**，
        把它们算进分母会让数字虚低（低估能力），
        把它们算进分子则会让数字虚高（高估能力）——
        两者都是失真。正确做法是分母按模式收缩，且**分母一并公开**。
        """
        return len(self.detected) / self.detectable if self.detectable else 0.0

    @property
    def miss_rate(self) -> float:
        return len(self.missed) / self.detectable if self.detectable else 0.0

    def render(self) -> str:
        lines = [
            f"[{self.mode}] 可检缺陷 {self.detectable}",
            f"  检出 {len(self.detected)}（{self.detection_rate:.1%}）",
            f"  漏报 {len(self.missed)}（{self.miss_rate:.1%}）",
            f"  误报 {len(self.false_positives)}",
        ]
        if self.missed:
            lines.append(f"  漏报清单：{', '.join(sorted(self.missed))}")
        if self.false_positives:
            lines.append(f"  误报清单：{', '.join(sorted(self.false_positives))}")
        return "\n".join(lines)


@dataclass
class DetectionReport:
    """检出报告（M8 §7 的 DoD：行业首个可复现的业务逻辑检出数字）。

    ★ **两种模式必须分别汇报，不得合并**（M8 §4.5 + §7 的明文要求）。
    """

    lab_name: str
    stats: dict[str, DetectionStats] = field(default_factory=dict)
    #: 各模式的契约来源（报告必须声明能力建立在什么输入上 —— §9 的诚实要求）。
    contract_sources: dict[str, str] = field(default_factory=dict)

    def rate_for(self, mode: str) -> float:
        s = self.stats.get(mode)
        return s.detection_rate if s else 0.0

    def render(self) -> str:
        lines = [f"业务逻辑检出报告 —— {self.lab_name}", ""]
        for mode in sorted(self.stats):
            src = self.contract_sources.get(mode, "unknown")
            lines.append(f"契约来源：{src}")
            lines.append(self.stats[mode].render())
            lines.append("")
        if len(self.stats) < 2:
            lines.append(
                "⚠ 本报告**仅覆盖一种模式** —— 不得用于声明整体能力。"
                "M8 §4.5 明确要求双模式分别统计（只报'有契约'的数字会高估能力）。"
            )
        return "\n".join(lines)


def evaluate_detection(
    lab: Lab,
    mode: str,
    violations: list[Violation],
) -> DetectionStats:
    """按模式统计检出率与漏报率（T8.13）。

    口径：
      · **分母** = 该模式下原理上可检的缺陷数（`lab.defects_in(mode)`）；
      · **检出** = 违背的 `endpoint_key` + 类型命中 ground truth；
      · **漏报** = 可检但未命中；
      · **误报** = 命中不了任何 ground truth 的违背。

    ★ 强证据门禁在这里的体现：只有 `has_strong_evidence` 的 `Violation`
    才计入检出 —— 这正是 M8 §6 "越权判定必须基于 DATA_RETURNED 副作用，
    禁止仅凭状态码"的机械化保证。
    """
    detectable = lab.defects_in(mode)
    truth = {(d.violation_type, d.endpoint_key): d.defect_id for d in detectable}

    detected: set[str] = set()
    matched_keys: set[tuple[str, str]] = set()
    false_positives: list[str] = []

    for v in violations:
        if not v.has_strong_evidence:
            # 无强证据 → 不计入检出（M8 §6 的硬要求）。
            continue
        key = (v.violation_type, v.endpoint_key)
        if key in truth:
            detected.add(truth[key])
            matched_keys.add(key)
        else:
            false_positives.append(f"{v.violation_type}@{v.endpoint_key}")

    missed = [
        d.defect_id for d in detectable if (d.violation_type, d.endpoint_key) not in matched_keys
    ]

    return DetectionStats(
        mode=mode,
        detectable=len(detectable),
        detected=sorted(detected),
        missed=sorted(missed),
        false_positives=sorted(false_positives),
    )


def build_report(
    lab: Lab,
    per_mode: dict[str, tuple[list[Violation], str]],
) -> DetectionReport:
    """构造双模式检出报告。

    `per_mode` 是 `{mode: (violations, contract_source)}`。

    刻意**要求调用方显式给出每个模式的数据** —— 若只给一个模式，
    报告会带"仅覆盖一种模式"的警告（不静默通过）。
    """
    report = DetectionReport(lab_name=lab.name)
    for mode, (violations, source) in sorted(per_mode.items()):
        report.stats[mode] = evaluate_detection(lab, mode, violations)
        report.contract_sources[mode] = source
    return report


def lab_covers_all_types(lab: Lab) -> dict[str, int]:
    """统计靶场对 BL1–BL6 的覆盖（M8 §7 DoD：每类至少 1 个）。

    返回 `{violation_type: 缺陷数}`；缺的类别值为 0。
    """
    out = dict.fromkeys(ALL_VIOLATION_TYPES, 0)
    for d in lab.defects:
        if d.violation_type in out:
            out[d.violation_type] += 1
    return out


def render_lab_summary(lab: Lab) -> str:
    """渲染靶场摘要（含双模式可检数 —— 诚实披露能力边界）。"""
    cov = lab_covers_all_types(lab)
    lines = [
        f"靶场：{lab.name}",
        f"缺陷总数：{len(lab.defects)}",
        "",
        "按类型覆盖：",
    ]
    for t in ALL_VIOLATION_TYPES:
        n = cov[t]
        mark = "✅" if n > 0 else "❌"
        lines.append(f"  {mark} {t} {VIOLATION_LABELS[t]}：{n}")
    lines.extend(["", "按模式可检数（分母）："])
    for mode in (LabMode.WITH_CONTRACT, LabMode.WITHOUT_CONTRACT):
        lines.append(f"  {mode}: {len(lab.defects_in(mode))}/{len(lab.defects)}")
    return "\n".join(lines)
