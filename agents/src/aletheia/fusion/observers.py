"""三路融合 —— 观测器统一接口与来源语义映射（modules/M7 §4.1，T7.1）。

# 核心主张（M7 §1）

**冲突不是需要消除的噪声，而是最高价值的信号。**

调研 39+ 个开源项目后的结论（M7 §2）：没有任何一个项目统一了三路观测 ——
黑盒 agent 不做代码级分析、白盒工具（VulnHuntr）仅支持 Python 且不验证
可利用性、二进制工具（VulHunt）完全独立不与其他观测交互。

# 本模块做什么、不做什么

做（M7 §3.1）：观测器统一接口、三路结果写入同一心智地图、
冲突检测与 `CONTRADICTS` 落图、冲突矩阵与四象限解读、冲突驱动下游任务。

**不做**（M7 §3.2）：
  · N1 不维护独立存储（全部写入 M2 的单一图）
  · N2 **不强行合并冲突**（保留多版本）
  · N3 不判定漏洞成立（DEFECT 状态由 M4 驱动）
  · N4 **不重实现 SAST 引擎**（复用 Semgrep/CodeQL/Ghidra）

N4 是本实现的关键设计约束：**目标不是重写静态分析器，而是把静态分析
结果纳入 agent 的证据体系**。因此本模块定义观测器的统一接口，
具体的引擎适配（Semgrep / tree-sitter / Ghidra）是可插拔的 ——
这也让融合逻辑可以在**没有安装任何 SAST 工具**的环境下被完整测试。
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

from aletheia.gen.aleth.v1 import aletheia_pb2 as pb

# ---------------------------------------------------------------------------
# 观测路（SourceKind 的语义映射，T7.1）
# ---------------------------------------------------------------------------

#: 黑盒：运行时观测（端口/服务/端点/响应/认证行为/实际可利用性）。
#: 由 M1 的适配器产出 —— M7 复用，不重实现（M7 §4.1 的"黑盒观测器
#: （M1 复用）"）。
BLACKBOX = pb.SourceKind.ACTIVE_SCAN
#: 白盒：源码级观测（调用链/污点传播/依赖漏洞/根因位置）。
WHITEBOX = pb.SourceKind.WHITEBOX_SOURCE
#: 二进制：无源码目标（反汇编/符号/字符串/固件/硬编码凭据）。
BINARY = pb.SourceKind.BINARY

#: 三路观测的集合（顺序即报告中的呈现顺序：黑盒 → 白盒 → 二进制）。
TRICHROMATIC: tuple[pb.SourceKind.V, ...] = (BLACKBOX, WHITEBOX, BINARY)


def source_label(kind: pb.SourceKind.V) -> str:
    """返回观测路的人类可读名（报告与日志用）。"""
    return {
        pb.SourceKind.ACTIVE_SCAN: "黑盒（运行时）",
        pb.SourceKind.WHITEBOX_SOURCE: "白盒（源码）",
        pb.SourceKind.BINARY: "二进制",
        pb.SourceKind.PASSIVE_TRAFFIC: "被动流量",
        pb.SourceKind.HISTORICAL: "历史数据",
        pb.SourceKind.LLM_INFERRED: "LLM 推断",
    }.get(kind, f"未知来源({kind})")


# ---------------------------------------------------------------------------
# 观测结果（观测器的统一输出）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Observation:
    """一次观测产出的**一个缺陷候选**。

    刻意不是"整份 SAST 报告"：统一到**单个缺陷**这一粒度，
    才能让三路结果按语义对齐（M7 §4.4 的矩阵是逐缺陷比较的）。

    字段与 M2 的 `EntityDraft` 对齐（`kind=DEFECT`），
    因为三路结果最终要写入同一张图（M7 §3.1 R3）。
    """

    #: 该观测来自哪一路。
    source: pb.SourceKind.V
    #: 缺陷类型（如 "sqli" / "hardcoded_credential" / "path_traversal"）。
    defect_type: str
    #: 目标载体（主机 / URL / 二进制路径）——与 M2 的 DEFECT 身份键对齐。
    target: str
    #: 位置（源码是 `file:line`；二进制是 `offset`/符号名；黑盒是端点）。
    location: str = ""
    #: 观测者自评置信度。**二进制默认偏低**（M7 §8：误报率高，
    #: 需黑盒验证才能升 CANDIDATE）。
    confidence: float = 1.0
    #: 该路是否验证了**实际可利用性**。
    #:
    #: 这是冲突矩阵的核心维度（M7 §4.4）：黑盒能验证可利用性，
    #: 白盒与二进制**只能指出缺陷存在**，不能证明可利用。
    #: 把它们混为一谈会让"白盒说有洞"被误读成"可以打"。
    exploitability_verified: bool = False
    #: 调用链（白盒）或符号路径（二进制）—— 供下游深挖任务使用。
    call_chain: tuple[str, ...] = ()
    #: 自由属性（写入 M2 实体时带上）。
    attributes: dict[str, str] = field(default_factory=dict)

    def entity_key(self) -> str:
        """该观测在 M2 中的身份键（与 `core/prism/identity.go` 的
        DEFECT 分支对齐）。

        # ★ 为什么键里**不含 location**

        `core/prism` 的 DEFECT 身份键是 `载体|缺陷类型|位置`。但三路
        观测对"位置"的表述**天然不同**：

            黑盒：URL `/api/v2/users`（运行时可见的入口）
            白盒：`app/views.py:42`（源码行号）
            二进制：`0x4012a0`（文件偏移）

        若把 location 纳入融合的对齐键，三路对**同一个缺陷**的观测
        永远无法对齐 —— 冲突矩阵会退化成三个互不相干的清单，
        而"融合"本身失去意义。

        因此融合层用 `载体|缺陷类型` 对齐，location 作为**该观测的
        补充信息**保留在各路观测内（`Conflict.location_of_static()`
        给出静态侧的位置）。

        **这会导致一种已知的过度对齐**：同一载体上的同一类缺陷若
        出现在多个位置（如两个不同的 SQL 注入点），融合层会把它们
        视为同一冲突。这是刻意的取舍 —— 宁可让同类的多个实例合并成
        一个"有缺陷"信号（下游深挖任务仍会列出各位置），也不让
        三路因位置表述差异而完全无法对齐。对 M7 的核心目标
        （识别"打不通但有缺陷"这一象限）而言，前者不损失信号，
        后者则会让整个矩阵失效。

        # ★ 写回 M2 时的集成要求（重要）

        本键**必须**被用于写入 M2 的 DEFECT 实体 —— 即实体属性里的
        `location` 应当填**观测路的定位信息**，而**身份键**由
        `载体 + 缺陷类型` 决定。

        若三路各自把 location 写进 M2 的 DEFECT 身份键（`core/prism`
        的密钥是 `载体|缺陷类型|位置`），三路会产生**三个不同的
        entity_id** —— 冲突检测（`MergeBranch` 只在同一 entity_id
        上生成 `CONTRADICTS`）将永远不触发，整个融合链路静默失效。

        集成方可用的做法：把观测路的 location 放进属性
        （如 `whitebox_location` / `blackbox_location`），
        而让 DEFECT 的身份位置字段只承载**归一化后的载体标识**。
        已在 `I8-交接.md` §6 登记为集成注意事项。
        """
        return f"{self.target}|{self.defect_type}"


# ---------------------------------------------------------------------------
# 观测器接口（T7.1）
# ---------------------------------------------------------------------------


class Observer(abc.ABC):
    """一路观测器的统一接口。

    实现者（引擎适配）只需产出 :class:`Observation` 列表 ——
    融合、冲突检测、矩阵生成全部由本模块完成。

    这个边界是 M7 §3.2 N4（不重实现 SAST 引擎）的直接体现：
    引擎能力可以替换（Semgrep → CodeQL），融合逻辑不变。
    """

    @property
    @abc.abstractmethod
    def source(self) -> pb.SourceKind.V:
        """本观测器属于哪一路。"""

    @abc.abstractmethod
    def observe(self, target: str) -> list[Observation]:
        """观测给定目标，返回缺陷候选列表。"""


class StaticObserver(Observer):
    """静态观测器基类（白盒 / 二进制的共同形态）。

    静态观测器的共同特征：**只能指出缺陷存在，不能证明可利用**
    （M7 §4.4 的矩阵正是建立在这个不对称上）。因此基类固定
    `exploitability_verified=False`，子类不必重复声明 ——
    也**不提供**覆盖它的入口，防止实现者误标。
    """

    @abc.abstractmethod
    def scan(self, target: str) -> list[Observation]:
        """扫描目标，返回缺陷候选。"""

    def observe(self, target: str) -> list[Observation]:
        out = []
        for obs in self.scan(target):
            # `dataclasses.replace` 而非原地改：Observation 是 frozen，
            # 且原地改会让"观测器返回的对象"与"融合层看到的对象"不一致。
            out.append(
                Observation(
                    source=obs.source,
                    defect_type=obs.defect_type,
                    target=obs.target,
                    location=obs.location,
                    confidence=obs.confidence,
                    exploitability_verified=False,  # 静态观测器恒不验证可利用性
                    call_chain=obs.call_chain,
                    attributes=obs.attributes,
                )
            )
        return out
