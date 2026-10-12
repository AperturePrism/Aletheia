"""冲突矩阵与四象限解读（modules/M7 §4.4，T7.9–T7.10）。

# 为什么这个矩阵是本项目的第二个"第一"（M7 §2）

| 黑盒结果 | 白盒结果 | 解读 | 优先级 |
|---|---|---|---|
| 可利用 | 有缺陷 | **双源确认** | 高 |
| **打不通** | **有缺陷** | **利用条件未满足 / 需前置认证** | **最高** |
| 可利用 | 无缺陷 | 配置/环境类问题，或白盒漏检 | 中 |
| 打不通 | 无缺陷 | 可能确实安全 | 低 |

**最高价值象限是第二行。** 对纯黑盒 agent 它是盲区（只知道"打不通"），
对纯白盒工具它也无意义（不验证可利用性）。**只有融合才能识别出
"这是链式漏洞的第一环"。**

依据（调研 D6）：链式漏洞成功率仅约 16%，agent 常卡在无法把侦察阶段
的发现传递到利用阶段。冲突矩阵是把"打不通"**从失败转化为线索**的机制。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aletheia.fusion.observers import BINARY, BLACKBOX, WHITEBOX, Observation

# ---------------------------------------------------------------------------
# 四象限
# ---------------------------------------------------------------------------


class Quadrant:
    """四个象限的标识（M7 §4.4）。

    用字符串常量而非 enum.IntEnum：象限要写进 M2 的 `CONTRADICTS`
    关系属性（M7 §4.5 的 `attributes={"quadrant": "..."}`），
    而属性值是字符串。
    """

    #: 黑盒可利用 + 静态有缺陷 —— 双源确认，最高可信度。
    CONFIRMED_BOTH = "CONFIRMED_BOTH"
    #: **黑盒打不通 + 静态有缺陷** —— 最高价值象限。可能是链式漏洞第一环。
    UNREACHABLE_BUT_FLAWED = "UNREACHABLE_BUT_FLAWED"
    #: 黑盒可利用 + 静态无缺陷 —— 配置/环境类问题，或静态漏检。
    EXPLOITABLE_BUT_CLEAN = "EXPLOITABLE_BUT_CLEAN"
    #: 黑盒打不通 + 静态无缺陷 —— 可能确实安全。
    NEITHER = "NEITHER"


#: 象限解读（M7 §4.4 的"解读"列原文含义）+ 优先级 + 建议动作。
QUADRANT_META: dict[str, dict[str, str]] = {
    Quadrant.CONFIRMED_BOTH: {
        "label": "双源确认",
        "priority": "高",
        "interpretation": "黑盒可打且静态有缺陷 —— 两个独立来源一致",
        "action": "直接进 Candidate，复现后 Confirmed",
    },
    Quadrant.UNREACHABLE_BUT_FLAWED: {
        "label": "打不通但有缺陷",
        "priority": "最高",
        "interpretation": ("利用条件未满足 / 环境差异 / 需前置认证 —— 可能是链式漏洞的第一环"),
        "action": "深挖前置条件（不要当作失败丢弃）",
    },
    Quadrant.EXPLOITABLE_BUT_CLEAN: {
        "label": "可打但静态无缺陷",
        "priority": "中",
        "interpretation": "配置/环境类问题，或静态分析漏检（盲区）",
        "action": "交叉复核，确认是否为静态盲区",
    },
    Quadrant.NEITHER: {
        "label": "两路皆无",
        "priority": "低",
        "interpretation": "黑盒打不通且静态无缺陷 —— 可能确实安全",
        "action": "降优先级",
    },
}


def classify(blackbox_exploitable: bool, static_flawed: bool) -> str:
    """按 M7 §4.4 的表格判定象限。

    两个布尔量的四种组合恰好对应四行 —— 这是设计上的刻意对齐：
    矩阵不是"经验总结"，而是**两个独立观测维度的完整笛卡尔积**。
    """
    if blackbox_exploitable and static_flawed:
        return Quadrant.CONFIRMED_BOTH
    if static_flawed:
        # 黑盒不可利用 + 静态有缺陷 —— 最高价值象限。
        return Quadrant.UNREACHABLE_BUT_FLAWED
    if blackbox_exploitable:
        return Quadrant.EXPLOITABLE_BUT_CLEAN
    return Quadrant.NEITHER


# ---------------------------------------------------------------------------
# 冲突（M7 §4.5：以 CONTRADICTS 关系显式落图）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Conflict:
    """一处冲突（映射 M2 的 `Relation{type=CONTRADICTS}`）。

    **冲突不合并**（M7 §3.2 N2）：保留两侧观测的完整信息，
    以关系的形式显式落图，让 M3 的光圈投影能优先呈现它
    （`CONTRADICTS` 权重 0.85，M3 §4.3）。
    """

    quadrant: str
    #: 缺陷的身份键（两侧对齐后的同一个 key）。
    entity_key: str
    target: str
    defect_type: str
    #: 各路的观测（可能有多个来源投同一路）。
    blackbox: tuple[Observation, ...] = ()
    whitebox: tuple[Observation, ...] = ()
    binary: tuple[Observation, ...] = ()

    @property
    def static_side(self) -> tuple[Observation, ...]:
        """静态侧的全部观测（白盒 + 二进制）。"""
        return self.whitebox + self.binary

    @property
    def priority(self) -> str:
        return QUADRANT_META[self.quadrant]["priority"]

    def location_of_static(self) -> str:
        """静态侧给出的位置（源码 `file:line` 或二进制 offset）。

        优先白盒（位置更精确、可读性更好），退回二进制。
        返回空串表示静态侧未给出位置 —— 调用方应显式说明
        （不编造一个位置）。
        """
        for o in self.whitebox:
            if o.location:
                return o.location
        for o in self.binary:
            if o.location:
                return o.location
        return ""

    def static_confidence(self) -> float:
        """静态侧的最高置信度（0 表示无静态观测）。

        取最高而非平均：两侧观测同一缺陷时，更有信心的那个更能代表
        "静态侧掌握的证据强度"。平均会被低置信的重复观测拉低 ——
        而那不该削弱一个已经被白盒确认的缺陷。
        """
        vals = [o.confidence for o in self.static_side]
        return max(vals) if vals else 0.0

    def blackbox_verified(self) -> bool:
        """黑盒侧是否验证了可利用性。"""
        return any(o.exploitability_verified for o in self.blackbox)

    def to_relation_attributes(self) -> dict[str, str]:
        """构造 `CONTRADICTS` 关系的属性（M7 §4.5 的形态）。"""
        return {
            "quadrant": self.quadrant,
            "priority": self.priority,
            "target": self.target,
            "defect_type": self.defect_type,
        }


# ---------------------------------------------------------------------------
# 矩阵生成
# ---------------------------------------------------------------------------


@dataclass
class ConflictMatrix:
    """冲突矩阵 —— 三路观测的对齐结果（M7 §4.4 的核心产出）。"""

    target: str
    #: 按缺陷身份键对齐后的全部条目。
    conflicts: list[Conflict] = field(default_factory=list)
    #: 各路的观测数量（用于覆盖度声明，M7 §9）。
    counts: dict[int, int] = field(default_factory=dict)

    def by_quadrant(self, quadrant: str) -> list[Conflict]:
        """取某象限的全部冲突（确定性顺序：按 entity_key 排序）。"""
        return sorted(
            (c for c in self.conflicts if c.quadrant == quadrant),
            key=lambda c: c.entity_key,
        )

    def chained_hypotheses(self) -> list[Conflict]:
        """返回"可能是链式漏洞第一环"的冲突（最高价值象限）。

        M7 §4.4 + §3.1 R6：这一象限的发现要**派生下游深挖任务**。
        单独成方法是为了让调用方（M5 编排层）有一个明确的入口 ——
        而不是自己去 `by_quadrant` 里挑，那容易漏掉。
        """
        return self.by_quadrant(Quadrant.UNREACHABLE_BUT_FLAWED)


#: 冲突落图的阈值（M7 §8：两侧 confidence 均 > 0.5 才落图，避免噪声）。
MIN_CONFLICT_CONFIDENCE = 0.5

#: 单次融合的冲突数量上限（M7 §8："数量上限"）。
MAX_CONFLICTS = 200


def build_matrix(
    target: str,
    observations: list[Observation],
    *,
    min_confidence: float = MIN_CONFLICT_CONFIDENCE,
    max_conflicts: int = MAX_CONFLICTS,
) -> ConflictMatrix:
    """把三路观测对齐为冲突矩阵（M7 §4.4 / §4.5）。

    对齐口径：按 :meth:`Observation.entity_key`（`载体|缺陷类型|位置`）
    分组。**这与 M2 的 DEFECT 身份键一致** —— 若不一致，三路对同一缺陷
    的观测会落到不同 entity_id，冲突将无从检测。

    阈值（M7 §8）：
      · 两侧 confidence 均 > ``min_confidence`` 才落图。
        低置信观测（尤其是二进制，M7 §8 说默认 < 0.6）不构成"冲突"，
        只是噪声 —— 让它们干扰矩阵会淹没真正的高价值信号。
      · 冲突总数上限 ``max_conflicts``（超出的按优先级截断）。
    """
    matrix = ConflictMatrix(target=target)

    # 覆盖度统计（M7 §9：报告必须显式声明覆盖度）。
    counts: dict[int, int] = {}
    for o in observations:
        counts[o.source] = counts.get(o.source, 0) + 1
    matrix.counts = counts

    # 按身份键分组。
    groups: dict[str, list[Observation]] = {}
    for o in observations:
        groups.setdefault(o.entity_key(), []).append(o)

    for key in sorted(groups):  # 确定性顺序（P-5）
        bucket = groups[key]
        bb = tuple(o for o in bucket if o.source == BLACKBOX)
        wb = tuple(o for o in bucket if o.source == WHITEBOX)
        bn = tuple(o for o in bucket if o.source == BINARY)

        # 阈值：两侧都要有**够置信**的观测才构成冲突。
        bb_strong = [o for o in bb if o.confidence > min_confidence]
        static_strong = [o for o in (wb + bn) if o.confidence > min_confidence]

        blackbox_exploitable = any(o.exploitability_verified for o in bb_strong)
        static_flawed = bool(static_strong)

        quadrant = classify(blackbox_exploitable, static_flawed)
        if quadrant == Quadrant.NEITHER:
            # 两路皆无 —— 不构成冲突（可能确实安全），不进矩阵。
            continue

        first = bucket[0]
        matrix.conflicts.append(
            Conflict(
                quadrant=quadrant,
                entity_key=key,
                target=first.target,
                defect_type=first.defect_type,
                blackbox=bb,
                whitebox=wb,
                binary=bn,
            )
        )

    # 优先级排序：最高价值象限排最前，便于消费方与 UI 直接取头部。
    priority_rank = {"最高": 0, "高": 1, "中": 2, "低": 3}
    matrix.conflicts.sort(key=lambda c: (priority_rank.get(c.priority, 9), c.entity_key))
    if max_conflicts > 0 and len(matrix.conflicts) > max_conflicts:
        matrix.conflicts = matrix.conflicts[:max_conflicts]

    return matrix
