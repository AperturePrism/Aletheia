"""冲突驱动的下游任务派生（modules/M7 §3.1 R6、§4.4，T7.11）。

# 为什么需要这一步

M7 §4.4 的结论：最高价值象限（**打不通但有缺陷**）的存在意义就是
「深挖前置条件 —— 可能是链式漏洞的第一环」。

但如果矩阵生成后没人消费它，这个象限就只是一条记录 —— 与
"打不过就放弃"没有区别。**R6 是把信号转化为行动的那一步。**

依据（调研 D6）：链式漏洞成功率仅约 16%，agent 常卡在无法把侦察阶段
的发现传递到利用阶段。本模块产出的任务带 `target_entity_hints`，
正是把这个传递**结构化**（而不是靠自然语言描述传给下游）。

# 为什么用 dataclass 而不直接产 proto Task

M5 的 `Task` 是 proto 消息，而本模块的职责边界是"派生任务意图"
（M7 §3.2 N5：不决定"下一步做什么"是 M5 的事）。因此这里给出
**结构化的任务意图**，由 M5 决定是否接受、如何排期。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aletheia.fusion.matrix import QUADRANT_META, Conflict, Quadrant


@dataclass(frozen=True)
class DerivedTask:
    """一条由冲突派生的下游任务意图。

    字段与 M5 的 `Task` 对齐（任务分解在 I6 已实现），
    特别是 ``target_entity_hints`` —— M3 §8 的缓解措施明确要求
    Planner 输出**结构化**实体提示而非自然语言，这样 M3 的
    Autofocus 才能可靠召回（`core/aperture` 的 recall 测试验证了这点）。
    """

    #: 任务标题（可读）。
    title: str
    #: 任务目标（给 agent 的指令）。
    objective: str
    #: 建议的 agent 角色（M5 的 AgentRole 枚举值）。
    required_role: int
    #: 结构化目标实体提示（喂给 M3 Autofocus）。
    target_entity_hints: tuple[str, ...] = ()
    #: 来源象限（可审计）。
    quadrant: str = ""
    #: 优先级（沿用矩阵的优先级标签）。
    priority: str = "中"
    #: 提醒 agent 的额外上下文。
    notes: tuple[str, ...] = field(default_factory=tuple)


# M5 的 AgentRole 枚举值（05 §6.1）—— 用常量而非 import proto，
# 保持本模块的依赖面最小（融合逻辑不该依赖编排层的消息定义）。
_ROLE_EXPLOITER = 4
_ROLE_RECON = 1


def derive_tasks(conflicts: list[Conflict]) -> list[DerivedTask]:
    """把冲突矩阵转化为下游任务意图（M7 §3.1 R6）。

    每个象限的动作按 M7 §4.4 的表格：

    * **UNREACHABLE_BUT_FLAWED（最高）** → 深挖前置条件。
      这是本函数的重点：产出带 `target_entity_hints` 的深挖任务，
      且 note 明确要求 agent **不要**把"打不通"当失败。
    * CONFIRMED_BOTH（高） → 复现并推进到 Confirmed。
    * EXPLOITABLE_BUT_CLEAN（中） → 交叉复核静态盲区。
    * NEITHER（低） → **不派生任务**（降优先级即可）。

    输出按优先级排序且确定性（P-5）。
    """
    out: list[DerivedTask] = []
    for c in conflicts:
        meta = QUADRANT_META[c.quadrant]
        hints = (c.target,) if c.target else ()
        if c.quadrant == Quadrant.UNREACHABLE_BUT_FLAWED:
            out.append(
                DerivedTask(
                    title=f"深挖前置条件：{c.defect_type} @ {c.target}",
                    objective=(
                        f"静态分析指出 {c.defect_type} 存在于 {c.target}"
                        f"{f'（{c.location_of_static()}）' if c.location_of_static() else ''}，"
                        "但黑盒未能利用。查明缺失的前置条件"
                        "（认证 / 配置 / 另一条路径 / 环境差异），"
                        "判断它是否为链式漏洞的第一环。"
                    ),
                    required_role=_ROLE_EXPLOITER,
                    target_entity_hints=hints,
                    quadrant=c.quadrant,
                    priority=meta["priority"],
                    notes=(
                        "★ 本项来自最高价值象限：白盒说有缺陷、黑盒打不通。",
                        "**不要把它当作失败的利用尝试而跳过** —— "
                        "对纯黑盒 agent 这个信号不可见，它正是链式漏洞的候选第一环。",
                        f"静态观测位置：{c.location_of_static() or '未给出'}",
                        f"静态侧置信度：{c.static_confidence():.2f}",
                    ),
                )
            )
        elif c.quadrant == Quadrant.CONFIRMED_BOTH:
            out.append(
                DerivedTask(
                    title=f"复现确认：{c.defect_type} @ {c.target}",
                    objective=(
                        f"黑盒已验证 {c.defect_type} 可被利用，静态分析亦指出该缺陷。"
                        "按 M4 的 G-4 独立复现流程推进到 Confirmed —— "
                        "**必须经四道闸门，不得直接标注 CONFIRMED**（09 §R4）。"
                    ),
                    required_role=_ROLE_EXPLOITER,
                    target_entity_hints=hints,
                    quadrant=c.quadrant,
                    priority=meta["priority"],
                    notes=(
                        "双源确认（黑盒可利用 + 静态有缺陷）。",
                        "仍须走 M4 闸门 —— 双源一致不等于已有可复现 PoC。",
                    ),
                )
            )
        elif c.quadrant == Quadrant.EXPLOITABLE_BUT_CLEAN:
            out.append(
                DerivedTask(
                    title=f"复核静态盲区：{c.defect_type} @ {c.target}",
                    objective=(
                        f"黑盒可打但静态分析未报缺陷（{c.defect_type} @ {c.target}）。"
                        "交叉复核是对手写代码的漏检，还是配置/环境类问题 —— "
                        "若确认是漏检，需记录白盒盲区的形态供后续改进。"
                    ),
                    required_role=_ROLE_RECON,
                    target_entity_hints=hints,
                    quadrant=c.quadrant,
                    priority=meta["priority"],
                    notes=("可能是静态分析的工具盲区，也可能是配置类问题。",),
                )
            )
        # NEITHER 不派生任务（M7 §4.4：降优先级）。

    # 确定性排序：优先级 + 标题（P-5）。
    rank = {"最高": 0, "高": 1, "中": 2, "低": 3}
    out.sort(key=lambda t: (rank.get(t.priority, 9), t.title))
    return out
