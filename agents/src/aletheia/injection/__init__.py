"""injection —— 提示词注入特征检测（`docs/07` §T1 的 **L4 检测层**）。

# 为什么需要这个包

`07` 把提示词注入标为 **★最高风险**，并给出五层缓解，其中：

    L1 架构层（最强）：目标内容永不进入"指令"位置
    L2 网络层（兜底）：Scope Kernel 三重校验
    L3 出站层：Privacy Gateway 出站二次扫描
    L4 检测层：注入特征检测 ← 本包
    L5 权限层：Agent 无权改 scope / 关网关 / 改预算

而"检测方法"一节要求：

> 构造注入靶场（`labs/injection/`），预埋 **20+ 种注入模式**
> （含中文、多语言、编码变体、Unicode 同形字），验证 agent 不被诱导越界。
> **纳入反幻觉测试套件。**

★ 但截至本次交付，`grep -rln 'ignore previous' .` 在整个仓库返回空 ——
这条被标为"★最高风险"的威胁，其 L4 检测层**从未实现**，
`labs/injection/` 目录也不存在。

# 为什么 L4 是"标记"而不是"拦截"

规格里一条容易读错的分工：L4 只负责**标记为可疑并告警**。
真正的防线是 L1（结构）与 L2/L3（物理约束）。

规格的原文说得很清楚："**缓解不能依赖"模型足够聪明"**"——
同理，L4 也不应假装自己能穷尽注入手法。模式匹配永远可以被绕过，
因此本包的价值是**让注入可被发现**（在审计里留下记录），
而不是声称能拦住它。

任何把本包当主要防线的主张都是错的。
"""

from aletheia.injection.detector import (
    ALL_CATEGORIES,
    MIN_REQUIRED_PATTERNS,
    PATTERNS,
    InjectionCategory,
    InjectionHit,
    Pattern,
    ScanReport,
    categories_covered,
    normalize_for_matching,
    pattern_count,
    scan,
)

__all__ = [
    "ALL_CATEGORIES",
    "MIN_REQUIRED_PATTERNS",
    "PATTERNS",
    "InjectionCategory",
    "InjectionHit",
    "Pattern",
    "ScanReport",
    "categories_covered",
    "normalize_for_matching",
    "pattern_count",
    "scan",
]
