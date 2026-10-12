"""注入特征检测（`docs/07` §T1 的 **L4 检测层**）。

# 本模块在 T1 缓解体系里的位置

`07` 把提示词注入标为 **★最高风险**，并给出五层缓解：

    L1 架构层（最强）：目标内容永不进入"指令"位置
    L2 网络层（兜底）：Scope Kernel 三重校验
    L3 出站层：Privacy Gateway 出站二次扫描
    L4 检测层：注入特征检测 ← 本模块
    L5 权限层：Agent 无权改 scope / 关网关 / 改预算

规格对 L4 的要求原文：

> 目标内容中出现"忽略之前""系统指令""你现在需要"等**多语言模式**时
> 标记为可疑并告警

而"检测方法"一节要求：构造注入靶场（`labs/injection/`），预埋
**20+ 种注入模式（含中文、多语言、编码变体、Unicode 同形字）**。

# ★ 本模块是"标记"，不是"拦截"

这是规格里一条容易读错的分工：

· L1 负责**结构**（数据不进指令位）—— 那是装配层的事，不在本模块
· L2/L3 负责**物理约束**（越界请求出不去、真实值出不去）
· **L4 只负责"标记为可疑并告警"**

规格明确说："**缓解不能依赖"模型足够聪明"**。因此 L4 的价值不是
"拦住注入"，而是**让注入可被发现**：即使 L1 的定界符被绕过，
检测层也能在审计里留下"这段目标内容看起来像在指挥我"的记录。

若本模块试图"自动删除可疑内容"，那会变成 L1 的一种错误实现 ——
并且**破坏证据**（08 §6：目标响应原文是审计材料）。

# 已知边界（诚实声明）

模式匹配**永远不可能穷尽**注入手法 —— 这是本层被标为
"检测"而非"防御"的原因。规格把 L1/L2 称为"最强"与"兜底"，
正是因为它们不依赖枚举。任何把 L4 当主要防线的主张都是错的。
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# 注入模式库（`07` §T1 L4：「20+ 种注入模式」）
# ---------------------------------------------------------------------------


class InjectionCategory:
    """注入模式的类别（用于告警分级与统计）。"""

    #: 直接要求忽略既有指令（最经典的形态）。
    INSTRUCTION_OVERRIDE = "INSTRUCTION_OVERRIDE"
    #: 伪装成系统/开发者消息。
    ROLE_SPOOFING = "ROLE_SPOOFING"
    #: 要求执行新的、范围外的动作（常与 A1 越界攻击联动）。
    NEW_TASK_INJECTION = "NEW_TASK_INJECTION"
    #: 要求外泄数据（与 A2 联动）。
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    #: 试图解除安全约束（关网关 / 扩 scope）。
    GUARDRAIL_REMOVAL = "GUARDRAIL_REMOVAL"
    #: 用编码/同形字/零宽字符绕过朴素匹配。
    OBFUSCATED = "OBFUSCATED"


ALL_CATEGORIES: tuple[str, ...] = (
    InjectionCategory.INSTRUCTION_OVERRIDE,
    InjectionCategory.ROLE_SPOOFING,
    InjectionCategory.NEW_TASK_INJECTION,
    InjectionCategory.DATA_EXFILTRATION,
    InjectionCategory.GUARDRAIL_REMOVAL,
    InjectionCategory.OBFUSCATED,
)


@dataclass(frozen=True)
class Pattern:
    """一条注入模式。

    `pattern` 是**已编译**的正则；`category` 用于分级；
    `note` 说明该模式为什么被列入（便于人工复核误报）。
    """

    name: str
    category: str
    pattern: re.Pattern[str]
    note: str = ""


def _p(name: str, category: str, regex: str, note: str = "") -> Pattern:
    """构造一条模式。

    统一用 `re.IGNORECASE`：这些短语的大小写变体（`SYSTEM:` / `System:`）
    在真实注入里都常见，逐条列出大小写组合没有意义。
    """
    return Pattern(
        name=name,
        category=category,
        pattern=re.compile(regex, re.IGNORECASE),
        note=note,
    )


#: 注入模式库 —— `07` §T1 L4 要求的「20+ 种，含中文、多语言、编码变体」。
#:
#: 组织方式：按类别分组，每类覆盖**同一意图的不同表述**。
#: 多语言是刻意的：规格原文点名"含中文、多语言"，因为只匹配英文的
#: 检测器对中文目标完全失明（而本项目的目标环境可能是中文系统）。
PATTERNS: tuple[Pattern, ...] = (
    # ---- 英文：指令覆盖（最经典）----
    _p(
        "en-ignore-previous",
        InjectionCategory.INSTRUCTION_OVERRIDE,
        r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b"
        r"[^.\n]{0,30}\b(instruction|prompt|rule|direction|context|scope|limit|"
        r"restriction|constraint|authoriz|guardrail|polic)",
        "要求忽略既有指令（含忽略范围/限制类表述 —— 07 场景原文用的是"
        " ignore the previous authorization scope limits，"
        "因此关键词不能只列 instruction/prompt）",
    ),
    _p(
        "en-new-instructions",
        InjectionCategory.INSTRUCTION_OVERRIDE,
        r"\b(new|updated|revised)\s+(system\s+)?(instruction|prompt|rule)s?\b",
        "自称有更新的指令",
    ),
    _p(
        "en-override",
        InjectionCategory.INSTRUCTION_OVERRIDE,
        r"\b(override|bypass|circumvent)\b[^.\n]{0,30}\b(instruction|rule|polic|restriction|guardrail|safety)",
        "要求覆盖/绕过规则",
    ),
    # ---- 英文：角色伪装 ----
    _p(
        "en-system-tag",
        InjectionCategory.ROLE_SPOOFING,
        r"(^|\n|\s)(system|developer|admin|root)\s*(message|instruction|prompt|note)?\s*:",
        "伪装成系统/开发者消息（`SYSTEM:` 这类标签）",
    ),
    _p(
        "en-html-comment-directive",
        InjectionCategory.ROLE_SPOOFING,
        r"<!--[^>]{0,200}?(system|instruction|ignore|you (must|need to|should))",
        "HTML 注释里塞指令（07 §T1 场景原文的形态）",
    ),
    _p(
        "en-assistant-prefix",
        InjectionCategory.ROLE_SPOOFING,
        r"\bassistant\s*:\s*(sure|ok|i will|understood)",
        "伪造助手已同意的回复",
    ),
    # ---- 英文：新任务注入 ----
    _p(
        "en-you-must-now",
        InjectionCategory.NEW_TASK_INJECTION,
        r"\byou (must|need to|should|are required to)\b[^.\n]{0,40}\b(now|immediately|next)\b",
        "要求立即执行新动作",
    ),
    _p(
        "en-please-scan",
        InjectionCategory.NEW_TASK_INJECTION,
        r"\b(please\s+)?(scan|attack|exploit|test|verify|curl|fetch|post to)\b"
        r"[^.\n]{0,40}https?://",
        "要求把动作指向某个 URL（越界攻击的典型形态）",
    ),
    _p(
        "en-task-reframe",
        InjectionCategory.NEW_TASK_INJECTION,
        r"\byour (real|actual|true|new) (task|goal|objective|mission) is\b",
        "重新定义任务目标",
    ),
    # ---- 英文：数据外泄 ----
    _p(
        "en-send-to",
        InjectionCategory.DATA_EXFILTRATION,
        r"\b(send|post|upload|exfiltrate|forward|transmit)\b[^.\n]{0,40}"
        r"\b(to|at)\b[^.\n]{0,20}(https?://|[\w.-]+@[\w.-]+)",
        "要求把数据发往某地址",
    ),
    _p(
        "en-include-secrets",
        InjectionCategory.DATA_EXFILTRATION,
        r"\b(include|attach|append|reveal|print|show)\b[^.\n]{0,30}"
        r"\b(credential|password|secret|api[_\s-]?key|token|\.env|config)",
        "要求带出凭据类内容",
    ),
    # ---- 英文：解除约束 ----
    _p(
        "en-disable-guard",
        InjectionCategory.GUARDRAIL_REMOVAL,
        r"\b(disable|turn off|deactivate|remove)\b[^.\n]{0,30}"
        r"\b(privacy|gateway|guardrail|safety|filter|restriction|scope|limit)",
        "要求关闭安全机制（L5 明令禁止 agent 这么做）",
    ),
    _p(
        "en-expand-scope",
        InjectionCategory.GUARDRAIL_REMOVAL,
        r"\b(add|expand|extend|widen|include)\b[^\n]{0,40}\b"
        r"(scope|authoriz|permission|allowlist|allowed|whitelist)",
        "要求扩大授权范围（allowed / whitelist 也在列："
        "add X to the allowed scope 是同一意图的常见措辞）",
    ),
    # ---- 中文：指令覆盖 ----
    _p(
        "zh-ignore-previous",
        InjectionCategory.INSTRUCTION_OVERRIDE,
        r"(忽略|无视|忘掉|忘记|不要理会)[^。\n]{0,20}"
        r"(之前|以上|上面|先前|原有|全部)[^。\n]{0,10}(指令|要求|限制|规则|提示)",
        "中文：要求忽略既有指令",
    ),
    _p(
        "zh-new-instruction",
        InjectionCategory.INSTRUCTION_OVERRIDE,
        r"(新的?|更新后的?|最新的?)(系统)?(指令|要求|规则)[：:]",
        "中文：自称有新指令",
    ),
    # ---- 中文：角色伪装 ----
    _p(
        "zh-system-tag",
        InjectionCategory.ROLE_SPOOFING,
        r"(^|\n|\s)(系统|开发者|管理员|运维)(指令|消息|提示|命令|通知)\s*[：:]",
        "中文：伪装成系统消息",
    ),
    _p(
        "zh-system-in-comment",
        InjectionCategory.ROLE_SPOOFING,
        r"<!--[^>]{0,200}?(系统|指令|忽略|你需要|你必须)",
        "中文：HTML 注释里塞指令",
    ),
    # ---- 中文：新任务 ----
    _p(
        "zh-you-must-now",
        InjectionCategory.NEW_TASK_INJECTION,
        r"(你现在|请你现在|立即|马上)[^。\n]{0,15}"
        r"(需要|必须|应该|要)[^。\n]{0,20}(扫描|验证|访问|请求|发送|上传)",
        "中文：要求立即执行新动作",
    ),
    _p(
        "zh-scan-url",
        InjectionCategory.NEW_TASK_INJECTION,
        r"(扫描|访问|请求|测试|验证)[^。\n]{0,20}https?://",
        "中文：要求对某 URL 执行动作",
    ),
    # ---- 中文：数据外泄 ----
    _p(
        "zh-send-data",
        InjectionCategory.DATA_EXFILTRATION,
        r"(发送|上传|提交|回传|外发)[^。\n]{0,20}(到|至)[^。\n]{0,15}"
        r"(https?://|[\w.-]+@[\w.-]+)",
        "中文：要求把数据发往某地址",
    ),
    _p(
        "zh-include-credential",
        InjectionCategory.DATA_EXFILTRATION,
        r"(包含|带上|附带|输出|打印|显示)[^。\n]{0,15}"
        r"(密码|口令|凭据|密钥|令牌|证书|配置文件)",
        "中文：要求带出凭据",
    ),
    # ---- 中文：解除约束 ----
    _p(
        "zh-disable-guard",
        InjectionCategory.GUARDRAIL_REMOVAL,
        r"(关闭|禁用|停用|去掉|取消)[^。\n]{0,15}"
        r"(隐私|网关|脱敏|安全|防护|过滤|限制|范围|校验)",
        "中文：要求关闭安全机制",
    ),
    _p(
        "zh-expand-scope",
        InjectionCategory.GUARDRAIL_REMOVAL,
        r"(扩大|放宽|增加|添加)[^。\n]{0,15}(范围|授权|权限|白名单)",
        "中文：要求扩大授权范围",
    ),
    # ---- 其他语言（规格点名"多语言"）----
    _p(
        "ja-ignore",
        InjectionCategory.INSTRUCTION_OVERRIDE,
        r"(以前|前|上記)の(指示|命令|ルール)[^。\n]{0,10}(無視|忘れ)",
        "日文：要求忽略既有指令",
    ),
    _p(
        "ja-system",
        InjectionCategory.ROLE_SPOOFING,
        r"(^|\n|\s)(システム|開発者)(指示|メッセージ|命令)\s*[：:]",
        "日文：伪装成系统消息",
    ),
    _p(
        "ko-ignore",
        InjectionCategory.INSTRUCTION_OVERRIDE,
        r"(이전|위|앞서)[^.\n]{0,10}(지시|명령|규칙)[^.\n]{0,10}(무시|잊)",
        "韩文：要求忽略既有指令",
    ),
    _p(
        "ru-ignore",
        InjectionCategory.INSTRUCTION_OVERRIDE,
        r"(игнорируй|забудь)[^.\n]{0,30}(инструкц|правил|указани)",
        "俄文：要求忽略既有指令",
    ),
    _p(
        "es-ignore",
        InjectionCategory.INSTRUCTION_OVERRIDE,
        r"(ignora|olvida)[^.\n]{0,30}(instruccion|regla|indicacion)",
        "西班牙文：要求忽略既有指令",
    ),
    # ---- 编码变体（规格点名"编码变体"）----
    _p(
        "b64-ignore-hint",
        InjectionCategory.OBFUSCATED,
        r"\b(base64|b64|atob)\b[^.\n]{0,30}(decode|解密|解码)",
        "提示「解码后执行」—— 注入常藏在编码串里",
    ),
    _p(
        "zero-width",
        InjectionCategory.OBFUSCATED,
        r"[\u200b\u200c\u200d\u2060\ufeff]",
        "零宽字符：用于让字面量匹配失效（`ig\\u200bnore`）",
    ),
    _p(
        "homoglyph-cyrillic",
        InjectionCategory.OBFUSCATED,
        r"[\u0430\u0435\u043e\u0440\u0441\u0443\u0445]",
        "西里尔同形字：`а`(U+0430) 看起来像 `a` —— 绕过朴素匹配",
    ),
)

#: 规格要求的模式数下限（"预埋 20+ 种注入模式"）。
MIN_REQUIRED_PATTERNS = 20


# ---------------------------------------------------------------------------
# 检测
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InjectionHit:
    """一次注入特征命中。"""

    pattern_name: str
    category: str
    #: 命中的原文片段（**保留原文** —— 它是审计证据，不做改写）。
    matched: str
    #: 在输入中的偏移。
    offset: int
    note: str = ""


@dataclass(frozen=True)
class ScanReport:
    """一次目标内容扫描的结果。"""

    hits: tuple[InjectionHit, ...]

    @property
    def suspicious(self) -> bool:
        """是否应当标记为可疑并告警（`07` §T1 L4 的判据）。"""
        return len(self.hits) > 0

    def categories(self) -> tuple[str, ...]:
        """命中的类别（去重、有序）—— 用于告警分级。"""
        seen: list[str] = []
        for h in self.hits:
            if h.category not in seen:
                seen.append(h.category)
        return tuple(seen)

    def summary(self) -> str:
        if not self.suspicious:
            return "no injection indicators"
        parts = [f"{len(self.hits)} indicator(s)"]
        for c in self.categories():
            n = sum(1 for h in self.hits if h.category == c)
            parts.append(f"{c}={n}")
        return "; ".join(parts)


def normalize_for_matching(text: str) -> str:
    """归一化文本以**削弱**混淆（但不用它替换原文）。

    `07` 点名了"Unicode 同形字"与"编码变体"，因此朴素匹配不够。
    本函数做三件事：

    1. **NFKC 归一化**：把同形字折叠到规范形式
       （如全角 `ＩＧＮＯＲＥ` → `IGNORE`）
    2. **去除零宽字符**：`ig\\u200bnore` 去掉 U+200B 后就是 `ignore`
    3. **全角标点转半角**：中文语境里 `：` 与 `:` 混用

    ★ 归一化**只用于匹配**，命中时记录的 `matched` 仍是**原文** ——
    审计需要看到目标实际返回了什么，而不是我们加工后的版本
    （08 §6：目标响应原文是审计材料）。
    """
    # NFKC 覆盖全角/半角与多数兼容字符（含部分同形字）。
    out = unicodedata.normalize("NFKC", text)
    # 零宽与 BOM 类字符直接删除（它们不承载语义，只用于规避匹配）。
    for ch in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"):
        out = out.replace(ch, "")
    # 常见全角标点 → 半角（NFKC 已处理一部分，这里补齐中文习惯用法）。
    return out.replace("：", ":").replace("；", ";")


def scan(content: str) -> ScanReport:
    """扫描目标内容，标记注入特征（`07` §T1 L4）。

    **不做拦截、不做改写** —— 只标记并返回命中，由调用方决定
    如何告警（规格原文："标记为可疑并告警"）。

    检测在**归一化后**的文本上做（以削弱同形字/零宽字符绕过），
    但命中的 `matched` 取自原文。
    """
    if not content:
        return ScanReport(hits=())

    normalized = normalize_for_matching(content)
    hits: list[InjectionHit] = []
    for pat in PATTERNS:
        m = pat.pattern.search(normalized)
        if m is None:
            continue
        # 从原文里取对应片段：归一化通常不改变长度（除零宽删除），
        # 因此直接用归一化后的位置**尽最大努力**映射回原文。
        # 映射不上时回退为归一化片段 —— 宁可给出略失真的证据，
        # 也不要因为映射失败而漏报。
        start, end = m.start(), m.end()
        matched = normalized[start:end]
        if end <= len(content) and normalized[:start] == content[:start]:
            matched = content[start:end]
        hits.append(
            InjectionHit(
                pattern_name=pat.name,
                category=pat.category,
                matched=matched,
                offset=start,
                note=pat.note,
            )
        )

    # 确定性排序（P-5）：先按偏移，再按模式名 —— 与 PATTERNS 的声明顺序
    # 无关，因此调整模式库顺序不会改变输出。
    hits.sort(key=lambda h: (h.offset, h.pattern_name))
    return ScanReport(hits=tuple(hits))


def pattern_count() -> int:
    """模式总数（供自检断言 `07` §T1 的"20+"要求）。"""
    return len(PATTERNS)


def categories_covered() -> tuple[str, ...]:
    """已被模式覆盖的类别（缺类别说明该维度的检测是空的）。"""
    return tuple(sorted({p.category for p in PATTERNS}))
