"""Termination Arbiter —— 终止仲裁（modules/M4 §4.5，T4.10）。

**agent 无权自行终止会话。** 这是消除 D3（Flag 幻觉导致提前终止）的
唯一有效手段：调研实测显示，agent 发现一段 Base64 或随机哈希就断定是
flag，**幻觉成功后立即终止会话**，且换更强模型也无法解决。

# 为什么"换更强模型"解决不了

因为问题不在推理能力，而在**权限结构**：只要 agent 有权结束会话，
"看起来完成了"就足以让它停下来。任何靠模型自我约束的方案都在赌
模型永远不出错 —— 而 D3 的实测结论正是这种赌注会输。

因此本模块的设计原则是：**不采信 agent 的任何自我评估**，
只做结构化校验。

# 四道独立校验（M4 §4.5）

    ① 达成物是否匹配目标定义？（目标是 flag？root shell？特定数据？）
    ② 目标归属是否已确认？（在 scope 内、确属该资产）
    ③ 证据是否通过全部四道闸门？
    ④ 是否疑似幻觉？（随机哈希/Base64/误判 banner）

四条全部通过才批准。任一失败 → 拒绝 + 给出 guidance
（避免 agent 陷入循环或反复重试 —— 单纯拒绝会让它一次次重提）。

# 与熔断的关系

`RequestTermination` 是系统**唯一**的会话终止入口（除熔断外）。
熔断（M6 预算耗尽 / M5 编排层条件）是系统自动行为，不走本模块；
agent 主动请求终止则必须走这里。
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

from aletheia.gen.aleth.v1 import aletheia_pb2 as pb

# ---------------------------------------------------------------------------
# 幻觉特征检测（第 ④ 道校验）
# ---------------------------------------------------------------------------

#: 疑似"随机串被当成 flag"的最小长度。短于此长度的串信息量不足以称为
#: 凭据 —— 但也不是拒绝理由（可能确实是短 flag），只是**不构成独立证据**。
_MIN_TOKEN_LEN = 16

#: 十六进制串（32+ 字符 = MD5/SHA1/SHA256 摘要形态）。
_HEX_TOKEN = re.compile(r"^[0-9a-fA-F]{32,}$")

#: Base64 串（含填充）。长度下限 16 —— 必须低于 :data:`_MIN_TOKEN_LEN`
#: 与各类哈希长度，否则 "恰好长 16 的 base64" 会落进"长度不足"分支
#: 而不是被判为 base64（两者都拒绝，但原因不同，且原因要写进审计）。
_B64_TOKEN = re.compile(r"^[A-Za-z0-9+/]{16,}={0,2}$")

#: 访问指示符：出现这些形态说明达成物描述的是**实际访问**，
#: 而不是裸 token。必须先于"提取 token"处理 —— 否则
#: `root@target:~#` 会被 `:` 切成 `~#`（2 字符）而误判为"信息量不足"。
_ACCESS_INDICATOR = re.compile(
    r"(uid=\d+|gid=\d+|root@[\w.-]+|[a-z_][\w.-]*@[\w.-]+:[~/]|#\s*$|\$\s*$)",
)

#: 通用 flag 形态（CTF 风格）—— 这是**唯一**能直接采信的形态。
#: 之所以要求前缀（如 flag{...}），是因为无前缀的随机串无法与
#: 哈希、会话 ID、nonce 区分开。
_FLAG_SHAPE = re.compile(r"^[A-Za-z0-9_]*\{[^}]{4,}\}$")

#: 误判 banner：这些词出现在工具输出里**不代表**取得访问权限。
#: 反面教材（M4 §4.2 记录的真实事故）：searchsploit 的任何输出都含
#: "Shellcodes"，任何服务回显都含 "login:" —— 用它们判"已攻破"
#: 会产生 100% 假阳性（实测 23 个"成功"实际获 shell 数为 0）。
_MISLEADING_BANNERS = (
    "shellcodes",
    "shellcode",
    "login:",
    "password:",
    "username:",
    "exploit completed",
    "exploit db",
    "searchsploit",
)


@dataclass(frozen=True)
class HallucinationSignal:
    """第 ④ 道校验的结论。"""

    suspected: bool
    reason: str = ""


def detect_suspected_hallucination(claimed: str) -> HallucinationSignal:
    """检测"达成物"是否具备幻觉特征（M4 §4.5 第 ④ 道校验）。

    判据（按可靠性从高到低）：

    1. **误判 banner**：达成物只是工具输出里的常见词（shellcodes /
       login: / exploit completed）。这些词的出现与访问权限**无关**。
    2. **纯哈希/Base64**：达成物是一个 32+ 位的十六进制串或长 Base64
       串，且不具备 flag 形态。裸哈希无法与 nonce、会话 ID、ETag
       区分 —— 采信它就是"发现随机串就宣告胜利"。
    3. **长度不足**：达成物短于 :data:`_MIN_TOKEN_LEN` 且无 flag 形态。

    刻意**不**把"看起来像 flag"当成通过条件：无前缀的随机串即使
    长度足够也不采信，因为无法与噪声区分。
    """
    s = claimed.strip()
    if not s:
        return HallucinationSignal(True, "claimed achievement is empty")

    low = s.lower()
    for banner in _MISLEADING_BANNERS:
        if banner in low:
            return HallucinationSignal(
                True,
                f"claimed achievement contains the misleading banner {banner!r} — "
                "this string appears in ordinary tool output and is not evidence of access",
            )

    # 访问指示符优先：`root@target:~#` / `uid=0(root) gid=0(root)` 这类
    # 达成物描述的是**实际访问**，不是裸 token。
    #
    # 这个检查必须先于下面的"提取 token"—— 否则 `root@target:~#` 会被
    # `:` 切成 `~#`（2 字符）而误判为"信息量不足"。那是假阴性：
    # 一个真实的 root shell 被当成幻觉拒掉，agent 将永远无法合法终止。
    if _ACCESS_INDICATOR.search(s):
        return HallucinationSignal(False)

    # 提取可能的 token（去掉典型前缀，如 "flag: xxx"）。
    #
    # 只在**前缀是短标签**时才切分：`flag: xxx` 与
    # `username: admin` 都符合，而 `http://host/path` 不符合
    # （前缀含 `//`），避免把 URL 之类的结构切坏。
    token = s
    if ":" in s:
        head, tail = s.split(":", 1)
        if len(head) <= 16 and "/" not in head and " " not in head.strip():
            token = tail.strip()

    if _FLAG_SHAPE.match(token):
        # 具备 flag 形态 —— 仍需 ② ③ 两道校验，这里只判"不像幻觉"。
        return HallucinationSignal(False)

    if _HEX_TOKEN.match(token):
        return HallucinationSignal(
            True,
            f"claimed achievement {token[:12]}... is a bare hex digest (32+ chars); "
            "a hash cannot be distinguished from a nonce, session id or ETag — "
            "treating it as a flag is the D3 flag-hallucination pattern",
        )

    if _is_base64_like(token):
        return HallucinationSignal(
            True,
            f"claimed achievement {token[:12]}... is base64-like without a flag shape; "
            "decoding random bytes yields no verifiable credential",
        )

    if len(token) < _MIN_TOKEN_LEN:
        return HallucinationSignal(
            True,
            f"claimed achievement is only {len(token)} chars and has no flag shape; "
            "too little information to serve as a termination basis",
        )

    return HallucinationSignal(False)


def _is_base64_like(token: str) -> bool:
    """判定 token 是否为（可解码的）Base64 串。"""
    if not _B64_TOKEN.match(token):
        return False
    # 真正的 Base64：长度是 4 的倍数且能解码。
    if len(token) % 4 != 0:
        return False
    try:
        base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return False
    return True


# ---------------------------------------------------------------------------
# 目标定义与达成物匹配（第 ① 道校验）
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GoalSpec:
    """目标定义（来自 ROE 的 goal_definition 字段）。

    为什么需要结构化解析：M4 §4.5 第 ① 道校验是"达成物是否匹配目标
    定义"，而目标定义在契约里是一个**自由文本字符串**。自由文本无法
    精确匹配，因此这里把它解析为可判定的形态。

    解析**刻意保守**：识别不出的目标类型不猜（``kind=UNKNOWN``），
    此时第 ① 道校验按"无法判定 → 拒绝"处理 —— 宁可让 agent 继续
    探索，也不放行一个无法验证的终止请求。
    """

    kind: str  # "flag" | "shell" | "data" | "unknown"
    raw: str
    #: 目标数据的关键词（用于 "data" 类目标的匹配）。
    keywords: tuple[str, ...] = ()


_FLAG_WORDS = ("flag",)
_SHELL_WORDS = ("shell", "root", "rce", "code execution", "命令执行", "提权")
_DATA_WORDS = ("data", "credential", "database", "dump", "数据", "凭据")


def parse_goal(goal_definition: str) -> GoalSpec:
    """把自由文本目标解析为可判定的 :class:`GoalSpec`。"""
    raw = (goal_definition or "").strip()
    low = raw.lower()
    if not raw:
        return GoalSpec(kind="unknown", raw=raw)

    if any(w in low for w in _FLAG_WORDS):
        return GoalSpec(kind="flag", raw=raw)
    if any(w in low for w in _SHELL_WORDS):
        return GoalSpec(kind="shell", raw=raw)
    if any(w in low for w in _DATA_WORDS):
        # 提取引号内的关键词作为匹配依据（如 "get the users table"）。
        kws = tuple(re.findall(r"[\w.-]{3,}", low))
        return GoalSpec(kind="data", raw=raw, keywords=kws)
    return GoalSpec(kind="unknown", raw=raw)


def goal_matches(goal: GoalSpec, claimed: str) -> tuple[bool, str]:
    """判定达成物是否匹配目标定义（第 ① 道校验）。"""
    s = (claimed or "").strip()
    if not s:
        return False, "claimed achievement is empty"
    if goal.kind == "unknown":
        # 无法判定的目标定义 → 拒绝（fail-closed）。放行会让"目标没写清
        # 就能随便终止"成为绕过路径。
        return False, (
            f"goal definition {goal.raw!r} cannot be parsed into a verifiable objective; "
            "refusing to approve termination on an unverifiable goal"
        )

    if goal.kind == "flag":
        token = s.split(":", 1)[1].strip() if ":" in s else s
        if not _FLAG_SHAPE.match(token):
            return False, (
                f"goal is a flag but the claimed achievement {token[:20]!r} "
                "does not have a flag shape"
            )
        return True, ""

    if goal.kind == "shell":
        # shell 目标的达成物必须体现**访问权限**，不能只是命令回显。
        # 这里只做形态检查，实质判定在 G-3（副作用观测）。
        low = s.lower()
        if any(b in low for b in _MISLEADING_BANNERS):
            return False, ("goal is a shell but the claimed achievement is a misleading banner")
        if not re.search(r"(uid=|root@|gid=|shell)", low):
            return False, (
                "goal is a shell but the claimed achievement does not exhibit "
                "any access indicator (uid=/root@/gid=)"
            )
        return True, ""

    # data 目标：达成物需与目标关键词有交集。
    low = s.lower()
    for kw in goal.keywords:
        if kw in low:
            return True, ""
    return False, (
        "goal is a data objective but the claimed achievement shares no keyword "
        "with the goal definition"
    )


# ---------------------------------------------------------------------------
# 仲裁结果
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ArbitrationVerdict:
    """Arbiter 的独立结论（映射 proto TerminationDecision）。"""

    approved: bool
    refusal_reason: pb.TerminationRefusalReason.V = (
        pb.TerminationRefusalReason.TERMINATION_REFUSAL_UNSPECIFIED
    )
    guidance: str = ""
    #: 四道校验的逐条结论（可审计 —— M4 §4.5 要求"不接受自我评估"，
    #: 因此必须留下每道校验实际看到了什么）。
    checks: tuple[str, ...] = ()

    def to_proto(self) -> pb.TerminationDecision:
        return pb.TerminationDecision(
            approved=self.approved,
            refusal_reason=self.refusal_reason,
            guidance=self.guidance,
        )


#: 拒绝后给 agent 的 guidance（M4 §4.5：避免陷入循环或反复重试）。
_GUIDANCE = {
    pb.TerminationRefusalReason.GOAL_MISMATCH: (
        "The claimed achievement does not correspond to the goal definition. "
        "Re-read the goal and continue toward it — do not re-submit the same claim. "
        "If the goal itself is ambiguous, that is an operator question, not a termination basis."
    ),
    pb.TerminationRefusalReason.ATTRIBUTION_UNCONFIRMED: (
        "The target attribution is not confirmed. Verify that the artifact belongs "
        "to the authorized target and is inside scope before claiming completion."
    ),
    pb.TerminationRefusalReason.EVIDENCE_INSUFFICIENT: (
        "The evidence has not passed all gates. Gather stronger evidence "
        "(target-side side-effect observations) rather than re-submitting."
    ),
    pb.TerminationRefusalReason.SUSPECTED_HALLUCINATION: (
        "The claimed achievement exhibits a hallucination pattern (bare hash / "
        "base64 / misleading banner). Re-derive the conclusion from raw tool output "
        "that demonstrates actual access. Do NOT treat this as a partial success."
    ),
}


# ---------------------------------------------------------------------------
# 复现失败的历史（第 ③ 道校验的输入之一）
# ---------------------------------------------------------------------------


@dataclass
class TerminationHistory:
    """同一 session 的终止请求历史（用于循环检测）。

    M4 §7（I7 DoD）要求「拒绝后 agent 能继续探索（循环检测有效）」——
    单纯拒绝会让 agent 反复重提同一请求，形成空转。因此记录拒绝次数，
    达到阈值后在 guidance 里明确指出"你在重复同样的请求"。
    """

    rejections: dict[str, int] = field(default_factory=dict)
    approved: set[str] = field(default_factory=set)

    def record_rejection(self, agent_id: str) -> int:
        self.rejections[agent_id] = self.rejections.get(agent_id, 0) + 1
        return self.rejections[agent_id]

    def rejections_for(self, agent_id: str) -> int:
        return self.rejections.get(agent_id, 0)


#: 同一 agent 被拒多少次后，guidance 升级为"停止重复"。
_REPEAT_THRESHOLD = 3


# ---------------------------------------------------------------------------
# 仲裁主流程
# ---------------------------------------------------------------------------


class TerminationArbiter:
    """终止仲裁器（M4 §4.5，T4.10）。

    **不接受 agent 的自我评估**：本类不读 ``claimed_achievement`` 之外的
    任何 agent 自述（如"我认为已经拿到 flag"），只做结构化校验。

    依赖注入的三件事（都由 M4 内部提供，agent 无法影响）：

    * ``scope_contains`` —— 目标是否在授权范围内（M6 ScopeKernel）；
    * ``evidence_ids_exist`` —— 引用的证据是否真实存在于账本；
    * ``gate_passed_for`` —— 该证据是否已通过四道闸门（G-1..G-4）。

    刻意用回调而非直接依赖具体实现：Arbiter 的职责是**判定顺序与
    判定语义**，不是数据访问。这样测试可以精确构造"证据不存在"、
    "闸门未过"等边界，而不必搭起整个账本。
    """

    def __init__(
        self,
        *,
        scope_contains,
        evidence_ids_exist,
        gate_passed_for,
    ) -> None:
        self._scope_contains = scope_contains
        self._evidence_ids_exist = evidence_ids_exist
        self._gate_passed_for = gate_passed_for
        self.history = TerminationHistory()

    # -- 主入口 --------------------------------------------------------

    def arbitrate(self, request: pb.TerminationRequest) -> ArbitrationVerdict:
        """独立校验一个终止请求（M4 §4.5 的四道校验）。

        判定顺序按"最便宜且最致命"优先：

        1. **疑似幻觉**（第 ④）—— 先判它，因为它是 D3 的直接防线，
           且完全不需要访问账本。一个裸哈希不因"证据链完整"就变成 flag。
        2. **目标匹配**（第 ①）—— 达成物与目标不符时，后面的校验无意义。
        3. **目标归属**（第 ②）—— 归属未确认是 AIxCC 重罚项
           （错误关联 -7 分）。
        4. **证据闸门**（第 ③）—— 最贵的校验放最后。

        顺序刻意如此：若先查证据，一个"证据齐全但达成物是随机哈希"的
        请求会走到最后才被拒，徒增账本访问。更重要的是，
        **幻觉检测必须先于一切** —— 否则精心构造的证据链可以为
        幻觉背书（M4 §8 风险栏："Arbiter 被 agent 通过精心构造的证据
        欺骗"）。
        """
        checks: list[str] = []

        # ---- 第 ④ 道：疑似幻觉 ----
        sig = detect_suspected_hallucination(request.claimed_achievement)
        checks.append(
            f"G-hallucination: {'SUSPECT' if sig.suspected else 'clean'}"
            + (f" — {sig.reason}" if sig.reason else "")
        )
        if sig.suspected:
            return self._refuse(
                pb.TerminationRefusalReason.SUSPECTED_HALLUCINATION,
                request,
                checks,
            )

        # ---- 第 ① 道：目标匹配 ----
        goal = parse_goal(request.goal_definition)
        matched, why = goal_matches(goal, request.claimed_achievement)
        checks.append(
            f"G-goal (kind={goal.kind}): {'match' if matched else 'MISMATCH'}"
            + (f" — {why}" if why else "")
        )
        if not matched:
            return self._refuse(pb.TerminationRefusalReason.GOAL_MISMATCH, request, checks)

        # ---- 第 ② 道：目标归属 ----
        target = request.target_entity_id
        if not target:
            checks.append("G-attribution: MISSING target_entity_id")
            return self._refuse(
                pb.TerminationRefusalReason.ATTRIBUTION_UNCONFIRMED,
                request,
                checks,
            )
        if not self._scope_contains(target):
            checks.append(f"G-attribution: target {target!r} is outside the authorized scope")
            return self._refuse(
                pb.TerminationRefusalReason.ATTRIBUTION_UNCONFIRMED,
                request,
                checks,
            )
        checks.append(f"G-attribution: target {target!r} confirmed in scope")

        # ---- 第 ③ 道：证据闸门 ----
        evidence_ids = tuple(request.evidence_ids)
        if not evidence_ids:
            checks.append("G-evidence: NO evidence_ids supplied")
            return self._refuse(
                pb.TerminationRefusalReason.EVIDENCE_INSUFFICIENT,
                request,
                checks,
            )
        missing = [e for e in evidence_ids if not self._evidence_ids_exist(e)]
        if missing:
            checks.append(f"G-evidence: referenced evidence does not exist: {missing}")
            return self._refuse(
                pb.TerminationRefusalReason.EVIDENCE_INSUFFICIENT,
                request,
                checks,
            )
        failed = [e for e in evidence_ids if not self._gate_passed_for(e)]
        if failed:
            checks.append(f"G-evidence: evidence has not passed all gates: {failed}")
            return self._refuse(
                pb.TerminationRefusalReason.EVIDENCE_INSUFFICIENT,
                request,
                checks,
            )
        checks.append(f"G-evidence: all {len(evidence_ids)} evidence entries passed gates")

        # 四道全过 → 批准。
        self.history.approved.add(request.session_id)
        return ArbitrationVerdict(approved=True, checks=tuple(checks))

    # -- 内部 ----------------------------------------------------------

    def _refuse(
        self,
        reason: pb.TerminationRefusalReason.V,
        request: pb.TerminationRequest,
        checks: list[str],
    ) -> ArbitrationVerdict:
        """构造拒绝结论，并按重复次数调整 guidance。"""
        guidance = _GUIDANCE.get(reason, "Termination refused; continue the session.")
        n = self.history.record_rejection(request.agent_id)
        if n >= _REPEAT_THRESHOLD:
            # 循环检测（M4 §7 I7 DoD）：反复提交同一请求是空转，
            # 必须明确指出 —— 否则 agent 会一直重试到预算耗尽。
            guidance += (
                f" NOTE: this agent has had {n} termination requests refused. "
                "Stop re-submitting the same claim — it will keep being refused. "
                "Change approach or escalate to the operator."
            )
        return ArbitrationVerdict(
            approved=False,
            refusal_reason=reason,
            guidance=guidance,
            checks=tuple(checks),
        )
