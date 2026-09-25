"""G-3 证据强度模式库（modules/M4 §4.2，T4.4）。

核心主张（D1 幻觉式成功的正面对策）：利用是否成功**不由工具输出自述
决定**，只由目标侧副作用观测决定。

反面教材（调研实测：searchsploit 任何输出都含 "Shellcodes"，任何服务
回显都含 "login:"，字符串匹配产生 100% 假阳性）::

    if "login:" in output or "shellcodes" in output.lower(): return "confirmed"

设计约束：

1. 模式由 **M4 维护**，不是 agent 提供 —— agent 无法自带宽松模式绕过
   G-3（07 §T1/T4 组合攻击的防御面）。
2. 每条模式有名字与出处注释；``matched_pattern`` 记录命中名，可审计。
3. 模式刻意**窄**：宁可漏（停在 CANDIDATE）也不误报（进 CONFIRMED）。
   假阴性的代价比假阳性低一个量级 —— 这是 05 §5.1 状态机语义的直接推论。
4. 扩展模式属安全决策：每条新增必须带正反例测试（M4 §6）。

I2 的模式集是「最小可信集」：只覆盖副作用观测中输出形态最稳定的三类。
PROCESS_SPAWNED / CONFIG_CHANGED 的通用形态依赖具体验证命令，
I2 不放猜测性宽模式 —— 对应 kind 的观测将显式记为「无模式命中」
（accepted=False，不计入 G-3），而不是用一个不可信的正则去匹配。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aletheia.gen.aleth.v1 import aletheia_pb2 as pb


@dataclass(frozen=True)
class EvidencePattern:
    """一条副作用观测验证模式。"""

    kind: pb.ObserverKind.V
    name: str
    regex: re.Pattern[str]
    rationale: str


# id(1) 输出：root 身份的直接证据（M4 §4.2 示例模式）。
_ID_ROOT = EvidencePattern(
    kind=pb.ObserverKind.ID_OUTPUT,
    name="id_root",
    regex=re.compile(r"uid=0\(root\)\s+gid=0\(root\)"),
    rationale="id(1) 输出显示 uid=0/gid=0 —— root 执行绑定的直接观测",
)
_ID_ANY = EvidencePattern(
    kind=pb.ObserverKind.ID_OUTPUT,
    name="id_generic",
    regex=re.compile(r"uid=\d+\([A-Za-z_][\w.-]{0,31}\)\s+gid=\d+\([A-Za-z_][\w.-]{0,31}\)"),
    rationale="id(1) 标准输出形态 —— 已获得目标侧 shell 的通用观测",
)

# /etc/passwd 新增行：账号创建的稳定形态（useradd 后 cat /etc/passwd）。
_PASSWD_ENTRY = EvidencePattern(
    kind=pb.ObserverKind.ACCOUNT_CREATED,
    name="passwd_entry",
    regex=re.compile(r"(?m)^[\w.-]+:[x*!]?:\d{3,4}:\d{3,4}:[^:]*:[^:]*:[^:\n]+$"),
    rationale="passwd(5) 行格式 —— 新账号落库的直接观测",
)

# sha256sum 输出行：目标侧文件存在且有内容的可复核形态。
_SHA256_OUTPUT = EvidencePattern(
    kind=pb.ObserverKind.FILE_CREATED,
    name="sha256_output",
    regex=re.compile(r"(?m)^[0-9a-f]{64}[* \t]+\S"),
    rationale="sha256sum(1) 输出行 —— 落盘文件可复核校验和",
)

# /etc/passwd 的 root 行出现在取回数据中：敏感数据外带的直接证据。
_ROOT_LINE_EXFIL = EvidencePattern(
    kind=pb.ObserverKind.DATA_RETURNED,
    name="root_line_exfiltrated",
    regex=re.compile(r"(?m)^root:[x*!]?:0:0:"),
    rationale="passwd root 行出现在回传数据 —— 敏感文件内容已取回",
)

# crontab -l 行：持久化配置变更的稳定形态。
_CRONTAB_ENTRY = EvidencePattern(
    kind=pb.ObserverKind.CONFIG_CHANGED,
    name="crontab_entry",
    regex=re.compile(r"(?m)^[\d*,/-]+\s+[\d*,/-]+\s+[\d*,/-]+\s+[\d*,-]+\s+[\d*,-]+\s+\S"),
    rationale="crontab(5) 行格式 —— 定时任务配置已写入",
)

# ps 输出中的伪终端行：交互进程已在目标侧运行。
_PS_PTS = EvidencePattern(
    kind=pb.ObserverKind.PROCESS_SPAWNED,
    name="ps_pts_entry",
    regex=re.compile(r"(?m)^\s*\d+\s+pts/\d+"),
    rationale="ps 输出含 pts 伪终端行 —— 交互 shell 进程存在",
)

PATTERNS: tuple[EvidencePattern, ...] = (
    _ID_ROOT,
    _ID_ANY,
    _PASSWD_ENTRY,
    _SHA256_OUTPUT,
    _ROOT_LINE_EXFIL,
    _CRONTAB_ENTRY,
    _PS_PTS,
)


def find_hits(kind: pb.ObserverKind.V, observation: str) -> list[EvidencePattern]:
    """返回该观测命中的全部模式（按库序）。空列表 = 无强证据。"""
    return [p for p in PATTERNS if p.kind == kind and p.regex.search(observation)]


def audit_text(observation: str) -> list[EvidencePattern]:
    """用**全库**模式扫描一段文本（反例审计用）。

    弱证据的反面教材（"exploit completed" / "Shellcodes" / "login:"）必须
    在任何 kind 下都不命中 —— 本函数就是那条测试的执行器。
    """
    return [p for p in PATTERNS if p.regex.search(observation)]
