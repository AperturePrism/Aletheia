"""Agent 角色规格（`docs/04` §I6 的 Agent 池）。

# 本模块解决什么

I6 的交付物要求「Agent 池（Recon/Scanner/Fuzzer/Exploiter/Reporter）」，
而 `proto` 里 `AgentRole` 已经冻结了八个角色。本模块把每个角色**能做什么**
写成数据（工具白名单 / 模型档位 / 提示词骨架），而不是散落在 if-else 里。

# 为什么角色必须是"数据"而不是"代码分支"

三条理由，都与本项目的原则直接相关：

1. **可审计**（P-1 证据优先）：安全评审需要一眼看到"Exploiter 允许调哪些
   工具"。如果权限散在代码里，评审只能靠通读；做成表则可以逐项核对，
   也才能被测试断言（见 `tests/execution/test_roles.py`）。
2. **可测**：`AGENT_ROLES` 是一张不变量表 —— 每个角色都必须有非空工具集、
   必须绑定合法档位、高危角色必须显式标注。这些都能静态断言。
3. **fail-closed 的落点**（P-4）：未知角色不存在"默认允许"，
   而是直接拒绝（`UnknownRoleError`）。默认放开是这类系统最常见的
   失效方式。

# 工具白名单的边界

白名单里的名字是**工具标识**（对应 `IngestService.Execute` 的
`tool_name`），不是任意命令。真实执行仍要经过 Sandbox + Scope Kernel +
Privacy Gateway 三道闸门 —— 本表只回答"这个角色**可以尝试**调什么"。

因此本表**不是**安全边界。真正的边界在 Go 侧（`core/ingest` +
`core/scopekernel`）。把这一点写清楚，是为了避免有人误以为
"改这里就能放开权限"—— 改了这里，越界请求照样会被 Scope Kernel 拒绝。
"""

from __future__ import annotations

from dataclasses import dataclass


class UnknownRoleError(KeyError):
    """请求了不存在的角色。

    继承 `KeyError` 以便调用方按字典语义处理，但**名称是显式的** ——
    `except KeyError` 太宽，会顺手吞掉拼写错误之外的 bug（P-4：失败要明确）。
    """


@dataclass(frozen=True)
class RoleSpec:
    """一个 Agent 角色的规格。

    `tools` 是"可以尝试调用的工具标识"白名单；`tier` 是模型档位
    （交给 `providers.Router` 决定实际模型）；`may_act` 标记该角色是否会
    **产生副作用**（对目标发起真实动作）。
    """

    #: 与 proto `AgentRole` 枚举名一致（大写），便于直接映射。
    proto_name: str
    #: 人类可读的中文名。
    label: str
    #: 允许尝试调用的工具标识（白名单）。
    tools: frozenset[str]
    #: 模型档位（`providers.DEFAULT_TIERS` 的键）。
    tier: str
    #: 该角色是否会对目标产生副作用（只读角色不需要 Exploiter 级的审慎）。
    may_act: bool
    #: 提示词骨架的用途说明（真正的提示词在 `planning` / `dispatch` 中组装）。
    purpose: str


#: Agent 池的角色表 —— `docs/04` §I6 点名的五个角色 + post_exploit。
#:
#: 「多 agent 只在高价值环节启用」（04 §I6 关键决策②）：
#: 因此表里刻意**不含** Fuzzer 之外的重复能力，且 Reporter 只读。
AGENT_ROLES: dict[str, RoleSpec] = {
    "RECON": RoleSpec(
        proto_name="RECON",
        label="侦察",
        # 只做被动/半被动信息收集，不触发漏洞利用类动作。
        tools=frozenset({"nmap", "httpx", "whatweb", "subfinder"}),
        tier="parse_assist",
        may_act=False,
        purpose="收集目标资产、端口、服务与技术栈，产出可入库的实体",
    ),
    "SCANNER": RoleSpec(
        proto_name="SCANNER",
        label="扫描",
        tools=frozenset({"nmap", "nuclei", "nikto"}),
        tier="analysis",
        may_act=True,
        purpose="在已知资产上发现可验证的缺陷（要求产出可复现证据）",
    ),
    "FUZZER": RoleSpec(
        proto_name="FUZZER",
        label="模糊测试",
        tools=frozenset({"ffuf", "feroxbuster", "wfuzz"}),
        tier="parse_assist",
        may_act=True,
        purpose="枚举隐藏路径与参数（高噪声，需严格速率与范围约束）",
    ),
    "EXPLOITER": RoleSpec(
        proto_name="EXPLOITER",
        label="利用",
        tools=frozenset({"sqlmap", "nuclei", "curl", "msfconsole"}),
        tier="planning",
        may_act=True,
        purpose="对已发现缺陷做最小化利用验证（禁止破坏性载荷）",
    ),
    "POST_EXPLOIT": RoleSpec(
        proto_name="POST_EXPLOIT",
        label="后渗透",
        tools=frozenset({"curl", "ssh", "impacket-secretsdump"}),
        tier="planning",
        may_act=True,
        purpose="在已授权范围内评估影响（痕迹只记录不清理，09 §R6）",
    ),
    "REPORTER": RoleSpec(
        proto_name="REPORTER",
        label="报告",
        tools=frozenset(),  # 不调工具：只消费账本里的证据
        tier="analysis",
        may_act=False,
        purpose="从证据账本生成报告（不得引入未经证据支持的结论）",
    ),
}


def role_spec(proto_name: str) -> RoleSpec:
    """按 proto 枚举名取角色规格。

    fail-closed：未知角色抛 `UnknownRoleError`，**没有默认值**。
    """
    key = (proto_name or "").strip().upper()
    try:
        return AGENT_ROLES[key]
    except KeyError as exc:
        raise UnknownRoleError(
            f"未知 Agent 角色 {proto_name!r}；"
            f"可用角色：{sorted(AGENT_ROLES)}。"
            "（不提供默认角色 —— 默认放开是这类系统最常见的失效方式）"
        ) from exc


def is_read_only(proto_name: str) -> bool:
    """该角色是否只读（不产生副作用）。"""
    return not role_spec(proto_name).may_act
