"""Agent 池：按任务的角色把工作派给对应 Agent。

# 为什么需要这一层（而不是让循环直接构造 Agent）

`ExecutionLoop` 只认识 `AgentRunner.run(task_id) -> TaskOutcome` 这个窄接口。
把"task_id → 角色 → Agent"的解析放在池里，好处是：

1. **循环与角色表解耦**：加一个角色不需要改循环；
2. **角色缺失是显式错误**：计划里出现了池中没有的角色 → 拒绝执行，
   而不是"没有对应 Agent 就当完成"（那是虚假完成）；
3. **可测**：池可以用假 Agent 填充，不必碰网络。

# 角色到 Agent 的绑定

每个角色一个 `Agent`（共享同一 Router 与 IngestPort，档位由 `RoleSpec.tier`
决定）。这不是"多 agent 协作"的花哨设计 —— `04` §I6 决策②明确说
"多 agent 只在高价值环节启用"，这里的分工是**按能力边界**（谁可以调什么），
而不是让多个 agent 对同一件事投票。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aletheia.execution.agents import Agent, IngestPort
from aletheia.execution.loop import TaskOutcome
from aletheia.execution.planner import DraftTask, PlanDraft
from aletheia.execution.roles import AGENT_ROLES, role_spec


class MissingAgentError(RuntimeError):
    """计划里的角色在池中没有对应 Agent。"""


@dataclass
class AgentPool:
    """按角色分发的 Agent 池。"""

    router: Any
    ingest: IngestPort
    #: 显式注入的 Agent（按 proto 角色名）。未提供的角色会按需用
    #: `router` + `ingest` + `RoleSpec` 自动构造 —— 但 `enabled_roles`
    #: 之外的**不会**被静默创建。
    agents: dict[str, Agent] = field(default_factory=dict)
    #: 允许的角色集合。默认只有计划里会出现的六个。
    enabled_roles: frozenset[str] = frozenset(AGENT_ROLES)

    def _agent_for(self, role: str) -> Agent:
        spec = role_spec(role)  # 未知角色 → UnknownRoleError（fail-closed）
        if spec.proto_name not in self.enabled_roles:
            raise MissingAgentError(
                f"角色 {spec.proto_name} 未启用；已启用：{sorted(self.enabled_roles)}"
            )
        existing = self.agents.get(spec.proto_name)
        if existing is not None:
            return existing
        agent = Agent(spec=spec, router=self.router, ingest=self.ingest)
        self.agents[spec.proto_name] = agent
        return agent


@dataclass
class PlanBoundRunner:
    """把一个 `PlanDraft` 绑到 Agent 池上，得到循环需要的 `AgentRunner`。

    循环只传 task_id，因此这里必须能按 id 找到计划里的任务
    （角色与目标都在计划里）。找不到 → 显式错误，不猜。
    """

    plan: PlanDraft
    pool: AgentPool
    _by_id: dict[str, DraftTask] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self._by_id = {t.task_id: t for t in self.plan.tasks}

    def run(self, task_id: str) -> TaskOutcome:
        task = self._by_id.get(task_id)
        if task is None:
            raise KeyError(f"计划中没有任务 {task_id!r}（计划含 {sorted(self._by_id)}）")
        return self.pool._agent_for(task.role).run(task)
