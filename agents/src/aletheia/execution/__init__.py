"""execution —— 执行侧：规划 → 派发 → 回写（`docs/04` §I6 的 Agent 池）。

# 这个包补的是什么缺口

2026-11-02 的项目检查结论里最重的一条是：

> 生产代码中**无人调用** Provider。Provider 只在 tests/i12/ 与单测中使用，
> Go 侧也没有任何 LLM 客户端。因此 Planner 只接受外部喂入的任务图，
> Agent 池不存在，没有任何"规划 → 派发 Agent → 调用工具 → 回写证据"的自主循环。

本包把这条链接上，且**不破坏**原有分工：

    Planner（LLM）     只产出「有哪些任务、依赖关系」（不做逐步决策）
    Orchestrator（Go） 确定性拓扑 + 资源约束，回答「现在该跑哪些」
    Agent（本包）      执行单个任务，产出证据引用或失败记录
    ExecutionLoop      串起来；**循环本身零 LLM 调用**

# 三条不可越过的边界

1. **序列可复现**：循环里没有 LLM，`NextReady` 仍由 Go 侧确定性求解。
   这与 `05` §6.2 的契约硬约束一致（并有静态检查守护
   `core/orchestrate` 不引入任何 LLM 客户端）。
2. **无特权路径**：所有动作经 `IngestService.Execute`，其内部
   Scope → Gateway → Sandbox → Ledger 四道闸门照常生效（`07` §T7）。
   本包不允许直接调用任何内部函数。
3. **失败不伪装成功**：模型输出解析失败、任务图有环、无就绪但未完成，
   全部抛显式异常，而不是返回一个"看起来跑完了"的空报告
   （`docs/10` §0）。

# 已知边界（诚实声明）

* Agent 内部的"如何完成这一步"仍由模型决定，本包只保证**结构约束**
  （角色/依赖/预算）与**闸门不可绕**。模型可能选错工具或选错参数 ——
  那由 Scope Kernel（越界即拒）与账本（证据不足则结论不成立）兜底。
* 本包不实现自动重试/Refiner 改写。`Refine` 是独立 RPC，其调用策略
  属于编排层的决策，留待后续迭代（且需要真实失败数据才能校准）。
"""

from aletheia.execution.agents import (
    Agent,
    IngestPort,
    ToolCall,
    ToolCallParseError,
    ToolNotAllowedError,
    build_agent_prompt,
    parse_tool_call,
)
from aletheia.execution.loop import (
    DEFAULT_SLOTS,
    MAX_ROUNDS,
    AgentRunner,
    ExecutionError,
    ExecutionLoop,
    OrchestratorPort,
    RunReport,
    StalledError,
    TaskOutcome,
)
from aletheia.execution.planner import (
    MAX_TASKS,
    MIN_TASK_BUDGET,
    DraftTask,
    PlanDraft,
    PlannerLLM,
    PlanParseError,
    PlanValidationError,
    build_planner_prompt,
    extract_json,
    find_cycle,
    validate_plan,
)
from aletheia.execution.pool import AgentPool, MissingAgentError, PlanBoundRunner
from aletheia.execution.roles import (
    AGENT_ROLES,
    RoleSpec,
    UnknownRoleError,
    is_read_only,
    role_spec,
)

__all__ = [
    "AGENT_ROLES",
    "DEFAULT_SLOTS",
    "MAX_ROUNDS",
    "MAX_TASKS",
    "MIN_TASK_BUDGET",
    "Agent",
    "AgentPool",
    "AgentRunner",
    "DraftTask",
    "ExecutionError",
    "ExecutionLoop",
    "IngestPort",
    "MissingAgentError",
    "OrchestratorPort",
    "PlanBoundRunner",
    "PlanDraft",
    "PlanParseError",
    "PlanValidationError",
    "PlannerLLM",
    "RoleSpec",
    "RunReport",
    "StalledError",
    "TaskOutcome",
    "ToolCall",
    "ToolCallParseError",
    "ToolNotAllowedError",
    "UnknownRoleError",
    "build_agent_prompt",
    "build_planner_prompt",
    "extract_json",
    "find_cycle",
    "is_read_only",
    "parse_tool_call",
    "role_spec",
    "validate_plan",
]
