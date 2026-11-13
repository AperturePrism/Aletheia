"""Planner：LLM 生成任务图，确定性校验后交给 Go 侧求解。

# 本模块的职责边界（`docs/04` §I6 关键决策①）

    LLM 只生成"有哪些任务、依赖关系"，不做逐步决策。
    序列求解交给确定性规划器（拓扑排序 + 资源约束）。

因此本模块**只做两件事**：

1. 把"目标 + 范围 + 预算"组装成提示词，向模型要一张任务图草稿；
2. 对草稿做**严格校验**（fail-closed），不合格就拒绝，绝不"猜它的意思"
   或自动修补。

真正的序列求解在 Go 侧 `core/orchestrate`（`NextReady` 零 LLM，
`05` §6.2 契约硬约束，且有静态检查守护）。

# 为什么校验必须严格到"拒绝"而不是"尽量修正"

模型输出是不可信输入（与目标响应同级）。若我们自动补 id、自动去环、
自动裁剪预算，就会出现两种坏结果：

* **静默改写了用户的计划**：审计时无法区分"模型说的"与"我们改的"；
* **把解析失败伪装成成功**：`docs/10` §0 说的"用绿灯替换有效性"。

所以这里的策略是：**能验证的逐项验证，验证不过就抛 `PlanValidationError`
并在消息里说清哪一条不满足**。调用方可以选择重试（再次问模型），
但"自动修补"永远不是本模块的行为。

# 为什么拒绝环

任务图是 DAG。带环的图会让 `NextReady` 永远返回空集，
表现为"编排卡住"而非"计划有错"—— 那种失败最难排查。
因此在入口处就拒绝，并在错误信息里指出环上的任务 id。

# 预算校验的口径

`sum(task.budget_tokens) <= session_budget`。这条不是优化，而是
`05` §6.3 / 熔断器的前置条件：若任务图本身就超预算，后面每一次
`Reserve` 都会失败，整场渗透停在第一步。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from string import Template
from typing import Any

from aletheia.execution.roles import AGENT_ROLES, UnknownRoleError, role_spec


class PlanValidationError(ValueError):
    """模型给出的任务图不合法（fail-closed，不做自动修补）。"""


class PlanParseError(PlanValidationError):
    """连 JSON 都没解析出来。"""


#: 每个任务的最小预算。低于此值的任务不可能是"有意义的一步"，
#: 更可能是模型为了凑数生成的空壳。
MIN_TASK_BUDGET = 64

#: 单个任务图的规模上限。防的是"模型生成 500 个任务"把预算
#: 稀释成每步都不够，或让编排层在一次规划里超时。
MAX_TASKS = 40


@dataclass(frozen=True)
class DraftTask:
    """任务图草稿里的一个任务（与 proto `Task` 的**子集**对应）。"""

    task_id: str
    title: str
    objective: str
    role: str  # proto 枚举名，如 "RECON"
    depends_on: tuple[str, ...] = ()
    budget_tokens: int = 1024


@dataclass(frozen=True)
class PlanDraft:
    """一张通过校验的任务图草稿。

    `rationale` 会被写进 `TaskGraph.plan_rationale` —— 可审计
    （`05` §6.1 字段注释："LLM 给出的规划理由（可审计）"）。
    """

    tasks: tuple[DraftTask, ...]
    rationale: str = ""
    #: 校验过程中的说明（例如"模型多给了未知字段，已忽略"）。
    #: 保留下来是为了不让"我们忽略了什么"变成不可见事实。
    notes: tuple[str, ...] = field(default=())

    def total_budget(self) -> int:
        return sum(t.budget_tokens for t in self.tasks)

    def task(self, task_id: str) -> DraftTask:
        for t in self.tasks:
            if t.task_id == task_id:
                return t
        raise KeyError(task_id)


# ---------------------------------------------------------------------------
# JSON 提取
# ---------------------------------------------------------------------------

#: 模型常把 JSON 包在 ```json 围栏里（或 ``` 围栏、或前后带解释）。
#: 这不是"模型的错"，而是普遍行为，因此要容忍 —— 但**只在提取这一层**容忍，
#: 提取出来的内容仍要过严格校验。
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def extract_json(text: str) -> Any:
    """从模型输出中提取 JSON。

    策略（按顺序）：整段就是 JSON → ``` 围栏内的内容 → 第一个 `{` 到
    最后一个 `}` 的子串。

    全部失败则抛 `PlanParseError`，**不返回空计划** ——
    "解析不出来"与"没有任务"是完全不同的两件事，
    混为一谈会让一次失败的规划看起来像一次成功的空规划。
    """
    raw = (text or "").strip()
    if not raw:
        raise PlanParseError("模型返回空内容，无法解析任务图")

    candidates: list[str] = [raw]
    candidates.extend(m.group(1).strip() for m in _FENCE_RE.finditer(raw))
    first, last = raw.find("{"), raw.rfind("}")
    if first != -1 and last > first:
        candidates.append(raw[first : last + 1])

    for cand in candidates:
        if not cand:
            continue
        try:
            return json.loads(cand)
        except json.JSONDecodeError:
            continue
    raise PlanParseError(
        "无法从模型输出中解析出 JSON 任务图（已尝试：整段 / 代码围栏 / 首尾花括号）。"
        f"原始输出前 200 字符：{raw[:200]!r}"
    )


# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise PlanValidationError(msg)


def find_cycle(tasks: tuple[DraftTask, ...]) -> list[str] | None:
    """返回一个环上的任务 id 序列（无环则 None）。

    用三色标记的迭代 DFS —— 不用递归：任务数虽被 `MAX_TASKS` 限制，
    但递归深度受模型输出影响，迭代版本没有这个隐患。
    """
    graph = {t.task_id: list(t.depends_on) for t in tasks}
    # 三色标记（小写以符合项目 lint 规则；它们是局部哨兵值，不是全局常量）。
    white, grey, black = 0, 1, 2
    color = dict.fromkeys(graph, white)

    for root in graph:
        if color[root] != white:
            continue
        stack: list[tuple[str, int]] = [(root, 0)]
        path: list[str] = []
        while stack:
            node, idx = stack.pop()
            if idx == 0:
                if color[node] == grey:
                    continue
                color[node] = grey
                path.append(node)
            deps = graph.get(node, [])
            if idx < len(deps):
                stack.append((node, idx + 1))
                nxt = deps[idx]
                if color.get(nxt) == grey:
                    # 环：从 path 里截出 nxt..node
                    start = path.index(nxt) if nxt in path else 0
                    return [*path[start:], nxt]
                if color.get(nxt, black) == white:
                    stack.append((nxt, 0))
            else:
                color[node] = black
                if path and path[-1] == node:
                    path.pop()
    return None


def validate_plan(
    payload: Any,
    *,
    session_budget: int | None = None,
) -> PlanDraft:
    """校验模型给出的任务图草稿。

    全部判据都是**拒绝式**的（见模块文档）。校验项：

    1. 顶层是对象，含非空 `tasks` 数组；`tasks` 规模 ≤ `MAX_TASKS`
    2. 每个任务：`id`/`title`/`objective`/`role` 非空；`role` 必须是
       `AGENT_ROLES` 里已知的角色（fail-closed，无默认角色）
    3. `id` 全局唯一
    4. `depends_on` 只能引用**存在**的任务 id（悬空依赖会让 `NextReady`
       永久阻塞，且错误现象是"卡住"而非"计划错"）
    5. 无环
    6. 预算：每任务 ≥ `MIN_TASK_BUDGET`；若给了 `session_budget`，
       总和不得超过它

    `notes` 会记录被忽略的未知字段 —— 不静默丢弃任何信息。
    """
    _require(isinstance(payload, dict), f"任务图顶层必须是对象，实际 {type(payload).__name__}")

    raw_tasks = payload.get("tasks")
    _require(isinstance(raw_tasks, list), "任务图缺少 tasks 数组")
    _require(len(raw_tasks) > 0, "任务图没有任何任务 —— 空计划不是有效计划")
    _require(
        len(raw_tasks) <= MAX_TASKS,
        f"任务数 {len(raw_tasks)} 超过上限 {MAX_TASKS}（避免预算被稀释成每步都不够）",
    )

    notes: list[str] = []
    tasks: list[DraftTask] = []
    seen: set[str] = set()

    for idx, raw in enumerate(raw_tasks):
        where = f"tasks[{idx}]"
        _require(isinstance(raw, dict), f"{where} 必须是对象")

        # id：兼容 id / task_id 两种写法（两者都是模型常见输出），
        # 但**只接受这两个名字**，不做模糊匹配。
        tid = raw.get("id") or raw.get("task_id")
        _require(
            isinstance(tid, str) and tid.strip() != "",
            f"{where} 缺少 id（或 task_id）",
        )
        tid = tid.strip()
        _require(tid not in seen, f"任务 id 重复：{tid!r}")
        seen.add(tid)

        title = raw.get("title")
        _require(isinstance(title, str) and title.strip() != "", f"{where}({tid}) 缺少 title")

        objective = raw.get("objective")
        _require(
            isinstance(objective, str) and objective.strip() != "",
            f"{where}({tid}) 缺少 objective（Agent 需要知道这一步要达成什么）",
        )

        role_raw = raw.get("role") or raw.get("required_role")
        _require(isinstance(role_raw, str), f"{where}({tid}) 缺少 role")
        try:
            spec = role_spec(role_raw)
        except UnknownRoleError as exc:
            raise PlanValidationError(f"{where}({tid}) {exc}") from exc

        deps_raw = raw.get("depends_on") or []
        _require(isinstance(deps_raw, list), f"{where}({tid}) 的 depends_on 必须是数组")
        deps: list[str] = []
        for d in deps_raw:
            _require(isinstance(d, str), f"{where}({tid}) 的 depends_on 含非字符串项")
            deps.append(d.strip())
        _require(
            len(set(deps)) == len(deps),
            f"{where}({tid}) 的 depends_on 有重复项：{deps}",
        )
        _require(tid not in deps, f"{where}({tid}) 依赖了自己")

        budget = raw.get("budget_tokens", 1024)
        _require(
            isinstance(budget, int) and not isinstance(budget, bool),
            f"{where}({tid}) 的 budget_tokens 必须是整数",
        )
        _require(
            budget >= MIN_TASK_BUDGET,
            f"{where}({tid}) 的 budget_tokens={budget} 低于下限 {MIN_TASK_BUDGET}",
        )

        # 未知字段：只记录，不失败（向前兼容），但**不静默**。
        known = {
            "id",
            "task_id",
            "title",
            "objective",
            "role",
            "required_role",
            "depends_on",
            "budget_tokens",
        }
        extra = sorted(set(raw) - known)
        if extra:
            notes.append(f"{tid}: 忽略了未知字段 {extra}")

        tasks.append(
            DraftTask(
                task_id=tid,
                title=title.strip(),
                objective=objective.strip(),
                role=spec.proto_name,
                depends_on=tuple(deps),
                budget_tokens=budget,
            )
        )

    # 悬空依赖（必须在环检测**之前**做：否则 find_cycle 可能因
    # 引用了不存在的节点而给出误导性的环）。
    for t in tasks:
        for d in t.depends_on:
            _require(
                d in seen,
                f"任务 {t.task_id!r} 依赖了不存在的任务 {d!r}"
                "（悬空依赖会让 NextReady 永久阻塞，现象是「卡住」而非「计划错」）",
            )

    cycle = find_cycle(tuple(tasks))
    if cycle:
        raise PlanValidationError(f"任务图存在环，无法拓扑排序：{' → '.join(cycle)}")

    total = sum(t.budget_tokens for t in tasks)
    if session_budget is not None:
        _require(
            total <= session_budget,
            f"任务图总预算 {total} 超过会话预算 {session_budget}"
            "（否则第一次 Reserve 就会失败，整场停在第一步）",
        )

    rationale = payload.get("plan_rationale") or payload.get("rationale") or ""
    if not isinstance(rationale, str):
        notes.append("忽略非字符串的 plan_rationale")
        rationale = ""

    return PlanDraft(tasks=tuple(tasks), rationale=rationale.strip(), notes=tuple(notes))


# ---------------------------------------------------------------------------
# 提示词
# ---------------------------------------------------------------------------

#: Planner 的系统提示（英文，因为多数模型对英文指令更稳定；
#: 但**输出内容**不限定语言 —— 任务标题/目标可以是中文）。
#:
#: 关键约束逐条对应 `04` §I6 的设计决策：
#:   · 只产出"任务 + 依赖"，不产出执行步骤（序列求解交给确定性规划器）
#:   · 角色必须来自固定枚举
#:   · 只输出 JSON（可被严格解析）
#:
#: 用 `string.Template` 的 `$name` 占位而不是 `str.format` 的 `{}`：
#: 提示词里含 JSON 示例（大量花括号），`str.format` 会把它们当占位符，
#: 报 `KeyError: '"tasks"'`。（这不是理论问题 —— 首次运行测试即撞上。）
PLANNER_SYSTEM = Template(
    """You are the planning stage of an authorized penetration-testing system.

Produce a TASK GRAPH, not a step-by-step plan.

Hard rules:
- Output ONLY a JSON object. No prose, no markdown fences, no explanations.
- The JSON shape is:
  {"tasks":[{"id":"t1","title":"...","objective":"...","role":"RECON",
             "depends_on":[],"budget_tokens":1024}],
   "plan_rationale":"..."}
- "role" MUST be one of: $roles
- "depends_on" may only reference ids defined in the same graph. The graph must be acyclic.
- Each task's budget_tokens is an integer >= $min_budget.
- Total budget must not exceed $budget.
- Keep the graph small and high-value: at most $max_tasks tasks.
- Do NOT invent targets outside the authorized scope.
- Do NOT include destructive steps (no DoS, no data destruction).
"""
)


def build_planner_prompt(
    objective: str,
    *,
    scope_summary: str = "",
    session_budget: int = 50_000,
    max_tasks: int = MAX_TASKS,
) -> str:
    """组装 Planner 提示词。

    `scope_summary` 只放**已授权的范围描述**（由 Scope Kernel 给出），
    不放原始目标内容 —— 后者属于 T1 的 L1 约束（目标内容永不进入指令位）。
    """
    system = PLANNER_SYSTEM.substitute(
        roles=", ".join(sorted(AGENT_ROLES)),
        min_budget=MIN_TASK_BUDGET,
        budget=session_budget,
        max_tasks=max_tasks,
    )
    parts = [system, "", "OBJECTIVE:", objective.strip()]
    if scope_summary.strip():
        parts += ["", "AUTHORIZED SCOPE (do not exceed):", scope_summary.strip()]
    parts += ["", f"SESSION BUDGET (tokens): {session_budget}"]
    return "\n".join(parts)


@dataclass
class PlannerLLM:
    """用 LLM 生成任务图草稿。

    刻意做成"薄"的一层：组装提示词 → 调 Provider → 解析 → 校验。
    任何一步失败都抛异常，**不返回部分结果** —— 半个任务图比没有更危险。
    """

    #: 满足 `providers.Router` 的 `chat(tier, prompt)` 接口；也可直接传
    #: 一个只有 `chat(prompt, *, model, max_tokens, ...)` 的 Provider。
    router: Any
    #: 档位：规划是重推理任务（`providers.DEFAULT_TIERS` 的 "planning"）。
    tier: str = "planning"

    def propose(
        self,
        objective: str,
        *,
        scope_summary: str = "",
        session_budget: int = 50_000,
        scan: Any = None,
    ) -> PlanDraft:
        """向模型要一张任务图，并校验它。"""
        prompt = build_planner_prompt(
            objective, scope_summary=scope_summary, session_budget=session_budget
        )
        result = self.router.chat(self.tier, prompt, scan=scan)
        content = getattr(result, "content", None)
        if not isinstance(content, str):
            raise PlanParseError(f"Provider 返回了意外类型：{type(result).__name__}")
        payload = extract_json(content)
        return validate_plan(payload, session_budget=session_budget)
