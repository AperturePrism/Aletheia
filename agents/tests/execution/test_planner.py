"""Planner 与角色规格的测试。

# 测试重点：模型的输出是**不可信输入**

本文件几乎全部用例都在验证"错误的东西会被拒绝"，而不是"正确的东西能通过"。
理由与 T1（提示词注入）同源：LLM 输出与目标响应属于同一类不可信输入。

若解析器倾向于"尽量修正"（自动补 id、自动去环、自动裁剪预算），
就会出现两种坏结果（见 `planner.py` 模块文档）：
  · 静默改写了用户的计划，审计时分不清"模型说的"与"我们改的"；
  · 把解析失败伪装成成功 —— `docs/10` §0 说的"用绿灯替换有效性"。

因此这里逐条锁定：**不合法 → 抛异常**。
"""

from __future__ import annotations

import pytest

from aletheia.execution import (
    AGENT_ROLES,
    MAX_TASKS,
    MIN_TASK_BUDGET,
    PlanParseError,
    PlanValidationError,
    UnknownRoleError,
    extract_json,
    find_cycle,
    is_read_only,
    role_spec,
    validate_plan,
)
from aletheia.execution.planner import DraftTask, build_planner_prompt

# ---------------------------------------------------------------------------
# 角色表
# ---------------------------------------------------------------------------


def test_all_six_pool_roles_exist() -> None:
    """`04` §I6 点名的五个角色 + post_exploit 必须都在。"""
    for name in ("RECON", "SCANNER", "FUZZER", "EXPLOITER", "POST_EXPLOIT", "REPORTER"):
        assert name in AGENT_ROLES, f"缺少角色 {name}"


def test_acting_roles_have_tools() -> None:
    """会产生副作用的角色必须至少有一个可用工具。

    反例（空工具集的动作角色）会让 Agent 派发后立刻无事可做 ——
    表现为"任务完成但没有任何证据"，属于虚假完成。
    """
    for name, spec in AGENT_ROLES.items():
        if spec.may_act and name != "REPORTER":
            assert spec.tools, f"{name} 标记为会动作但没有工具"


def test_reporter_is_read_only_and_toolless() -> None:
    """报告者只消费账本，不调工具（否则可自造"证据"）。"""
    assert is_read_only("REPORTER")
    assert role_spec("REPORTER").tools == frozenset()


def test_unknown_role_is_rejected() -> None:
    """★ fail-closed：未知角色没有默认值。"""
    with pytest.raises(UnknownRoleError) as exc:
        role_spec("SUPER_HACKER")
    assert "未知 Agent 角色" in str(exc.value)


def test_role_lookup_is_case_insensitive_but_strict() -> None:
    assert role_spec("recon").proto_name == "RECON"
    with pytest.raises(UnknownRoleError):
        role_spec("")


def test_every_role_has_a_valid_tier() -> None:
    from aletheia.providers.provider import DEFAULT_TIERS

    for name, spec in AGENT_ROLES.items():
        assert spec.tier in DEFAULT_TIERS, f"{name} 的档位 {spec.tier} 不在 DEFAULT_TIERS"


# ---------------------------------------------------------------------------
# JSON 提取
# ---------------------------------------------------------------------------


def test_extract_plain_json() -> None:
    assert extract_json('{"tasks": []}') == {"tasks": []}


def test_extract_from_markdown_fence() -> None:
    """模型常把 JSON 包在 ```json 围栏里 —— 这是普遍行为，提取层要容忍。"""
    text = 'Sure, here is the plan:\n```json\n{"tasks": [], "plan_rationale": "x"}\n```\nDone.'
    assert extract_json(text)["plan_rationale"] == "x"


def test_extract_from_bare_fence() -> None:
    assert extract_json('```\n{"tasks": []}\n```') == {"tasks": []}


def test_extract_from_surrounded_prose() -> None:
    assert extract_json('The graph: {"tasks": []} — hope this helps') == {"tasks": []}


@pytest.mark.parametrize("text", ["", "   ", "no json at all", "{broken"])
def test_extract_failure_is_explicit(text: str) -> None:
    """★ 解析失败必须抛错，**不得**返回空计划。

    "解析不出来"与"没有任务"是完全不同的两件事；混为一谈会让
    一次失败的规划看起来像一次成功的空规划。
    """
    with pytest.raises(PlanParseError):
        extract_json(text)


# ---------------------------------------------------------------------------
# 任务图校验 —— 正向
# ---------------------------------------------------------------------------


def _task(
    tid: str, *, role: str = "RECON", deps: list[str] | None = None, budget: int = 1024
) -> dict:
    return {
        "id": tid,
        "title": f"任务 {tid}",
        "objective": f"完成 {tid}",
        "role": role,
        "depends_on": deps or [],
        "budget_tokens": budget,
    }


def test_valid_graph_passes() -> None:
    draft = validate_plan({"tasks": [_task("t1"), _task("t2", deps=["t1"])]})
    assert len(draft.tasks) == 2
    assert draft.total_budget() == 2048
    assert draft.task("t2").depends_on == ("t1",)


def test_task_id_alias_is_accepted() -> None:
    """模型也常写 `task_id` 而不是 `id` —— 两者都接受，但不做模糊匹配。"""
    raw = _task("t1")
    raw["task_id"] = raw.pop("id")
    assert validate_plan({"tasks": [raw]}).tasks[0].task_id == "t1"


def test_unknown_fields_are_noted_not_fatal() -> None:
    """向前兼容：未知字段忽略但**记录**（不静默丢弃信息）。"""
    raw = _task("t1")
    raw["risk"] = "low"
    draft = validate_plan({"tasks": [raw]})
    assert any("risk" in n for n in draft.notes)


def test_rationale_is_preserved_for_audit() -> None:
    draft = validate_plan({"tasks": [_task("t1")], "plan_rationale": "先侦察再扫描"})
    assert draft.rationale == "先侦察再扫描"


# ---------------------------------------------------------------------------
# 任务图校验 —— 反向（每一条都是 fail-closed）
# ---------------------------------------------------------------------------


def test_empty_task_list_is_rejected() -> None:
    with pytest.raises(PlanValidationError, match="没有任何任务"):
        validate_plan({"tasks": []})


def test_non_object_payload_is_rejected() -> None:
    with pytest.raises(PlanValidationError, match="顶层必须是对象"):
        validate_plan([_task("t1")])


def test_too_many_tasks_rejected() -> None:
    with pytest.raises(PlanValidationError, match="超过上限"):
        validate_plan({"tasks": [_task(f"t{i}") for i in range(MAX_TASKS + 1)]})


def test_duplicate_task_id_rejected() -> None:
    with pytest.raises(PlanValidationError, match="id 重复"):
        validate_plan({"tasks": [_task("t1"), _task("t1")]})


def test_missing_required_fields_rejected() -> None:
    for field in ("title", "objective"):
        raw = _task("t1")
        raw.pop(field)
        with pytest.raises(PlanValidationError):
            validate_plan({"tasks": [raw]})


def test_unknown_role_rejected_at_validation() -> None:
    with pytest.raises(PlanValidationError, match="未知 Agent 角色"):
        validate_plan({"tasks": [_task("t1", role="GODMODE")]})


def test_dangling_dependency_rejected() -> None:
    """悬空依赖会让 NextReady 永久阻塞，现象是"卡住"而非"计划错"。"""
    with pytest.raises(PlanValidationError, match="不存在"):
        validate_plan({"tasks": [_task("t1", deps=["ghost"])]})


def test_self_dependency_rejected() -> None:
    with pytest.raises(PlanValidationError, match="依赖了自己"):
        validate_plan({"tasks": [_task("t1", deps=["t1"])]})


def test_two_cycle_rejected() -> None:
    with pytest.raises(PlanValidationError, match="存在环"):
        validate_plan({"tasks": [_task("t1", deps=["t2"]), _task("t2", deps=["t1"])]})


def test_three_cycle_rejected_and_names_the_cycle() -> None:
    with pytest.raises(PlanValidationError) as exc:
        validate_plan(
            {
                "tasks": [
                    _task("a", deps=["c"]),
                    _task("b", deps=["a"]),
                    _task("c", deps=["b"]),
                ]
            }
        )
    msg = str(exc.value)
    assert "存在环" in msg
    # 错误信息要指出环上的任务，否则用户只能猜。
    assert all(x in msg for x in ("a", "b", "c"))


def test_budget_below_minimum_rejected() -> None:
    with pytest.raises(PlanValidationError, match="低于下限"):
        validate_plan({"tasks": [_task("t1", budget=MIN_TASK_BUDGET - 1)]})


def test_total_budget_over_session_rejected() -> None:
    """任务图本身就超预算 → 第一次 Reserve 就失败，整场停在第一步。"""
    with pytest.raises(PlanValidationError, match="超过会话预算"):
        validate_plan(
            {"tasks": [_task("t1", budget=1000), _task("t2", budget=1000)]},
            session_budget=1500,
        )


def test_non_integer_budget_rejected() -> None:
    for bad in ("1024", 1024.0, True):
        raw = _task("t1")
        raw["budget_tokens"] = bad
        with pytest.raises(PlanValidationError):
            validate_plan({"tasks": [raw]})


def test_duplicate_dependency_rejected() -> None:
    with pytest.raises(PlanValidationError, match="重复"):
        validate_plan({"tasks": [_task("t1"), _task("t2", deps=["t1", "t1"])]})


# ---------------------------------------------------------------------------
# 环检测本身
# ---------------------------------------------------------------------------


def test_find_cycle_returns_none_for_dag() -> None:
    tasks = (
        DraftTask("a", "A", "a", "RECON"),
        DraftTask("b", "B", "b", "SCANNER", ("a",)),
        DraftTask("c", "C", "c", "REPORTER", ("a", "b")),
    )
    assert find_cycle(tasks) is None


def test_find_cycle_detects_deep_cycle() -> None:
    tasks = (
        DraftTask("a", "A", "a", "RECON", ("d",)),
        DraftTask("b", "B", "b", "SCANNER", ("a",)),
        DraftTask("c", "C", "c", "FUZZER", ("b",)),
        DraftTask("d", "D", "d", "REPORTER", ("c",)),
    )
    cycle = find_cycle(tasks)
    assert cycle is not None
    # 首尾相同（闭环表达），且覆盖四个节点。
    assert cycle[0] == cycle[-1]
    assert set(cycle) == {"a", "b", "c", "d"}


# ---------------------------------------------------------------------------
# 提示词
# ---------------------------------------------------------------------------


def test_prompt_states_the_role_enum_and_budget() -> None:
    p = build_planner_prompt("扫一遍 target", session_budget=1234)
    assert "RECON" in p and "REPORTER" in p
    assert "1234" in p
    assert "JSON" in p


def test_prompt_forbids_destructive_steps() -> None:
    """`04` §I6 与 `08` 的范围原则：不得要求破坏性动作。"""
    p = build_planner_prompt("x")
    assert "destructive" in p.lower()
