"""真实模型的 Planner 冒烟（`llm_live` 标记，默认跳过）。

# 为什么这条测试必须存在

2026-11-02 的项目检查结论里最重的一条是：

> 生产代码中无人调用 Provider ... Agent 池不存在，没有任何
> "规划 → 派发 Agent → 调用工具 → 回写证据"的自主循环。

单元测试用假 Router 证明了**结构**正确（校验、循环、失败路径），
但证明不了"真的能跟一个真实模型对上话"。假 Router 永远不会因为
`max_tokens` 太小、真的太慢、或者返回了带围栏的 JSON 而失败 ——
而这些恰恰是真实接入时最先撞到的。

因此这条测试跑一次真实调用，断言：

1. 真实端点可达、鉴权通过；
2. 模型输出能被 `extract_json` 提取（容忍围栏）；
3. 通过 `validate_plan` 的全部结构校验（角色/依赖/预算/无环）；
4. 账本记录了 token 消耗（I12 的成本维度不能只是"以为记了"）。

# 默认跳过的理由

CI 不烧真钱（`pyproject.toml` 的 marker 说明）。本地跑：

    ALETHEIA_LLM_KEY=... \\
    ALETHEIA_LLM_BASE=https://ark.cn-beijing.volces.com/api/plan/v3 \\
    ALETHEIA_LLM_MODEL=deepseek-v4.1-flash \\
    pytest agents/tests/execution/test_live_planner.py -m llm_live -v

★ 密钥**只经环境变量注入**，不写入任何文件（`08`/`07` §T8 的同一原则：
真实敏感值不得落到仓库里）。
"""

from __future__ import annotations

import os

import pytest

from aletheia.execution import PlannerLLM
from aletheia.providers.provider import CostLedger, OpenAICompatProvider, Router

pytestmark = pytest.mark.llm_live


def _live_router(model: str, ledger: CostLedger | None = None) -> Router:
    """按环境变量组装一个指向真实渠道的 Router。

    所有档位都映射到同一个模型 —— 本测试只验证"能对话"，
    分级路由的差异由 `tests/i12/` 的基准测试负责（那需要更多调用）。
    """
    base = os.environ["ALETHEIA_LLM_BASE"]
    key = os.environ["ALETHEIA_LLM_KEY"]
    provider = OpenAICompatProvider(base_url=base, api_key=key, ledger=ledger)
    return Router(
        provider=provider,
        tiers={
            "planning": model,
            "analysis": model,
            "parse_assist": model,
            "rank": model,
            "default": model,
        },
        # 不对模型做推理控制：规划是重推理任务，保留推理是质量要求。
        tier_extras={},
    )


def _require_env() -> tuple[str, str, str]:
    key = os.environ.get("ALETHEIA_LLM_KEY")
    if not key:
        pytest.skip("ALETHEIA_LLM_KEY 未设置（真实渠道冒烟默认跳过，避免烧钱）")
    base = os.environ.get("ALETHEIA_LLM_BASE")
    if not base:
        pytest.skip("ALETHEIA_LLM_BASE 未设置")
    model = os.environ.get("ALETHEIA_LLM_MODEL", "deepseek-v4.1-flash")
    return key, base, model


def test_live_provider_roundtrip() -> None:
    """最小冒烟：一次真实 chat，确认端点/鉴权/协议都对。"""
    _require_env()
    ledger = CostLedger()
    router = _live_router(os.environ.get("ALETHEIA_LLM_MODEL", "deepseek-v4.1-flash"), ledger)

    result = router.chat("parse_assist", "Reply with the single word: pong")

    assert result.content.strip(), "真实模型返回了空内容"
    assert result.usage.total_tokens > 0, "用量应为正数（否则账本无法归因）"
    assert ledger.total_tokens() == result.usage.total_tokens


def test_live_planner_produces_a_valid_graph() -> None:
    """★ 核心断言：真实模型 → 可解析 → 通过全部结构校验。"""
    _require_env()
    model = os.environ.get("ALETHEIA_LLM_MODEL", "deepseek-v4.1-flash")
    ledger = CostLedger()
    planner = PlannerLLM(router=_live_router(model, ledger))

    draft = planner.propose(
        "对一个已授权的测试站点（例如本地靶场 127.0.0.1 上的 Juice Shop）"
        "做一次最小化的信息收集与漏洞验证，产出可复现的证据。",
        scope_summary="仅限 127.0.0.1，仅限本地靶场，不得发起破坏性请求。",
        session_budget=20_000,
    )

    assert draft.tasks, "真实模型没有产出任何任务"
    assert 1 <= len(draft.tasks) <= 20, f"任务数异常：{len(draft.tasks)}"
    assert draft.total_budget() <= 20_000

    # 结构不变量（即使模型换了也必须成立）。
    ids = [t.task_id for t in draft.tasks]
    assert len(ids) == len(set(ids)), "任务 id 重复"
    for t in draft.tasks:
        assert t.role in {"RECON", "SCANNER", "FUZZER", "EXPLOITER", "POST_EXPLOIT", "REPORTER"}
        for d in t.depends_on:
            assert d in ids, f"{t.task_id} 依赖了不存在的 {d}"

    # 真实调用必须记账（I12 的成本维度）。
    assert ledger.total_tokens() > 0, "真实调用未记账 —— I12 的成本数据会缺失"
    print(
        f"\n[live] 模型={model} 任务数={len(draft.tasks)} "
        f"总预算={draft.total_budget()} 实耗 tokens={ledger.total_tokens()}"
    )
    for t in draft.tasks:
        print(f"  - {t.task_id} [{t.role}] {t.title} deps={list(t.depends_on)}")
