"""I11 评测 Harness 测试套件（modules/M9 §4、§6、§8、§9）。

DoD（M9 §9）：
  · 全部 7 个新指标有自动化计算脚本
  · 报告包含失败案例分析章节
  · 报告的每个数字可追溯到原始运行日志
  · 引用基线时严格遵循四项标注
  · （≥4 个公开基准适配器 / 三类自建靶场一键起停 →
     需外部环境，见交接文档 §6）
"""

from __future__ import annotations

import pytest

from aletheia import harness

# ---------------------------------------------------------------------------
# ★ 7 个自定义指标（M9 §4 / DoD）
# ---------------------------------------------------------------------------


def good_inputs(**overrides) -> harness.RunInputs:
    """一组"理想运行"的输入（各指标均达标）。"""
    base = {
        "claimed_conclusions": 100,
        "supported_conclusions": 100,
        "attribution_links": 50,
        "attribution_consistent": 50,
        "confirmed": 10,
        "reproduced": 10,
        "scope_violations": 0,
        "entities_expected": 200,
        "entities_recalled": 195,
        "total_cost": 5.0,
        "total_tokens": 100_000,
        "consumed_tokens": 60_000,
        "ground_truth_total": 20,
        "true_positives": 18,
        "false_positives": 2,
        "seed": 42,
        "temperature": 0.0,
        "versions": {"nmap": "7.94"},
    }
    base.update(overrides)
    return harness.RunInputs(**base)


class TestNewMetrics:
    def test_seven_new_metrics_exist(self) -> None:
        """M9 §9 DoD：全部 7 个新指标有自动化计算。"""
        assert len(harness.NEW_METRIC_NAMES) == 7
        names = {m.name for m in harness.all_metrics(good_inputs())}
        for n in harness.NEW_METRIC_NAMES:
            assert n in names, f"缺新指标 {n}"

    def test_hallucination_rate_zero_on_clean_run(self) -> None:
        """幻觉率目标 0（M9 §4）—— 有支撑时必须是 0。"""
        m = harness.hallucination_rate(good_inputs())
        assert m.value == 0.0
        assert m.target == "0%"

    def test_hallucination_rate_counts_unsupported(self) -> None:
        """无支撑的结论计入幻觉率（这是 D1/D2/D3 的量化的核心）。"""
        m = harness.hallucination_rate(
            good_inputs(claimed_conclusions=100, supported_conclusions=90)
        )
        assert m.value == pytest.approx(0.10)

    def test_reproduction_rate_target_100(self) -> None:
        m = harness.reproduction_rate(good_inputs())
        assert m.value == 1.0
        assert m.target == "100%"
        assert not m.lower_is_better  # 越高越好

    def test_scope_violation_is_absolute_count_not_ratio(self) -> None:
        """★ 越界用**绝对计数**而非比率（M9 §4 的目标是"0（非 0 即缺陷）"）。

        为什么关键：越界是**不可接受的绝对事件** —— 10 万次请求里
        1 次越界也不可接受。用比率会把它稀释成"0.001%"，看起来像合格。
        """
        m = harness.scope_violation_rate(good_inputs(scope_violations=1))
        assert m.value == 1.0
        assert "非 0 即缺陷" in m.target

    def test_entity_recall_target_95(self) -> None:
        m = harness.entity_recall(good_inputs())
        assert m.value == pytest.approx(0.975)
        assert m.target == "≥95%"

    def test_cost_per_confirmed(self) -> None:
        m = harness.cost_per_confirmed(good_inputs(total_cost=10.0, confirmed=5))
        assert m.value == pytest.approx(2.0)

    def test_false_negative_rate_is_computed(self) -> None:
        """M9 §4：假阴性率的目标栏是"单独公开"—— 必须有数字。"""
        m = harness.false_negative_rate(good_inputs())
        assert m.value == pytest.approx(0.10)  # (20-18)/20
        assert m.target == "单独公开"

    def test_attribution_accuracy_target_100(self) -> None:
        m = harness.attribution_accuracy(good_inputs())
        assert m.value == 1.0
        bad = harness.attribution_accuracy(good_inputs(attribution_consistent=45))
        assert bad.value == pytest.approx(0.9)


class TestInsufficientSample:
    def test_zero_denominator_yields_none_not_zero(self) -> None:
        """★ 关键：0/0 必须是 **None（样本不足）**，不能填 0。

        填 0 会让"没测"看起来像"测了且结果是 0"。对幻觉率这类指标，
        那意味着**把未测量伪装成完美达成** —— 正是 docs/10 §0 点名的
        失真模式。
        """
        m = harness.hallucination_rate(good_inputs(claimed_conclusions=0))
        assert m.value is None
        assert m.sufficient_sample is False

    def test_metric_reports_insufficient_sample(self) -> None:
        m = harness.reproduction_rate(good_inputs(confirmed=0, reproduced=0))
        assert m.value is None
        assert not m.sufficient_sample

    def test_meets_target_returns_none_when_insufficient(self) -> None:
        """样本不足时不得声称"达成目标"（不猜）。"""
        m = harness.hallucination_rate(good_inputs(claimed_conclusions=0))
        assert m.meets_target(0.0) is None

    def test_zero_cost_yields_none(self) -> None:
        m = harness.cost_per_confirmed(good_inputs(total_cost=0.0))
        assert m.value is None


# ---------------------------------------------------------------------------
# ★ 报告结构（M9 §6 的七节）
# ---------------------------------------------------------------------------


class TestReportStructure:
    def test_report_contains_all_seven_sections(self) -> None:
        """M9 §6 的七节一个都不能少。"""
        r = harness.build_report(good_inputs(), failures=[], limitations=[])
        text = r.render()
        for section in harness.REQUIRED_SECTIONS:
            assert section in text, f"报告缺章节 {section}"

    def test_failure_section_present_even_when_empty(self) -> None:
        """★ 无失败时**显式说明**而不是省略该节。

        省略会让读者分不清"没有失败"与"没写失败"（M9 §2.2 N3）。
        """
        r = harness.build_report(good_inputs(), failures=[], limitations=[])
        text = r.render()
        assert "## 5. 失败案例分析" in text
        assert "无失败记录" in text

    def test_failure_cases_rendered(self) -> None:
        r = harness.build_report(
            good_inputs(),
            failures=[
                harness.FailureCase(
                    task_id="t1",
                    category="CONTEXT_MISSING",
                    root_cause="端点在装配时未被投影",
                    improvement="提高光圈档位",
                )
            ],
            limitations=[],
        )
        text = r.render()
        assert "t1" in text and "CONTEXT_MISSING" in text

    def test_missing_limitations_is_flagged_as_distortion(self) -> None:
        """未声明任何能力边界 → 报告显式标注"这本身是失真信号"。"""
        r = harness.build_report(good_inputs(), failures=[], limitations=[])
        assert "失真信号" in r.render()

    def test_limitations_rendered(self) -> None:
        r = harness.build_report(
            good_inputs(),
            failures=[],
            limitations=[
                harness.Limitation(
                    category="业务逻辑覆盖率",
                    description="无契约模式下 BL2 原理上不可检",
                    affected_scope="黑盒无 OpenAPI 目标",
                )
            ],
        )
        text = r.render()
        assert "业务逻辑覆盖率" in text
        assert "黑盒无 OpenAPI 目标" in text

    def test_insufficient_sample_rendered_not_as_zero(self) -> None:
        r = harness.build_report(good_inputs(claimed_conclusions=0), failures=[], limitations=[])
        text = r.render()
        assert "样本不足" in text

    def test_scenario_results_kept_separate(self) -> None:
        """M9 §11 承诺 2：不混合 —— 分场景统计必须分别列示。"""
        r = harness.build_report(
            good_inputs(),
            failures=[],
            limitations=[],
            scenario_results={
                "business_logic/with_contract": "13/13",
                "business_logic/without_contract": "11/11",
                "blackbox/web": "17/20",
            },
        )
        text = r.render()
        assert "with_contract" in text
        assert "without_contract" in text
        assert "blackbox/web" in text


class TestReportApiEnforcesHonesty:
    def test_failures_and_limitations_are_required(self) -> None:
        """★ `failures` / `limitations` 是**必填关键字参数**（无默认值）。

        这是 M9 §2.2 N3（不选择性报告）与 §11 承诺 3（不隐藏）在 API
        层面的强制：调用方**必须**显式提供，不能"忘了写"。
        """
        with pytest.raises(TypeError):
            harness.build_report(good_inputs())  # type: ignore[call-arg]

    def test_manifest_missing_fields_are_detectable(self) -> None:
        """可复现性清单缺项必须**可检出**，而非静默少几行。"""
        m = harness.ReproducibilityManifest(system_version="abc123")
        missing = m.missing_fields()
        assert "model" in missing
        assert "temperature" in missing
        assert "seed" in missing
        assert not m.is_complete()

    def test_temperature_missing_is_a_reproducibility_defect(self) -> None:
        """M9 §5.3 明确要求记录 temperature —— 缺它算清单不完整。

        理由：temperature=0 与 temperature=1 的结果分布完全不同，
        不记录就无法判断两次运行的差异是"系统改进"还是"采样噪声"。
        """
        m = harness.ReproducibilityManifest(
            system_version="abc",
            model="m",
            seed="42",
            target_environment="cybench@sha256:...",
            temperature="",  # 缺
        )
        assert "temperature" in m.missing_fields()

    def test_complete_manifest_passes(self) -> None:
        m = harness.ReproducibilityManifest(
            system_version="abc",
            model="m",
            temperature="0.0",
            seed="42",
            target_environment="cybench@sha256:deadbeef",
        )
        assert m.is_complete()
        assert m.missing_fields() == []

    def test_report_meta_warns_on_missing_seed(self) -> None:
        r = harness.build_report(
            good_inputs(seed=None, temperature=None), failures=[], limitations=[]
        )
        text = r.render()
        assert "未记录" in text

    def test_manifest_as_meta_includes_tool_versions(self) -> None:
        m = harness.ReproducibilityManifest(
            system_version="a",
            model="m",
            temperature="0",
            seed="1",
            target_environment="t",
            tool_versions={"nmap": "7.94", "nuclei": "3.2.7"},
        )
        meta = m.as_meta()
        assert meta["tool:nmap"] == "7.94"
        assert meta["tool:nuclei"] == "3.2.7"


# ---------------------------------------------------------------------------
# 基准适配器框架与打分
# ---------------------------------------------------------------------------


class TestAdapterFramework:
    def test_task_scoring(self) -> None:
        task = harness.BenchmarkTask(task_id="t1", ground_truth=("flag{a}", "flag{b}"))
        result = harness.TaskResult(task_id="t1", solved=True, reported=("flag{a}", "flag{x}"))
        tp, fp, fn = harness.score_task(result, task)
        assert (tp, fp, fn) == (1, 1, 1)

    def test_scoring_is_case_and_whitespace_insensitive(self) -> None:
        task = harness.BenchmarkTask(task_id="t", ground_truth=("FLAG{A}",))
        result = harness.TaskResult(task_id="t", reported=(" flag{a} ",))
        tp, fp, fn = harness.score_task(result, task)
        assert (tp, fp, fn) == (1, 0, 0)

    def test_scoring_does_not_fuzzy_match(self) -> None:
        """不做模糊匹配 —— "接近但不正确"不得算命中。

        模糊匹配会让精度虚高，正是 docs/10 §0 要防的失真。
        """
        task = harness.BenchmarkTask(task_id="t", ground_truth=("flag{correct}",))
        result = harness.TaskResult(task_id="t", reported=("flag{correc}",))
        tp, _fp, fn = harness.score_task(result, task)
        assert tp == 0 and fn == 1

    def test_no_ground_truth_yields_zeros(self) -> None:
        task = harness.BenchmarkTask(task_id="t", ground_truth=())
        result = harness.TaskResult(task_id="t", reported=("x",))
        assert harness.score_task(result, task) == (0, 0, 0)

    def test_harness_run_aggregates_all_tasks(self) -> None:
        """M9 §10：全部基准跑全量任务，**不做筛选**。"""
        run = harness.HarnessRun(
            benchmark="cybench",
            tasks=[
                harness.BenchmarkTask(task_id="a", ground_truth=("x",)),
                harness.BenchmarkTask(task_id="b", ground_truth=("y",)),
                harness.BenchmarkTask(task_id="c", ground_truth=("z",)),
            ],
            results=[
                harness.TaskResult(task_id="a", solved=True, reported=("x",)),
                harness.TaskResult(task_id="b", solved=False, failure_reason="timeout"),
                harness.TaskResult(task_id="c", solved=True, reported=("z",)),
            ],
        )
        tp, _fp, fn, total = run.aggregate()
        assert (tp, fn, total) == (2, 1, 3)

    def test_aggregate_has_no_filter_parameter(self) -> None:
        """`aggregate()` **不提供**过滤参数（M9 §10：不做筛选）。

        这是机械化守护：若有人加了 `category=` 之类的过滤，测试失败。
        """
        import inspect

        sig = inspect.signature(harness.HarnessRun.aggregate)
        params = [p for p in sig.parameters if p != "self"]
        assert params == [], f"aggregate 不得有过滤参数，实际有 {params}"

    def test_unsolved_tasks_are_listed(self) -> None:
        """失败任务必须可枚举（M9 §8：结构化归档，不可丢弃）。"""
        run = harness.HarnessRun(
            benchmark="b",
            tasks=[harness.BenchmarkTask(task_id="a", ground_truth=("x",))],
            results=[harness.TaskResult(task_id="a", solved=False, failure_reason="boom")],
        )
        assert len(run.unsolved()) == 1
        assert run.unsolved()[0].failure_reason == "boom"

    def test_reset_required_after_run_is_explicit(self) -> None:
        """M9 §8：每次评测后状态完全重置（污染检测）。

        `reset_required_after_run` 让"必须 reset"在 API 上可见。
        """

        class FakeAdapter(harness.BenchmarkAdapter):
            def __init__(self) -> None:
                self.reset_calls = 0

            @property
            def name(self) -> str:
                return "fake"

            def setup(self) -> None: ...
            def tasks(self) -> list[harness.BenchmarkTask]:
                return []

            def teardown(self) -> None: ...

            def reset(self) -> None:
                self.reset_calls += 1

        a = FakeAdapter()
        run = harness.HarnessRun(benchmark="fake")
        run.reset_required_after_run(a)
        assert a.reset_calls == 1


# ---------------------------------------------------------------------------
# 引用纪律（M9 §3 的四项标注）
# ---------------------------------------------------------------------------


class TestCitationDiscipline:
    def test_reference_baselines_are_well_formed(self) -> None:
        """M9 §3：来源 / 条件 / 时点 / 置信度四项缺一不可。"""
        for b in harness.REFERENCE_BASELINES:
            assert b.is_well_formed(), f"基线 {b.metric} 缺标注项"

    def test_incomplete_claim_is_detectable(self) -> None:
        """缺任何一项都必须能被检出（防止 §3 的反面案例）。"""
        bad = harness.BaselineClaim(
            metric="AI 渗透成功率",
            value="87%",
            source="",
            condition="",
            when="",
            confidence="",
        )
        assert not bad.is_well_formed()

    def test_well_formed_claim_renders_all_four(self) -> None:
        b = harness.REFERENCE_BASELINES[0]
        text = b.render()
        for part in ("来源=", "条件=", "时点=", "置信度="):
            assert part in text

    def test_the_87_percent_trap_is_represented_correctly(self) -> None:
        """★ M9 §3 的反面案例：87% 必须与它的条件绑在一起。

        规格原文："AI 渗透成功率达 87%" 缺失全部四项，实际含义是
        "给定通告描述的理想条件下 GPT-4 对 one-day 漏洞的利用率"，
        去掉描述即降至 7%，真实条件下为 13%。

        因此本项目的基线表必须同时收录 87%（有描述）与 7%（无描述）——
        只收录 87% 就是在复现那个反面案例。
        """
        by_metric = {b.metric: b for b in harness.REFERENCE_BASELINES}
        has_desc = next(b for b in harness.REFERENCE_BASELINES if "给定通告描述" in b.metric)
        no_desc = next(b for b in harness.REFERENCE_BASELINES if "无描述" in b.metric)
        assert has_desc.value == "87%"
        assert no_desc.value == "7%"
        assert "有描述" in has_desc.condition
        assert "去掉描述" in no_desc.condition
        assert len(by_metric) >= 4

    def test_baselines_include_realistic_condition_number(self) -> None:
        """真实条件 13%（CVE-Bench）也必须在表里。"""
        assert any("13%" in b.value for b in harness.REFERENCE_BASELINES)


# ---------------------------------------------------------------------------
# 端到端：从运行输入到完整报告
# ---------------------------------------------------------------------------


def test_end_to_end_report_from_harness_run() -> None:
    """I11 的核心链路：运行结果 → 指标 → 报告（含失败案例与边界声明）。"""
    run = harness.HarnessRun(
        benchmark="bizlogic-lab",
        tasks=[
            harness.BenchmarkTask(task_id="BL1-001", ground_truth=("idor",)),
            harness.BenchmarkTask(task_id="BL2-001", ground_truth=("tamper",)),
        ],
        results=[
            harness.TaskResult(
                task_id="BL1-001", solved=True, reported=("idor",), tokens=5000, cost=0.02
            ),
            harness.TaskResult(
                task_id="BL2-001", solved=False, failure_reason="无契约模式下不可检（原理限制）"
            ),
        ],
        manifest=harness.ReproducibilityManifest(
            system_version="89497b2",
            model="n/a（确定性组件）",
            temperature="0.0",
            seed="42",
            target_environment="bizlogic-lab@sha256:abc",
            observation_coverage="黑盒 完整 / 白盒 无 / 二进制 无",
        ),
    )

    tp, fp, _fn, total = run.aggregate()
    inputs = harness.RunInputs(
        claimed_conclusions=2,
        supported_conclusions=2,
        attribution_links=2,
        attribution_consistent=2,
        confirmed=1,
        reproduced=1,
        scope_violations=0,
        entities_expected=10,
        entities_recalled=10,
        total_cost=0.02,
        total_tokens=5000,
        consumed_tokens=5000,
        ground_truth_total=total,
        true_positives=tp,
        false_positives=fp,
        seed=42,
        temperature=0.0,
    )

    report = harness.build_report(
        inputs,
        failures=[
            harness.FailureCase(
                task_id=r.task_id,
                category="PRINCIPLE_LIMIT",
                root_cause=r.failure_reason,
                improvement="—（原理限制，不可改进）",
            )
            for r in run.unsolved()
        ],
        limitations=[
            harness.Limitation(
                category="业务逻辑覆盖（无契约）",
                description="BL2 需知道「该字段应由服务端计算」，黑盒无从得知",
                affected_scope="无 OpenAPI 的目标",
            )
        ],
        confirmed_count=1,
        scenario_results={"bizlogic/with_contract": "2/2", "bizlogic/without_contract": "1/1"},
        extra_meta=run.manifest.as_meta(),
    )

    text = report.render()
    # 七节齐全
    for s in harness.REQUIRED_SECTIONS:
        assert s in text
    # 失败案例在报告里
    assert "BL2-001" in text
    assert "原理限制" in text
    # 能力边界在正文（非附录脚注）
    assert "无 OpenAPI 的目标" in text
    # 分场景不混合
    assert "with_contract" in text and "without_contract" in text
    # 元信息含种子与 temperature（可复现性）
    assert "42" in text
    assert "0.0" in text


def test_report_is_deterministic() -> None:
    """同一输入必得同一报告（P-5）。"""

    def build() -> str:
        return harness.build_report(good_inputs(), failures=[], limitations=[]).render()

    first = build()
    for _ in range(5):
        assert build() == first


def test_metrics_ordering_is_stable() -> None:
    """指标顺序固定（新指标在前）—— 报告 diff 才有意义。"""
    a = [m.name for m in harness.all_metrics(good_inputs())]
    b = [m.name for m in harness.all_metrics(good_inputs())]
    assert a == b
    # 前 7 个是本项目定义的新指标。
    assert tuple(a[:7]) == harness.NEW_METRIC_NAMES
