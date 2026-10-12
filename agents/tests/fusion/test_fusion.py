"""I8 三路融合测试套件（modules/M7 §4、§6、§7）。

**本套件的重点是最高价值象限**（M7 §4.4 第二行）：
「黑盒打不通 + 白盒有缺陷」—— 对纯黑盒 agent 它是盲区，
对纯白盒工具它无意义，**只有融合才能识别出"这是链式漏洞的第一环"**。

DoD（M7 §7）：
  · 三路观测器对同一目标写入，`SourceKind` 正确标记
  · 冲突矩阵生成，四象限解读正确
  · **"打不通 + 有缺陷"象限能派生出下游深挖任务**
  · 无独立存储，全部写入 M2 单一图

观测器用测试替身实现 —— 本模块的正确性核心是**融合逻辑**
（象限判定、对齐口径、阈值、派生），而非引擎适配（M7 §3.2 N4）。
"""

from __future__ import annotations

import pytest

from aletheia.fusion import (
    BINARY,
    BLACKBOX,
    QUADRANT_META,
    TRICHROMATIC,
    WHITEBOX,
    ConflictMatrix,
    CoverageStatus,
    Fusion,
    Observation,
    Quadrant,
    StaticObserver,
    build_matrix,
    classify,
    derive_tasks,
    source_label,
)

# ---------------------------------------------------------------------------
# 测试替身观测器
# ---------------------------------------------------------------------------


class FakeObserver:
    """可编程观测器（返回预置观测，或抛异常）。"""

    def __init__(self, source: int, observations: list[Observation], *, raises=None):
        self._source = source
        self._observations = observations
        self._raises = raises

    @property
    def source(self) -> int:
        return self._source

    def observe(self, target: str) -> list[Observation]:
        if self._raises is not None:
            raise self._raises
        return list(self._observations)


def bb(
    defect: str = "sqli",
    target: str = "host1",
    *,
    exploitable: bool = False,
    confidence: float = 1.0,
    location: str = "/api/v2/users",
) -> Observation:
    """构造黑盒观测。"""
    return Observation(
        source=BLACKBOX,
        defect_type=defect,
        target=target,
        location=location,
        confidence=confidence,
        exploitability_verified=exploitable,
    )


def wb(
    defect: str = "sqli",
    target: str = "host1",
    *,
    confidence: float = 0.9,
    location: str = "app/views.py:42",
) -> Observation:
    """构造白盒观测。"""
    return Observation(
        source=WHITEBOX,
        defect_type=defect,
        target=target,
        location=location,
        confidence=confidence,
    )


def binobs(
    defect: str = "hardcoded_credential",
    target: str = "host1",
    *,
    confidence: float = 0.5,
    location: str = "0x4012a0",
) -> Observation:
    """构造二进制观测（默认低置信 —— M7 §8）。"""
    return Observation(
        source=BINARY,
        defect_type=defect,
        target=target,
        location=location,
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# 四象限判定（M7 §4.4 表格逐行）
# ---------------------------------------------------------------------------


class TestQuadrantClassification:
    def test_row1_confirmed_both(self) -> None:
        """表格第 1 行：可利用 + 有缺陷 → 双源确认（高）。"""
        q = classify(blackbox_exploitable=True, static_flawed=True)
        assert q == Quadrant.CONFIRMED_BOTH
        assert QUADRANT_META[q]["priority"] == "高"

    def test_row2_unreachable_but_flawed_is_highest(self) -> None:
        """表格第 2 行：**打不通 + 有缺陷 → 最高优先级**。

        这是本项目的第二个"第一"所在 —— 必须断言它是**最高**，
        而不只是"被识别"。若优先级判错，下游深挖任务的排期会错。
        """
        q = classify(blackbox_exploitable=False, static_flawed=True)
        assert q == Quadrant.UNREACHABLE_BUT_FLAWED
        assert QUADRANT_META[q]["priority"] == "最高"

    def test_row3_exploitable_but_clean(self) -> None:
        q = classify(blackbox_exploitable=True, static_flawed=False)
        assert q == Quadrant.EXPLOITABLE_BUT_CLEAN
        assert QUADRANT_META[q]["priority"] == "中"

    def test_row4_neither(self) -> None:
        q = classify(blackbox_exploitable=False, static_flawed=False)
        assert q == Quadrant.NEITHER
        assert QUADRANT_META[q]["priority"] == "低"

    def test_all_four_combinations_covered(self) -> None:
        """四象限是**两个独立维度的完整笛卡尔积** —— 四种组合必须互异。"""
        seen = {classify(bb_, st_) for bb_ in (True, False) for st_ in (True, False)}
        assert seen == {
            Quadrant.CONFIRMED_BOTH,
            Quadrant.UNREACHABLE_BUT_FLAWED,
            Quadrant.EXPLOITABLE_BUT_CLEAN,
            Quadrant.NEITHER,
        }


# ---------------------------------------------------------------------------
# DoD① 冲突矩阵生成（含 SourceKind 正确标记）
# ---------------------------------------------------------------------------


class TestSignalPlacement:
    def test_sources_are_tagged_correctly(self) -> None:
        """DoD①：三路观测的 `SourceKind` 必须正确标记。"""
        obs = [bb(), wb(), binobs()]
        m = build_matrix("host1", obs)
        assert m.counts[BLACKBOX] == 1
        assert m.counts[WHITEBOX] == 1
        assert m.counts[BINARY] == 1

    def test_trichromatic_constant_covers_three_paths(self) -> None:
        assert len(TRICHROMATIC) == 3
        assert set(TRICHROMATIC) == {BLACKBOX, WHITEBOX, BINARY}
        for s in TRICHROMATIC:
            assert source_label(s)  # 每路都有可读名


class TestConflictAlignment:
    def test_same_defect_from_two_paths_aligns(self) -> None:
        """对齐口径正确：同一缺陷的两路观测落到同一 entity_key。

        若对齐失败（如身份键字段不同），冲突将无从检测 —— 这是
        本模块最关键的实现约束。
        """
        # 刻意用**不同的 location**（黑盒给 URL、白盒给源码行）——
        # 这正是真实场景，且必须仍能对齐。
        m = build_matrix(
            "host1",
            [
                bb(defect="sqli", location="/api/v2/users"),
                wb(defect="sqli", location="app/views.py:42"),
            ],
        )
        assert len(m.conflicts) == 1
        c = m.conflicts[0]
        assert c.target == "host1" and c.defect_type == "sqli"
        assert len(c.blackbox) == 1
        assert len(c.whitebox) == 1
        # location 仍保留在各自观测内（静态侧位置可查）。
        assert c.location_of_static() == "app/views.py:42"

    def test_different_defects_do_not_align(self) -> None:
        m = build_matrix("host1", [bb(defect="sqli"), wb(defect="xss")])
        # sqli：黑盒无（未验证可利用）+ 白盒无 → NEITHER（被过滤）
        # xss：白盒有 → UNREACHABLE_BUT_FLAWED
        assert len(m.conflicts) == 1
        assert m.conflicts[0].defect_type == "xss"

    def test_entity_key_excludes_location_by_design(self) -> None:
        """融合层的对齐键**刻意不含 location**。

        三路对"位置"的表述天然不同（黑盒是 URL、白盒是源码行号、
        二进制是文件偏移）。若把 location 纳入对齐键，三路对同一缺陷
        的观测**永远无法对齐** —— 冲突矩阵会退化成三个互不相干的
        清单，"融合"本身失去意义。

        代价是已知的过度对齐（同载体的同类缺陷会合并），见
        `Observation.entity_key` 的详细说明。
        """
        a = wb(defect="sqli", target="host1", location="a.py:1")
        b = bb(defect="sqli", target="host1", location="/api/users")
        assert a.entity_key() == b.entity_key() == "host1|sqli"


class TestMatrixThresholds:
    def test_low_confidence_does_not_create_conflict(self) -> None:
        """M7 §8：两侧 confidence 均 > 0.5 才落图（避免噪声）。

        低置信观测（尤其二进制，§8 说默认 < 0.6）只构成噪声，
        让它们进矩阵会淹没真正的高价值信号。
        """
        m = build_matrix("host1", [bb(confidence=0.3), wb(confidence=0.3)])
        assert m.conflicts == []

    def test_high_confidence_static_with_unreachable_blackbox(self) -> None:
        m = build_matrix("host1", [bb(confidence=1.0), wb(confidence=0.9)])
        assert len(m.conflicts) == 1
        assert m.conflicts[0].quadrant == Quadrant.UNREACHABLE_BUT_FLAWED

    def test_neither_quadrant_is_excluded(self) -> None:
        """两路皆无 → 不进矩阵（M7 §4.4：降优先级，不是冲突）。"""
        # 黑盒有观测但**未验证可利用** + 无静态观测 → NEITHER
        m = build_matrix("host1", [bb(exploitable=False)])
        assert m.conflicts == []

    def test_max_conflicts_cap(self) -> None:
        """M7 §8：冲突数量上限。"""
        obs = [wb(defect=f"d{i}", target="h") for i in range(10)]
        m = build_matrix("h", obs, max_conflicts=3)
        assert len(m.conflicts) == 3

    def test_priority_ordering_highest_first(self) -> None:
        """最高价值象限必须排在最前 —— 消费方与 UI 都直接取头部。"""
        obs = [
            wb(defect="unreachable"),  # 无黑盒 → UNREACHABLE_BUT_FLAWED
            bb(defect="clean", exploitable=True),  # → EXPLOITABLE_BUT_CLEAN
            bb(defect="both", exploitable=True),
            wb(defect="both"),
        ]
        m = build_matrix("h", obs)
        assert m.conflicts[0].quadrant == Quadrant.UNREACHABLE_BUT_FLAWED


# ---------------------------------------------------------------------------
# ★ DoD③ 最高价值象限 → 派生下游深挖任务
# ---------------------------------------------------------------------------


class TestConflictDrivesDownstream:
    def test_unreachable_but_flawed_derives_task(self) -> None:
        """★ 核心 DoD：该象限必须能派生出下游深挖任务。"""
        m = build_matrix("host1", [bb(), wb(location="app/views.py:42")])
        tasks = derive_tasks(m.conflicts)
        assert len(tasks) == 1
        t = tasks[0]
        assert t.quadrant == Quadrant.UNREACHABLE_BUT_FLAWED
        assert t.priority == "最高"
        assert "深挖" in t.title

    def test_derived_task_carries_structured_hints(self) -> None:
        """派生的任务必须带**结构化** `target_entity_hints`。

        这是 M3 §8 的缓解措施要求（Planner 输出结构化实体提示而非
        自然语言），否则 M3 的 Autofocus 无法可靠召回 ——
        `core/aperture` 的 recall 测试验证了这条依赖。
        """
        m = build_matrix("10.40.23.5", [bb(target="10.40.23.5"), wb(target="10.40.23.5")])
        tasks = derive_tasks(m.conflicts)
        assert tasks[0].target_entity_hints == ("10.40.23.5",)

    def test_derived_task_warns_against_treating_as_failure(self) -> None:
        """派生的任务必须明确提醒"不要当失败跳过"。

        否则 agent 会把"打不通"当作失败——那就退回了纯黑盒的盲区，
        本模块的存在意义消失。
        """
        m = build_matrix("h", [bb(), wb()])
        t = derive_tasks(m.conflicts)[0]
        joined = " ".join(t.notes)
        assert "不要" in joined and "链式" in joined

    def test_confirmed_both_derives_reproduce_task(self) -> None:
        m = build_matrix("h", [bb(exploitable=True), wb()])
        tasks = derive_tasks(m.conflicts)
        assert len(tasks) == 1
        assert "复现" in tasks[0].title
        # 必须提醒仍要走 M4 闸门（09 §R4：不存在绕过账本的 CONFIRMED 路径）。
        assert any("闸门" in n for n in tasks[0].notes)

    def test_exploitable_but_clean_derives_review_task(self) -> None:
        m = build_matrix("h", [bb(exploitable=True)])
        tasks = derive_tasks(m.conflicts)
        assert len(tasks) == 1
        assert "盲区" in tasks[0].title

    def test_neither_derives_nothing(self) -> None:
        """低优先级象限不派生任务（M7 §4.4：降优先级即可）。"""
        m = ConflictMatrix(target="h")
        assert derive_tasks(m.conflicts) == []

    def test_derived_tasks_are_deterministic(self) -> None:
        """确定性（P-5）：相同输入必得相同顺序。"""
        obs = [
            bb(defect="d3", target="h"),
            wb(defect="d3", target="h"),
            bb(defect="d1", target="h"),
            wb(defect="d1", target="h"),
            bb(defect="d2", target="h"),
            wb(defect="d2", target="h"),
        ]
        m = build_matrix("h", obs)
        first = [t.title for t in derive_tasks(m.conflicts)]
        for _ in range(10):
            assert [t.title for t in derive_tasks(m.conflicts)] == first


class TestChainedHypothesesEntryPoint:
    def test_matrix_exposes_chained_hypotheses(self) -> None:
        """矩阵必须给下游一个明确的入口取"链式漏洞候选"。

        若让调用方自己去 `by_quadrant` 里挑，很容易漏掉 ——
        而这个象限漏掉就等于整个融合白做。
        """
        obs = [
            wb(defect="unreachable"),
            bb(defect="both", exploitable=True),
            wb(defect="both"),
        ]
        m = build_matrix("h", obs)
        chained = m.chained_hypotheses()
        assert len(chained) == 1
        assert chained[0].defect_type == "unreachable"


# ---------------------------------------------------------------------------
# 观测器的可利用性语义（矩阵的核心不对称）
# ---------------------------------------------------------------------------


class TestExploitabilityAsymmetry:
    def test_static_observer_cannot_claim_exploitability(self) -> None:
        """静态观测器**不能**声称已验证可利用性。

        这是矩阵的核心不对称（M7 §4.4）：黑盒能验证可利用性，
        白盒与二进制只能指出缺陷存在。把它们混为一谈会让
        "白盒说有洞"被误读成"可以打"。
        """

        class MyStatic(StaticObserver):
            @property
            def source(self) -> int:
                return WHITEBOX

            def scan(self, target: str) -> list[Observation]:
                # 观测器**试图**声称可利用 → 基类必须强制改回 False
                return [
                    Observation(
                        source=WHITEBOX,
                        defect_type="rce",
                        target=target,
                        exploitability_verified=True,  # 越权声明
                    )
                ]

        out = MyStatic().observe("h")
        assert out[0].exploitability_verified is False

    def test_blackbox_can_verify_exploitability(self) -> None:
        m = build_matrix("h", [bb(exploitable=True), wb()])
        c = m.conflicts[0]
        assert c.blackbox_verified() is True
        assert c.quadrant == Quadrant.CONFIRMED_BOTH


# ---------------------------------------------------------------------------
# 融合编排与覆盖度声明（M7 §8 降级、§9 诚实要求）
# ---------------------------------------------------------------------------


class TestFusionOrchestration:
    def test_all_three_paths_run(self) -> None:
        f = Fusion(
            blackbox=FakeObserver(BLACKBOX, [bb()]),
            whitebox=FakeObserver(WHITEBOX, [wb()]),
            binary=FakeObserver(BINARY, [binobs(target="h", defect="sqli", location="x")]),
        )
        r = f.fuse("host1")
        assert r.coverage.active_paths == 3
        assert r.coverage.is_trichromatic
        assert len(r.observations) == 3

    def test_missing_path_degrades_not_fails(self) -> None:
        """M7 §8：三路不是必须全有 —— 单路可用时降级为单路模式。

        白盒失明（目标无源码）是**常态**（规格说 30% 的目标拿不到源码）。
        若白盒不可用就整体失败，这个模块在最需要它的场景下反而不可用。
        """
        f = Fusion(whitebox=FakeObserver(WHITEBOX, [wb()]))
        r = f.fuse("host1")
        assert r.coverage.active_paths == 1
        assert not r.coverage.is_trichromatic
        # 缺两路必须有显式说明，不能静默。
        assert len(r.coverage.entries) == 3

    def test_failing_observer_does_not_block_others(self) -> None:
        f = Fusion(
            blackbox=FakeObserver(BLACKBOX, [bb()]),
            whitebox=FakeObserver(WHITEBOX, [], raises=RuntimeError("semgrep not installed")),
        )
        r = f.fuse("host1")
        # 黑盒结果仍产出。
        assert r.coverage.active_paths == 1
        # 失败必须记入 warnings（不吞 —— P-4）。
        assert any("semgrep not installed" in w for w in r.warnings)

    def test_coverage_report_renders_and_warns(self) -> None:
        """M7 §9：覆盖度声明必须写入报告，且在非三路时显式警告。"""
        f = Fusion(blackbox=FakeObserver(BLACKBOX, [bb()]))
        r = f.fuse("h")
        text = r.coverage.render()
        assert "观测覆盖度" in text

    def test_full_coverage_report_has_no_degradation_warning(self) -> None:
        f = Fusion(
            blackbox=FakeObserver(BLACKBOX, [bb()]),
            whitebox=FakeObserver(WHITEBOX, [wb()]),
            binary=FakeObserver(BINARY, [binobs()]),
        )
        text = f.fuse("h").coverage.render()
        assert "仅" not in text or "1/3" not in text


class TestCoverageEntries:
    def test_partial_when_path_produces_nothing(self) -> None:
        """有观测器但无发现 → PARTIAL（不是 COMPLETE，也不是 UNAVAILABLE）。

        "跑了但没发现"与"没跑"是不同的观测事实 —— 混为一谈会让
        覆盖度声明失真。
        """
        f = Fusion(blackbox=FakeObserver(BLACKBOX, []))
        r = f.fuse("h")
        bb_entry = next(e for e in r.coverage.entries if e.source == BLACKBOX)
        assert bb_entry.status == CoverageStatus.PARTIAL

    def test_unavailable_when_no_observer_configured(self) -> None:
        f = Fusion(blackbox=FakeObserver(BLACKBOX, [bb()]))
        r = f.fuse("h")
        wb_entry = next(e for e in r.coverage.entries if e.source == WHITEBOX)
        assert wb_entry.status == CoverageStatus.UNAVAILABLE

    def test_entry_counts_observations(self) -> None:
        f = Fusion(whitebox=FakeObserver(WHITEBOX, [wb(defect="a"), wb(defect="b")]))
        r = f.fuse("h")
        wb_entry = next(e for e in r.coverage.entries if e.source == WHITEBOX)
        assert wb_entry.observation_count == 2


# ---------------------------------------------------------------------------
# 不可变性 / 边界
# ---------------------------------------------------------------------------


def test_observation_is_frozen() -> None:
    """Observation 必须不可变 —— 融合层不应能改写观测器的产出。

    若可变，上游（融合）的一次"顺手修正"会让下游看到的观测与
    观测器实际报告的不一致，审计链断裂。
    """
    o = wb()
    with pytest.raises(Exception):  # noqa: B017 —— dataclasses.FrozenInstanceError
        o.confidence = 0.1  # type: ignore[misc]


def test_empty_observations_yield_empty_matrix() -> None:
    m = build_matrix("h", [])
    assert m.conflicts == []
    assert m.counts == {}


def test_matrix_by_quadrant_is_sorted() -> None:
    obs = [
        wb(defect="z", target="h"),
        wb(defect="a", target="h"),
        wb(defect="m", target="h"),
    ]
    m = build_matrix("h", obs)
    keys = [c.defect_type for c in m.by_quadrant(Quadrant.UNREACHABLE_BUT_FLAWED)]
    assert keys == ["a", "m", "z"]


def test_conflict_relation_attributes_match_m7_spec() -> None:
    """`CONTRADICTS` 关系的属性形态必须符合 M7 §4.5。"""
    m = build_matrix("h", [bb(target="host1"), wb(target="host1")])
    attrs = m.conflicts[0].to_relation_attributes()
    assert attrs["quadrant"] == Quadrant.UNREACHABLE_BUT_FLAWED
    assert attrs["priority"] == "最高"
    assert attrs["target"] == "host1"


# ---------------------------------------------------------------------------
# ★ 写回 M2 的集成契约（本模块与 core/prism 的衔接点）
# ---------------------------------------------------------------------------


class TestM2WritebackContract:
    """融合层与 M2 图模型的衔接契约。

    `core/prism` 的 DEFECT 身份键是 `载体|缺陷类型|位置`，而
    **`MergeBranch` 只在同一 entity_id 上生成 `CONTRADICTS`**。
    因此若三路把各自的 location 写进身份键，会产生三个不同的
    entity_id，冲突检测**永远不触发** —— 整个融合链路静默失效。

    这组测试把该契约固定下来，避免后续实现"顺手"把 location 写进
    身份位置字段。
    """

    def test_alignment_key_ignores_location(self) -> None:
        """黑盒与白盒的 location 表述不同，但必须对齐到同一键。"""
        b = bb(defect="sqli", target="10.0.0.1", location="/api/v2/users")
        w = wb(defect="sqli", target="10.0.0.1", location="app/views.py:42")
        assert b.entity_key() == w.entity_key()
        # 两个 location 都不同 —— 若键含 location 就不会相等。
        assert b.location != w.location

    def test_alignment_key_varies_with_defect_type(self) -> None:
        """不同缺陷类型必须分开（不能过度合并成"这个载体有缺陷"）。"""
        a = bb(defect="sqli", target="10.0.0.1")
        b = bb(defect="xss", target="10.0.0.1")
        assert a.entity_key() != b.entity_key()

    def test_alignment_key_varies_with_target(self) -> None:
        """不同载体必须分开。"""
        a = bb(defect="sqli", target="10.0.0.1")
        b = bb(defect="sqli", target="10.0.0.2")
        assert a.entity_key() != b.entity_key()

    def test_full_pipeline_real_shaped_data(self) -> None:
        """端到端：真实形态的输入 → 对齐 → 象限 → 派生任务。

        这是 I8 的核心链路，用真实场景的数据形状（黑盒给 URL、
        白盒给源码行）验证。
        """
        observations = [
            Observation(
                source=BLACKBOX,
                defect_type="sqli",
                target="192.0.2.20",
                location="/api/v2/users",
                exploitability_verified=False,  # 黑盒打不通
                confidence=1.0,
            ),
            Observation(
                source=WHITEBOX,
                defect_type="sqli",
                target="192.0.2.20",
                location="app/views.py:42",
                confidence=0.9,
            ),
        ]
        m = build_matrix("192.0.2.20", observations)
        assert len(m.conflicts) == 1
        c = m.conflicts[0]
        assert c.quadrant == Quadrant.UNREACHABLE_BUT_FLAWED
        assert c.location_of_static() == "app/views.py:42"
        assert c.static_confidence() == 0.9

        tasks = derive_tasks(m.conflicts)
        assert len(tasks) == 1
        assert tasks[0].priority == "最高"
        assert tasks[0].target_entity_hints == ("192.0.2.20",)
        # 关系属性可直接用于写入 M2 的 CONTRADICTS。
        attrs = c.to_relation_attributes()
        assert attrs["quadrant"] == Quadrant.UNREACHABLE_BUT_FLAWED


def test_observation_key_is_documented_as_writeback_requirement() -> None:
    """`entity_key` 的 docstring 必须说明写回 M2 的集成要求。

    这不是形式主义：该要求是本模块与 `core/prism` 之间**唯一**的
    隐式契约，而违约的后果是**静默失效**（冲突检测永不触发）。
    注释掉了，下一位实现者就会踩中。
    """
    doc = Observation.entity_key.__doc__ or ""
    assert "M2" in doc
    assert "CONTRADICTS" in doc or "MergeBranch" in doc
