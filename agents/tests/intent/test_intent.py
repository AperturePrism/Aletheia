"""I10 业务逻辑意图建模测试套件（modules/M8 §4、§6、§7）。

DoD（M8 §7）：
  · 自建靶场含 ≥10 类业务逻辑缺陷，覆盖 BL1–BL6
  · 靶场双模式（有/无 OpenAPI）均可运行
  · **给出行业首个可复现的业务逻辑检出数字**
  · 六类缺陷每类至少检出 1 个
  · 越权判定基于**副作用观测**而非状态码
  · 漏报率单独统计并公开
  · 诚实标注：无契约黑盒覆盖率单独给出，不合并汇报
"""

from __future__ import annotations

import pytest

from aletheia import intent
from aletheia.intent import (
    ALL_VIOLATION_TYPES,
    ContractSource,
    CrossAccessProbe,
    Endpoint,
    EndpointContract,
    Field,
    LabMode,
    PermissionEntry,
    PermissionMatrix,
    ProbeResult,
    TrafficRecord,
    ViolationType,
    build_default_lab,
    build_report,
    evaluate_cross_access,
    evaluate_detection,
    evaluate_flow_bypass,
    evaluate_privilege_chain,
    evaluate_quota_bypass,
    evaluate_race,
    evaluate_tampering,
    field_str,
    from_openapi,
    from_traffic,
    illegal_transitions,
    infer_state_machine,
    judge,
    lab_covers_all_types,
)

# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------


def probe(
    *,
    key: str = "GET /a",
    vtype: str = ViolationType.BL1_IDOR,
    status: int = 200,
    data_returned: bool = True,
    exec_id: str = "ex_1",
    session: str = "sess_a",
    excerpt: str = '{"order_id": 42}',
) -> ProbeResult:
    return ProbeResult(
        endpoint_key=key,
        violation_type=vtype,
        status_code=status,
        data_returned=data_returned,
        data_excerpt=excerpt,
        exec_id=exec_id,
        session_id=session,
    )


# ---------------------------------------------------------------------------
# ★ 强证据门禁（M8 §4.3 末句 / §6）
# ---------------------------------------------------------------------------


class TestStrongEvidenceGate:
    def test_status_code_alone_is_not_enough(self) -> None:
        """★ 核心约束：仅凭 200 状态码**不得**判定（M8 §4.3 末句）。

        原文："必须实际取回 B 的资源内容（DATA_RETURNED 副作用观测），
        仅返回 200 状态码不足以判定（可能是空壳响应）"。

        这是 M4 的 G-3 在业务逻辑场景的应用 —— 避免"只看状态码就判定
        成功"这类 D1 幻觉式成功。
        """
        r = probe(status=200, data_returned=False)
        assert judge(r, rationale="looks exploitable") is None

    def test_data_returned_yields_violation_with_evidence(self) -> None:
        r = probe(status=200, data_returned=True, exec_id="ex_evidence")
        v = judge(r, rationale="cross-session read")
        assert v is not None
        assert v.has_strong_evidence
        assert v.strong_evidence_exec_id == "ex_evidence"

    def test_evidence_required_even_for_4xx_status(self) -> None:
        """状态码反常时同样以副作用为准 —— 状态码不是判据。"""
        r = probe(status=500, data_returned=True, exec_id="ex_x")
        v = judge(r, rationale="data leaked despite error status")
        assert v is not None and v.has_strong_evidence

    def test_violation_without_evidence_is_not_counted(self) -> None:
        """无强证据的违背不得计入检出统计（M8 §6 的机械化）。"""
        lab = build_default_lab()
        lab_defect = lab.defects[0]
        no_evidence = ProbeResult(
            endpoint_key=lab_defect.endpoint_key,
            violation_type=lab_defect.violation_type,
            status_code=200,
            data_returned=False,  # 关键
            exec_id="",
        )
        v = judge(no_evidence, rationale="x")
        assert v is None
        stats = evaluate_detection(lab, LabMode.WITH_CONTRACT, [])
        assert stats.detected == []
        assert stats.detection_rate == 0.0


# ---------------------------------------------------------------------------
# BL1 会话隔离（M8 §4.3 的访问矩阵）
# ---------------------------------------------------------------------------


class TestBL1CrossAccess:
    def test_cross_access_with_data_is_violation(self) -> None:
        """交叉访问 + 取回数据 → 越权（M8 §4.3 的矩阵第 2 格）。"""
        ep = Endpoint(path="/api/v2/orders/{id}", method="GET")
        p = CrossAccessProbe(
            session_id="sess_a",
            resource_owner_session="sess_b",
            is_cross_access=True,
            result=probe(data_returned=True, exec_id="ex_idor"),
        )
        v = evaluate_cross_access(p, ep)
        assert v is not None
        assert v.violation_type == ViolationType.BL1_IDOR
        assert v.has_strong_evidence

    def test_same_session_access_is_not_violation(self) -> None:
        """访问自身资源是正常行为，不是违背。"""
        ep = Endpoint(path="/api/v2/orders/{id}", method="GET")
        p = CrossAccessProbe(
            session_id="sess_a",
            resource_owner_session="sess_a",
            is_cross_access=False,
            result=probe(data_returned=True),
        )
        assert evaluate_cross_access(p, ep) is None

    def test_cross_access_without_data_is_not_violation(self) -> None:
        """交叉访问但未取回数据 → 不构成违背（只有 200 不够）。"""
        ep = Endpoint(path="/api/v2/orders/{id}", method="GET")
        p = CrossAccessProbe(
            session_id="sess_a",
            resource_owner_session="sess_b",
            is_cross_access=True,
            result=probe(data_returned=False),
        )
        assert evaluate_cross_access(p, ep) is None

    def test_expectation_follows_matrix(self) -> None:
        """访问矩阵的期望值必须与 M8 §4.3 一致。"""
        cross = CrossAccessProbe("a", "b", True, probe())
        same = CrossAccessProbe("a", "a", False, probe())
        assert cross.expectation == "DENY"
        assert same.expectation == "ALLOW"


# ---------------------------------------------------------------------------
# BL2 价格篡改
# ---------------------------------------------------------------------------


class TestBL2Tampering:
    def test_server_recomputing_is_not_violation(self) -> None:
        """服务端改写了客户端提交的值 → 它在服务端计算，**不是**违背。

        这条很关键：若把"客户端提交了 price"直接判为违背，
        每个正常接受该字段但会重算的端点都会被误报。
        """
        ep = Endpoint(
            path="/checkout",
            method="POST",
            server_computed=Field(("price",)),
        )
        v = evaluate_tampering(
            probe(vtype=ViolationType.BL2_TAMPERING),
            ep,
            client_value="0.01",
            server_value="99.99",  # 服务端改写了
        )
        assert v is None

    def test_server_accepting_client_value_is_violation(self) -> None:
        ep = Endpoint(
            path="/checkout",
            method="POST",
            server_computed=Field(("price",)),
        )
        v = evaluate_tampering(
            probe(vtype=ViolationType.BL2_TAMPERING, data_returned=True, exec_id="ex_b2"),
            ep,
            client_value="0.01",
            server_value="0.01",  # 原样接受
        )
        assert v is not None
        assert v.violation_type == ViolationType.BL2_TAMPERING

    def test_no_server_computed_fields_means_no_judgement(self) -> None:
        """契约未声明服务端计算字段 → 无判据，不判（不猜）。"""
        ep = Endpoint(path="/x", method="POST")
        v = evaluate_tampering(
            probe(vtype=ViolationType.BL2_TAMPERING),
            ep,
            client_value="1",
            server_value="1",
        )
        assert v is None


# ---------------------------------------------------------------------------
# BL3 流程绕过
# ---------------------------------------------------------------------------


class TestBL3FlowBypass:
    def test_illegal_transitions_are_enumerated(self) -> None:
        """M8 §4.4：枚举"未观测到但在语义上可能"的转移。"""
        c = EndpointContract()
        c.transitions = {("POST /pay", "POST /confirm"), ("POST /cart", "POST /pay")}
        c.terminal_states = {"POST /confirm"}
        pairs = illegal_transitions(c)
        assert ("POST /pay", "POST /confirm") in pairs

    def test_bypass_with_data_is_violation(self) -> None:
        c = EndpointContract()
        ep = Endpoint(path="/confirm", method="POST")
        v = evaluate_flow_bypass(
            probe(vtype=ViolationType.BL3_FLOW_BYPASS, data_returned=True, exec_id="ex_b3"),
            ep,
            skipped_state="POST /pay",
            contract=c,
        )
        assert v is not None and v.violation_type == ViolationType.BL3_FLOW_BYPASS

    def test_no_skipped_state_means_no_judgement(self) -> None:
        c = EndpointContract()
        ep = Endpoint(path="/confirm", method="POST")
        v = evaluate_flow_bypass(
            probe(vtype=ViolationType.BL3_FLOW_BYPASS),
            ep,
            skipped_state="",
            contract=c,
        )
        assert v is None

    def test_state_machine_inference_marks_terminal(self) -> None:
        c = EndpointContract()
        c.transitions = {("a", "b"), ("b", "c")}
        infer_state_machine(c)
        assert c.terminal_states == {"c"}

    def test_state_machine_without_traffic_warns(self) -> None:
        """无流量观测 → 明确告警（BL3 检测不可用），不静默。"""
        c = EndpointContract()
        infer_state_machine(c)
        assert any("BL3" in w for w in c.warnings)


# ---------------------------------------------------------------------------
# BL4 配额绕过
# ---------------------------------------------------------------------------


class TestBL4QuotaBypass:
    def test_count_reset_is_violation(self) -> None:
        ep = Endpoint(path="/trial/reset", method="POST", is_counter=Field(True))
        v = evaluate_quota_bypass(
            probe(vtype=ViolationType.BL4_QUOTA_BYPASS, data_returned=True, exec_id="ex_b4"),
            ep,
            observed_counts=[5, 4, 3],  # 回退
        )
        assert v is not None and v.violation_type == ViolationType.BL4_QUOTA_BYPASS

    def test_monotonic_counts_are_not_violation(self) -> None:
        ep = Endpoint(path="/export", method="GET", is_counter=Field(True))
        v = evaluate_quota_bypass(
            probe(vtype=ViolationType.BL4_QUOTA_BYPASS),
            ep,
            observed_counts=[1, 2, 3],
        )
        assert v is None

    def test_insufficient_samples_means_no_judgement(self) -> None:
        """少于 2 个样本无法判断单调性 → 不猜。"""
        ep = Endpoint(path="/x", method="POST", is_counter=Field(True))
        assert (
            evaluate_quota_bypass(
                probe(vtype=ViolationType.BL4_QUOTA_BYPASS), ep, observed_counts=[1]
            )
            is None
        )
        assert (
            evaluate_quota_bypass(
                probe(vtype=ViolationType.BL4_QUOTA_BYPASS), ep, observed_counts=[]
            )
            is None
        )


# ---------------------------------------------------------------------------
# BL5 权限提升
# ---------------------------------------------------------------------------


class TestBL5PrivilegeChain:
    def test_denied_subject_succeeding_is_violation(self) -> None:
        m = PermissionMatrix(
            entries=[
                PermissionEntry("admin", "users", "promote", allowed=True),
                PermissionEntry("user", "users", "promote", allowed=False),
            ]
        )
        v = evaluate_privilege_chain(
            probe(vtype=ViolationType.BL5_PRIVILEGE_CHAIN, data_returned=True, exec_id="ex_b5"),
            m,
            subject="user",
            resource="users",
            action="promote",
        )
        assert v is not None and v.violation_type == ViolationType.BL5_PRIVILEGE_CHAIN
        assert "低权限" in v.rationale

    def test_allowed_subject_is_not_violation(self) -> None:
        m = PermissionMatrix(
            entries=[
                PermissionEntry("admin", "users", "promote", allowed=True),
            ]
        )
        assert (
            evaluate_privilege_chain(
                probe(vtype=ViolationType.BL5_PRIVILEGE_CHAIN),
                m,
                subject="admin",
                resource="users",
                action="promote",
            )
            is None
        )

    def test_unregistered_combination_means_no_judgement(self) -> None:
        """矩阵未登记 → 无判据，不判（"未登记"不是低置信）。"""
        m = PermissionMatrix()
        assert (
            evaluate_privilege_chain(
                probe(vtype=ViolationType.BL5_PRIVILEGE_CHAIN),
                m,
                subject="x",
                resource="y",
                action="z",
            )
            is None
        )

    def test_low_privilege_inferred_from_matrix_not_role_name(self) -> None:
        """低权限主体从矩阵**反推**，不靠角色名前缀猜。

        角色名在不同系统里差异极大（`user` / `member` / `staff` /
        `oper` 都可能），靠名字猜会误判。
        """
        m = PermissionMatrix(
            entries=[
                PermissionEntry("weird_name_1", "res", "act", allowed=False),
                PermissionEntry("weird_name_2", "res", "act", allowed=True),
            ]
        )
        assert m.low_privilege_subjects() == {"weird_name_1"}


# ---------------------------------------------------------------------------
# BL6 竞态
# ---------------------------------------------------------------------------


class TestBL6Race:
    def test_excess_successes_is_violation(self) -> None:
        ep = Endpoint(path="/withdraw", method="POST", concurrency_sensitive=Field(True))
        v = evaluate_race(
            probe(vtype=ViolationType.BL6_RACE, data_returned=True, exec_id="ex_b6"),
            ep,
            concurrent_requests=10,
            successes=3,
            expected_max_successes=1,
        )
        assert v is not None and v.violation_type == ViolationType.BL6_RACE

    def test_within_expected_is_not_violation(self) -> None:
        ep = Endpoint(path="/w", method="POST", concurrency_sensitive=Field(True))
        assert (
            evaluate_race(
                probe(vtype=ViolationType.BL6_RACE),
                ep,
                concurrent_requests=10,
                successes=1,
                expected_max_successes=1,
            )
            is None
        )

    def test_single_request_means_no_judgement(self) -> None:
        """并发数 ≤1 时不是竞态测试 → 不判。"""
        ep = Endpoint(path="/w", method="POST")
        assert (
            evaluate_race(
                probe(vtype=ViolationType.BL6_RACE),
                ep,
                concurrent_requests=1,
                successes=5,
            )
            is None
        )

    def test_details_retained_for_significance_testing(self) -> None:
        """M8 §8：竞态有概率性，需统计显著性 —— 原始数字必须保留。"""
        ep = Endpoint(path="/w", method="POST", concurrency_sensitive=Field(True))
        v = evaluate_race(
            probe(vtype=ViolationType.BL6_RACE, data_returned=True, exec_id="e"),
            ep,
            concurrent_requests=20,
            successes=7,
            expected_max_successes=1,
        )
        assert v.details["concurrent_requests"] == "20"
        assert v.details["successes"] == "7"


# ---------------------------------------------------------------------------
# 契约抽取
# ---------------------------------------------------------------------------


class TestContractExtraction:
    def test_openapi_extracts_paths_and_methods(self) -> None:
        spec = {
            "paths": {
                "/api/v2/orders/{order_id}": {
                    "get": {"security": [{"bearer": []}]},
                },
                "/api/v2/public/health": {
                    "get": {},  # 无 security → 不要求认证
                },
            },
            "security": [],
        }
        c = from_openapi(spec)
        assert c.get("GET", "/api/v2/orders/{order_id}") is not None
        assert c.get("GET", "/api/v2/orders/{order_id}").auth_required.value is True
        assert c.get("GET", "/api/v2/public/health").auth_required.value is False

    def test_openapi_detects_resource_id_params(self) -> None:
        """资源标识参数是 BL1 的判据来源。"""
        spec = {"paths": {"/api/v2/orders/{order_id}": {"get": {"security": [{"b": []}]}}}}
        c = from_openapi(spec)
        ep = c.get("GET", "/api/v2/orders/{order_id}")
        assert "order_id" in str(ep.resource_owner.value) or ep.resource_owner.value == "self"

    def test_openapi_flags_sensitive_body_fields_as_low_confidence(self) -> None:
        """OpenAPI 只能告诉我们"客户端提供了该字段"，不能告诉我们
        "它不该由客户端提供" —— 因此置信度必须低。
        """
        spec = {
            "paths": {
                "/checkout": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"properties": {"price": {"type": "number"}}},
                                }
                            }
                        },
                    },
                },
            },
        }
        c = from_openapi(spec)
        ep = c.get("POST", "/checkout")
        assert "price" in ep.server_computed.value
        assert ep.server_computed.effective_confidence < 0.5

    def test_invalid_json_raises(self) -> None:
        with pytest.raises(ValueError, match="invalid OpenAPI"):
            from_openapi("{not json")

    def test_traffic_inference_warns_about_limits(self) -> None:
        """M8 §3.2 N3 的诚实性要求：流量推断的限制必须写进告警。"""
        c = from_traffic([TrafficRecord("GET", "/a", authenticated=True, seq=0)])
        assert any("不可见" in w or "N3" in w for w in c.warnings)

    def test_traffic_cannot_infer_auth_required(self) -> None:
        """★ 关键：只观测到认证请求时**不能**断言"要求认证"。

        那可能只是我们恰好都带了 cookie。因此用 `None` 表达"未知"，
        而不是猜 `True` —— 猜 True 会让 BL1 检测漏掉真正无需认证的端点。
        """
        c = from_traffic([TrafficRecord("GET", "/a", authenticated=True, seq=0)])
        ep = c.get("GET", "/a")
        assert ep.auth_required.value is None
        assert ep.auth_required.effective_confidence < 0.5

    def test_traffic_infers_no_auth_from_unauthenticated_success(self) -> None:
        c = from_traffic([TrafficRecord("GET", "/pub", authenticated=False, status=200, seq=0)])
        assert c.get("GET", "/pub").auth_required.value is False

    def test_traffic_builds_state_machine_transitions(self) -> None:
        c = from_traffic(
            [
                TrafficRecord("POST", "/cart", seq=0),
                TrafficRecord("POST", "/pay", seq=1),
                TrafficRecord("POST", "/confirm", seq=2),
            ]
        )
        assert ("POST /cart", "POST /pay") in c.transitions
        assert ("POST /pay", "POST /confirm") in c.transitions

    def test_source_confidence_ordering(self) -> None:
        """M8 §4.1：OpenAPI > 源码注解 > 流量 > 文档。"""
        assert (
            intent.source_confidence(ContractSource.OPENAPI)
            > intent.source_confidence(ContractSource.SOURCE_ANNOTATION)
            > intent.source_confidence(ContractSource.TRAFFIC)
            > intent.source_confidence(ContractSource.DOCUMENT)
        )

    def test_field_defaults_confidence_from_source(self) -> None:
        f = Field(True, ContractSource.OPENAPI)
        assert f.effective_confidence == 1.0
        f2 = Field(True, ContractSource.DOCUMENT)
        assert f2.effective_confidence < 0.5

    def test_field_str_handles_none(self) -> None:
        """`None` 表达"未知"，不得被转成字符串 "None"（语义污染）。"""
        assert field_str(Field(None)) == ""
        assert field_str(Field("x")) == "x"


# ---------------------------------------------------------------------------
# ★ 靶场与双模式检出统计（DoD 核心）
# ---------------------------------------------------------------------------


class TestLab:
    def test_lab_has_at_least_ten_defects(self) -> None:
        """M8 §7 DoD：靶场含 ≥10 类业务逻辑缺陷。"""
        lab = build_default_lab()
        assert len(lab.defects) >= 10

    def test_lab_covers_all_six_types(self) -> None:
        """M8 §7 DoD + §6：BL1–BL6 每类至少 1 个。"""
        cov = lab_covers_all_types(build_default_lab())
        for t in ALL_VIOLATION_TYPES:
            assert cov[t] >= 1, f"靶场缺 {t} 类缺陷"

    def test_dual_mode_detectable_counts_differ(self) -> None:
        """★ 双模式是诚实性的关键（M8 §4.5）。

        无契约模式下有些缺陷**原理上不可检**（如 BL2 需要知道
        "该字段应由服务端计算"）—— 分母必须随之收缩。
        """
        lab = build_default_lab()
        with_c = lab.defects_in(LabMode.WITH_CONTRACT)
        without_c = lab.defects_in(LabMode.WITHOUT_CONTRACT)
        assert len(without_c) < len(with_c), (
            "无契约模式的可检数必须少于有契约模式 —— 否则双模式统计无意义"
        )
        assert len(with_c) == len(lab.defects)

    def test_defect_ids_are_unique(self) -> None:
        lab = build_default_lab()
        ids = [d.defect_id for d in lab.defects]
        assert len(ids) == len(set(ids))

    def test_lab_summary_is_renderable(self) -> None:
        text = intent.render_lab_summary(build_default_lab())
        assert "BL1_IDOR" in text
        assert "WITH_CONTRACT" in text


class TestDetectionStats:
    def test_full_detection_gives_100_percent(self) -> None:
        """六类全检出 → 100%（构造完全命中）。"""
        lab = build_default_lab()
        violations = [
            judge(
                probe(
                    key=d.endpoint_key,
                    vtype=d.violation_type,
                    data_returned=True,
                    exec_id=f"ex_{d.defect_id}",
                ),
                rationale="detected",
            )
            for d in lab.defects_in(LabMode.WITH_CONTRACT)
        ]
        stats = evaluate_detection(lab, LabMode.WITH_CONTRACT, [v for v in violations if v])
        assert stats.detection_rate == 1.0
        assert stats.missed == []

    def test_missed_defects_are_listed(self) -> None:
        """M8 §6：漏报率必须**单独统计并公开**。"""
        lab = build_default_lab()
        first = lab.defects_in(LabMode.WITH_CONTRACT)[0]
        v = judge(
            probe(key=first.endpoint_key, vtype=first.violation_type, exec_id="ex"),
            rationale="only one",
        )
        stats = evaluate_detection(lab, LabMode.WITH_CONTRACT, [v])
        assert stats.detected == [first.defect_id]
        assert len(stats.missed) == stats.detectable - 1
        assert stats.miss_rate > 0
        assert first.defect_id not in stats.missed

    def test_false_positives_are_listed(self) -> None:
        lab = build_default_lab()
        v = judge(
            probe(key="GET /not-in-lab", vtype=ViolationType.BL1_IDOR, exec_id="ex_fp"),
            rationale="not a real defect",
        )
        stats = evaluate_detection(lab, LabMode.WITH_CONTRACT, [v])
        assert len(stats.false_positives) == 1
        assert "not-in-lab" in stats.false_positives[0]

    def test_no_evidence_violation_not_counted(self) -> None:
        """无强证证据的违背不进检出（M8 §6 硬要求）。"""
        lab = build_default_lab()
        d = lab.defects_in(LabMode.WITH_CONTRACT)[0]
        v = judge(
            probe(key=d.endpoint_key, vtype=d.violation_type, data_returned=False),
            rationale="no evidence",
        )
        assert v is None
        stats = evaluate_detection(lab, LabMode.WITH_CONTRACT, [])
        assert stats.detected == []

    def test_denominator_shrinks_in_without_contract_mode(self) -> None:
        """无契约模式的分母必须小于有契约模式。"""
        lab = build_default_lab()
        s_with = evaluate_detection(lab, LabMode.WITH_CONTRACT, [])
        s_without = evaluate_detection(lab, LabMode.WITHOUT_CONTRACT, [])
        assert s_without.detectable < s_with.detectable

    def test_stats_render_includes_miss_list(self) -> None:
        lab = build_default_lab()
        stats = evaluate_detection(lab, LabMode.WITH_CONTRACT, [])
        text = stats.render()
        assert "漏报" in text
        assert "BLE" not in text  # 拼写错误哨兵


class TestReport:
    def test_dual_mode_report_covers_both(self) -> None:
        """★ M8 §7 DoD：双模式分别给出数字，**不合并汇报**。"""
        lab = build_default_lab()
        report = build_report(
            lab,
            {
                LabMode.WITH_CONTRACT: ([], ContractSource.OPENAPI),
                LabMode.WITHOUT_CONTRACT: ([], ContractSource.TRAFFIC),
            },
        )
        assert len(report.stats) == 2
        text = report.render()
        assert "仅覆盖一种模式" not in text

    def test_single_mode_report_warns(self) -> None:
        """只报一种模式时必须显式警告（M8 §4.5：会高估能力）。"""
        lab = build_default_lab()
        report = build_report(
            lab,
            {
                LabMode.WITH_CONTRACT: ([], ContractSource.OPENAPI),
            },
        )
        assert "仅覆盖一种模式" in report.render()

    def test_report_records_contract_source_per_mode(self) -> None:
        """报告必须声明能力建立在什么输入上（M8 §9 的诚实要求）。"""
        lab = build_default_lab()
        report = build_report(
            lab,
            {
                LabMode.WITH_CONTRACT: ([], ContractSource.OPENAPI),
                LabMode.WITHOUT_CONTRACT: ([], ContractSource.TRAFFIC),
            },
        )
        assert report.contract_sources[LabMode.WITH_CONTRACT] == ContractSource.OPENAPI
        assert report.contract_sources[LabMode.WITHOUT_CONTRACT] == ContractSource.TRAFFIC

    def test_rate_for_unknown_mode_is_zero(self) -> None:
        lab = build_default_lab()
        report = build_report(lab, {})
        assert report.rate_for("NOPE") == 0.0


# ---------------------------------------------------------------------------
# ★ 端到端：给出可复现的检出数字（DoD 的核心交付物）
# ---------------------------------------------------------------------------


def test_end_to_end_produces_reproducible_detection_numbers() -> None:
    """I10 的 DoD：给出**可复现**的业务逻辑检出数字。

    模拟一次完整的探测轮次：对靶场的每个缺陷构造命中（含强证据），
    再按双模式统计。第二次运行必须得到**完全相同**的数字 ——
    这就是"可复现"的含义（M8 §6「可复现」测试要求：
    "第三方在干净环境重跑得到同量级结果"）。
    """

    def run() -> tuple[float, float, int]:
        lab = build_default_lab()
        # 模拟探测：对全部「可检」缺陷都取回了数据（强证据）。
        violations = []
        for d in lab.defects_in(LabMode.WITH_CONTRACT):
            violations.append(
                judge(
                    probe(
                        key=d.endpoint_key,
                        vtype=d.violation_type,
                        data_returned=True,
                        exec_id=f"ex_{d.defect_id}",
                    ),
                    rationale="simulated probe with DATA_RETURNED",
                )
            )
        # 无契约模式：只能检出 11/13（BL2 的 2 个原理上不可检）。
        without = []
        for d in lab.defects_in(LabMode.WITHOUT_CONTRACT):
            without.append(
                judge(
                    probe(
                        key=d.endpoint_key,
                        vtype=d.violation_type,
                        data_returned=True,
                        exec_id=f"ex_{d.defect_id}",
                    ),
                    rationale="traffic-inferred probe",
                )
            )

        report = build_report(
            lab,
            {
                LabMode.WITH_CONTRACT: ([v for v in violations if v], ContractSource.OPENAPI),
                LabMode.WITHOUT_CONTRACT: ([v for v in without if v], ContractSource.TRAFFIC),
            },
        )

        with_rate = report.rate_for(LabMode.WITH_CONTRACT)
        without_rate = report.rate_for(LabMode.WITHOUT_CONTRACT)
        total = sum(s.detectable for s in report.stats.values())
        return with_rate, without_rate, total

    first = run()
    for _ in range(5):
        assert run() == first, "检出数字必须可复现（P-5）"

    with_rate, without_rate, total = first
    # 有契约模式全部检出。
    assert with_rate == 1.0
    # 无契约模式受**分母收缩**影响，比例反而可能更高 ——
    # 关键是分母不同（这才是诚实统计的核心）。
    assert without_rate > 0
    assert total == 13 + 11


def test_report_never_claims_universal_capability() -> None:
    """M8 §3.2 N3：不得声称对黑盒无文档目标有通用能力。

    本测试守护报告措辞中的诚实性：单模式报告必须带警告，
    双模式报告必须分别列示。
    """
    lab = build_default_lab()
    single = build_report(lab, {LabMode.WITH_CONTRACT: ([], ContractSource.OPENAPI)})
    assert "不得用于声明整体能力" in single.render()
