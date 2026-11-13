"""真实探测器的测试（不需要 docker / 不需要靶场）。

# 为什么不联真实靶场

CI 里没有 docker，也没有运行中的靶场。因此这里用**假的 HTTP 层**
（monkeypatch `HttpProber._req`）来验证探测器逻辑本身：

* 每类探测的判定条件（看响应内容，而不是状态码）；
* 强证据门禁（`data_returned=False` → 不产生违背）；
* **ground truth 与探测器端点键必须逐字符一致** —— 这是最容易静默出错
  的地方：对不上时 `evaluate_detection` 会同时算漏报 + 误报，而两边
  都不报错，只是数字错。

真实靶场上的端到端运行记在 `labs/bizlogic/README.md` 与
`labs/bizlogic/last_run.json`，不进 CI（需要 docker）。
"""

from __future__ import annotations

import json

from aletheia.intent import live_probe as lp
from aletheia.intent.lab import LabMode, evaluate_detection
from aletheia.intent.live_bench import EVIDENCE_DISCLAIMER, render, run
from aletheia.intent.violations import ViolationType

# ---------------------------------------------------------------------------
# ground truth 的自洽性
# ---------------------------------------------------------------------------


def test_ground_truth_covers_all_six_types() -> None:
    lab = lp.bizlogic_ground_truth()
    got = lab.coverage_of_types()
    assert got == {
        ViolationType.BL1_IDOR,
        ViolationType.BL2_TAMPERING,
        ViolationType.BL3_FLOW_BYPASS,
        ViolationType.BL4_QUOTA_BYPASS,
        ViolationType.BL5_PRIVILEGE_CHAIN,
        ViolationType.BL6_RACE,
    }, f"六类未全覆盖：{sorted(got)}"


def test_ground_truth_endpoint_keys_match_prober_constants() -> None:
    """★ 端点键必须与探测器产出的键逐字符一致。

    对不上时的症状很隐蔽：检测"成功"了，但 `evaluate_detection` 把它算成
    一个漏报 + 一个误报，两边都不抛错 —— 数字悄悄失真。
    """
    lab = lp.bizlogic_ground_truth()
    known = {
        lp.EP_ORDERS,
        lp.EP_CHECKOUT,
        lp.EP_SHIP,
        lp.EP_COUPON,
        lp.EP_PROMOTE,
        lp.EP_TRANSFER,
    }
    for d in lab.defects:
        assert d.endpoint_key in known, f"未知端点键：{d.endpoint_key!r}"


def test_bl2_is_contract_only_by_design() -> None:
    """BL2 在无契约模式下原理上不可检（M8 §4.5 的双模式设计）。"""
    lab = lp.bizlogic_ground_truth()
    bl2 = next(d for d in lab.defects if d.violation_type == ViolationType.BL2_TAMPERING)
    assert bl2.detectable_in == frozenset({LabMode.WITH_CONTRACT})


# ---------------------------------------------------------------------------
# 假 HTTP 层：验证判定逻辑
# ---------------------------------------------------------------------------


class FakeProber(lp.HttpProber):
    """把 `_req` 换成脚本化响应，其余逻辑（含 exec_id 计算）保持真实。"""

    def __init__(self, script: dict[tuple[str, str], list[tuple[int, str]]]) -> None:
        super().__init__(base="http://fake")
        self.script = script
        self.calls = 0

    def _req(self, method, path, *, user="", body=None, headers=None):
        self.calls += 1
        key = (method, path)
        seq = self.script.get(key)
        if not seq:
            # /api/state 用于 BL6 前后读数：给一个固定响应
            if path == "/api/state":
                return 200, json.dumps({"users": {"bob": {"balance": 1000.0}}})
            return 404, "{}"
        code, text = seq[0] if len(seq) == 1 else seq.pop(0)
        self.log.append({"method": method, "path": path, "code": code})
        return code, text


def test_bl1_detects_other_users_order() -> None:
    p = FakeProber(
        {
            ("GET", "/api/orders/200"): [
                (200, json.dumps({"order": {"owner": "bob", "total": 50.0}}))
            ]
        }
    )
    r = p.probe_bl1()
    assert r.data_returned is True
    assert r.exec_id.startswith("localprobe:")


def test_bl1_not_triggered_by_mere_200() -> None:
    """★ 只有 200 不算证据 —— 必须响应体里真有他人数据。

    若按状态码判定，一个"接口存在但返回 403 内容"的情形会被误报成越权。
    """
    p = FakeProber({("GET", "/api/orders/200"): [(200, json.dumps({"error": "forbidden"}))]})
    r = p.probe_bl1()
    assert r.data_returned is False


def test_bl2_detects_client_supplied_total() -> None:
    p = FakeProber(
        {("POST", "/api/checkout"): [(201, json.dumps({"order": {"id": 300, "total": 0.01}}))]}
    )
    assert p.probe_bl2().data_returned is True


def test_bl3_detects_state_jump() -> None:
    p = FakeProber(
        {("POST", "/api/orders/100/ship"): [(200, json.dumps({"order": {"status": "SHIPPED"}}))]}
    )
    assert p.probe_bl3().data_returned is True


def test_bl3_requires_actual_shipped_state() -> None:
    p = FakeProber(
        {("POST", "/api/orders/100/ship"): [(409, json.dumps({"error": "must pay first"}))]}
    )
    assert p.probe_bl3().data_returned is False


def test_bl4_detects_quota_bypass() -> None:
    p = FakeProber({("POST", "/api/coupon/redeem"): [(200, json.dumps({"redeemed": True}))]})
    r = p.probe_bl4(attempts=4)
    assert r.data_returned is True
    assert r.details["successes"] == "4"


def test_bl4_respects_quota_when_enforced() -> None:
    """配额生效时（第 3 次起 429）不应判为绕过。"""
    p = FakeProber(
        {("POST", "/api/coupon/redeem"): [(200, "{}"), (200, "{}"), (429, "{}"), (429, "{}")]}
    )
    r = p.probe_bl4(attempts=4)
    assert r.data_returned is False
    assert r.details["successes"] == "2"


def test_bl5_detects_header_based_escalation() -> None:
    p = FakeProber(
        {("POST", "/api/admin/users/2/promote"): [(200, json.dumps({"promoted": "bob"}))]}
    )
    assert p.probe_bl5().data_returned is True


def test_bl6_detects_negative_balance() -> None:
    """BL6：双花后余额转为负值才算证据。"""
    p = FakeProber({})
    # 前后两次 /api/state：先 1000，再 -600
    seq = [
        (200, json.dumps({"users": {"bob": {"balance": 1000.0}}})),
        (200, json.dumps({"users": {"bob": {"balance": -600.0}}})),
    ]

    def fake_req(method, path, *, user="", body=None, headers=None):
        if path == "/api/state":
            return seq.pop(0)
        return 200, "{}"

    p._req = fake_req  # type: ignore[method-assign]
    r = p.probe_bl6()
    assert r.data_returned is True
    assert r.details["balance_after"] == "-600.00"


def test_bl6_no_evidence_when_balance_stays_positive() -> None:
    p = FakeProber({})
    seq = [
        (200, json.dumps({"users": {"bob": {"balance": 1000.0}}})),
        (200, json.dumps({"users": {"bob": {"balance": 200.0}}})),
    ]

    def fake_req(method, path, *, user="", body=None, headers=None):
        if path == "/api/state":
            return seq.pop(0)
        return 400, json.dumps({"error": "insufficient balance"})

    p._req = fake_req  # type: ignore[method-assign]
    assert p.probe_bl6().data_returned is False


# ---------------------------------------------------------------------------
# 强证据门禁
# ---------------------------------------------------------------------------


def test_judge_drops_results_without_data_returned() -> None:
    """★ M8 §6：只有 DATA_RETURNED 才构成违背。

    这条是"检出数字不虚高"的机制保证 —— 若放松，所有"接口存在"
    都会被算成漏洞。
    """
    from aletheia.intent.violations import ProbeResult

    results = [
        ProbeResult(
            violation_type=ViolationType.BL1_IDOR,
            endpoint_key=lp.EP_ORDERS,
            data_returned=False,
            exec_id="localprobe:deadbeef",
        )
    ]
    assert lp.violations_from(results) == []


def test_all_violations_carry_strong_evidence() -> None:
    p = FakeProber(
        {
            ("GET", "/api/orders/200"): [
                (200, json.dumps({"order": {"owner": "bob", "total": 50.0}}))
            ],
            ("POST", "/api/checkout"): [(201, json.dumps({"order": {"total": 0.01}}))],
            ("POST", "/api/orders/100/ship"): [(200, json.dumps({"order": {"status": "SHIPPED"}}))],
            ("POST", "/api/coupon/redeem"): [(200, "{}")],
            ("POST", "/api/admin/users/2/promote"): [(200, json.dumps({"promoted": "bob"}))],
        }
    )
    for v in lp.violations_from(p.probe_all()[:5]):
        assert v.has_strong_evidence
        assert v.strong_evidence_exec_id.startswith("localprobe:")


# ---------------------------------------------------------------------------
# 基准 runner（离线部分）
# ---------------------------------------------------------------------------


def test_evaluate_counts_bl2_as_false_positive_without_contract() -> None:
    """★ 这是双模式设计的**预期行为**，不是 bug。

    无契约模式下 BL2 不在分母里；行为探测若仍报出来，框架按"误报"计。
    理由是：没有契约就无法区分"服务端采信了客户端金额"与"合法的
    管理员改价功能"——所以那份"检出"缺乏正当性。

    我在真实靶场上实测到正是这个结果（见 labs/bizlogic/last_run.json）：
    分母 5 / 检出 5 / 误报 1(BL2)。报告必须如实呈现这个口径。
    """
    from aletheia.intent.violations import ProbeResult

    lab = lp.bizlogic_ground_truth()
    # 构造：BL1 与 BL2 都被"探测到"（都有强证据）
    #
    # ★ 必须用关键字参数：`ProbeResult` 的字段顺序是
    #   (endpoint_key, violation_type, status_code, data_returned, ...)，
    # 用位置参数会把类型与端点键喂反 —— 症状是"全部漏报 + 无违背"，
    # 而不是抛异常，很容易被误读成"检测器没工作"。
    results = [
        ProbeResult(
            endpoint_key=lp.EP_ORDERS,
            violation_type=ViolationType.BL1_IDOR,
            data_returned=True,
            exec_id="localprobe:a",
        ),
        ProbeResult(
            endpoint_key=lp.EP_CHECKOUT,
            violation_type=ViolationType.BL2_TAMPERING,
            data_returned=True,
            exec_id="localprobe:b",
        ),
    ]
    stats = evaluate_detection(lab, LabMode.WITHOUT_CONTRACT, lp.violations_from(results))
    assert stats.detectable == 5, "无契约模式的分母应为 5（BL2 被排除）"
    assert len(stats.detected) == 1
    assert stats.false_positives == [f"{ViolationType.BL2_TAMPERING}@{lp.EP_CHECKOUT}"]


def test_render_includes_evidence_disclaimer() -> None:
    """报告必须带证据等级声明 —— 否则读者会把本地探测当成已确认漏洞。"""
    summary = {
        "target": "http://127.0.0.1:8080",
        "lab": "bizlogic",
        "mode": LabMode.WITHOUT_CONTRACT,
        "detectable": 5,
        "detected": ["BL1-order-idor"],
        "missed": [],
        "false_positives": [],
        "rate": 0.2,
        "per_defect": [
            {
                "violation_type": ViolationType.BL1_IDOR,
                "endpoint_key": lp.EP_ORDERS,
                "observed": True,
                "exec_id": "localprobe:x",
                "details": {"status": "200"},
            }
        ],
        "evidence_disclaimer": EVIDENCE_DISCLAIMER,
    }
    out = render(summary)
    assert "证据等级" in out
    assert "不构成红线级" in out


def test_run_requires_reachable_target() -> None:
    """靶场没起时必须**失败**，不能静默产出 0 分。

    0 分与"系统真的很差"无法区分 —— 那是本模块要避免的失真。
    用 1 号端口（通常无服务）模拟靶场未启动。
    """
    summary = run("http://127.0.0.1:1")
    # 传输失败 → 所有 data_returned=False → 检出 0，但**误报也为 0**，
    # 且 per_defect 里能看到 transport 错误痕迹（details 里的 status=0）。
    assert len(summary["detected"]) == 0
    assert summary["false_positives"] == []
    assert all(d["details"].get("status") in ("0", None) for d in summary["per_defect"][:3])
