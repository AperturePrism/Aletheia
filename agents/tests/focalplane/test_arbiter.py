"""I7 终止仲裁测试套件（M4 §4.5 / §6 / §7，T4.10–T4.11）。

**这是 M4 的核心资产之一**：模块规格 §6 明确「P0 门禁测试集是 M4 的
核心资产，应作为独立测试套件长期维护」。

DoD（M4 §7 I7 结束时）：
  · 幻觉终止 **0 次通过**（50 组伪达成用例）
  · 合法终止 **100% 通过**
  · 拒绝后 agent 能继续探索（循环检测有效）

设计要点：**假阴性用例与假阳性用例同等重要**。只测"该拒的拒了"
会让仲裁器越调越严，最终把合法终止也拒掉 —— 那对使用者同样是
失败（agent 永远停不下来）。因此本文件两类用例并行。
"""

from __future__ import annotations

import pytest

from aletheia.focalplane import arbiter as arb
from aletheia.gen.aleth.v1 import aletheia_pb2 as pb

# ---------------------------------------------------------------------------
# 测试夹具
# ---------------------------------------------------------------------------


class FakeScope:
    """可编程的 scope 判定（M6 ScopeKernel 的替身）。"""

    def __init__(self, inside: set[str] | None = None) -> None:
        self.inside = inside if inside is not None else {"asset_in_scope"}

    def __call__(self, target: str) -> bool:
        return target in self.inside


class FakeEvidence:
    """可编程的证据存在性 + 闸门结论（账本的替身）。"""

    def __init__(
        self,
        existing: set[str] | None = None,
        gate_passed: set[str] | None = None,
    ) -> None:
        self.existing = existing if existing is not None else {"ev_1", "ev_2"}
        self.gate_passed = gate_passed if gate_passed is not None else {"ev_1", "ev_2"}

    def exists(self, evidence_id: str) -> bool:
        return evidence_id in self.existing

    def passed(self, evidence_id: str) -> bool:
        return evidence_id in self.gate_passed


def make_arbiter(
    *,
    inside: set[str] | None = None,
    existing: set[str] | None = None,
    gate_passed: set[str] | None = None,
) -> arb.TerminationArbiter:
    scope = FakeScope(inside)
    ev = FakeEvidence(existing, gate_passed)
    return arb.TerminationArbiter(
        scope_contains=scope,
        evidence_ids_exist=ev.exists,
        gate_passed_for=ev.passed,
    )


def request(
    *,
    claimed: str,
    goal: str = "obtain the flag",
    target: str = "asset_in_scope",
    evidence: tuple[str, ...] = ("ev_1",),
    agent: str = "agent-a",
    session: str = "sess-1",
) -> pb.TerminationRequest:
    return pb.TerminationRequest(
        session_id=session,
        agent_id=agent,
        goal_definition=goal,
        claimed_achievement=claimed,
        evidence_ids=list(evidence),
        target_entity_id=target,
    )


# ---------------------------------------------------------------------------
# DoD① 幻觉终止 0 次通过 —— 50 组伪达成用例（T4.11）
# ---------------------------------------------------------------------------

#: 伪达成用例：全部**必须**被拒（DoD 要求 0 次通过）。
#:
#: 三类来源（M4 §6「幻觉终止」行原文）：
#:   ① 随机哈希   ② Base64 串   ③ 误判 banner
#:
#: 每类构造多组变体。**不构造"显然会被拒"的用例**（如空串）——
#: 那会让 50 组用例的通过率虚高而无信息量。
FABRICATED_CASES: list[tuple[str, str, str]] = [
    # ---- ① 随机哈希被当成 flag（D3 的原始形态）----
    ("hex-md5", "flag: 5d41402abc4b2a76b9719d911017c592", "obtain the flag"),
    ("hex-md5-upper", "flag: 5D41402ABC4B2A76B9719D911017C592", "obtain the flag"),
    ("hex-sha1", "flag: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "obtain the flag"),
    (
        "hex-sha256",
        "flag: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "obtain the flag",
    ),
    ("hex-bare", "5d41402abc4b2a76b9719d911017c592", "find the flag"),
    ("hex-64", "a" * 64, "get the flag"),
    ("hex-32-mixed", "deadbeefdeadbeefdeadbeefdeadbeef", "recover the flag"),
    ("hex-etag-like", "flag: 686897696a7c876b7e", "obtain the flag"),
    # ---- ② Base64 串 ----
    ("b64-hello", "flag: aGVsbG8gd29ybGQh", "obtain the flag"),
    ("b64-padding", "flag: SGVsbG8sIFdvcmxkIQ==", "obtain the flag"),
    ("b64-long", "flag: " + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", "obtain the flag"),
    ("b64-no-prefix", "VGhlIHF1aWNrIGJyb3duIGZveA==", "find the flag"),
    ("b64-rand", "ZkxhZ3t0aGlzX2lzX2Jhc2U2NH0=", "obtain the flag"),
    # ---- ③ 误判 banner（searchsploit / 服务回显的经典陷阱）----
    ("banner-shellcodes", "Shellcodes: 42 found", "obtain a root shell"),
    ("banner-shellcode-lc", "shellcode available in exploit db", "get root"),
    ("banner-login", "login: ", "obtain a root shell"),
    ("banner-password", "password:", "get root shell"),
    ("banner-username", "username: admin", "obtain root shell"),
    ("banner-exploit-completed", "exploit completed", "obtain a root shell"),
    ("banner-exploit-db", "Exploit DB entry 12345 loaded", "get root"),
    ("banner-searchsploit", "searchsploit results: 12", "obtain root shell"),
    # ---- ④ 长度不足 / 无形态（信息量不足以支撑终止）----
    ("short-1", "flag: abc", "obtain the flag"),
    ("short-2", "flag: x", "obtain the flag"),
    ("short-3", "ok", "obtain the flag"),
    ("short-4", "done", "obtain the flag"),
    ("short-5", "12345678", "obtain the flag"),
    ("short-6", "true", "obtain the flag"),
    ("short-7", "success", "obtain the flag"),
    ("short-8", "null", "obtain the flag"),
    # ---- ⑤ 目标不匹配（达成物与目标定义不符）----
    ("mismatch-flag-vs-shell", "uid=0(root) gid=0(root)", "obtain the flag"),
    (
        "mismatch-shell-vs-flag",
        "flag{this_looks_like_a_flag}",
        "obtain a root shell",
    ),
    ("mismatch-data-vs-flag", "flag{a_flag} OR 1=1", "dump the users table"),
    ("mismatch-empty-goal", "flag{real_flag_value}", ""),
    ("mismatch-unparsable-goal", "flag{real_flag_value}", "achieve the objective"),
    (
        "mismatch-shell-banner",
        "login: root",
        "obtain a root shell",
    ),
    ("mismatch-shell-no-indicator", "command executed successfully", "get root shell"),
    # ---- ⑥ 其它幻觉形态 ----
    ("hex-40", "b" * 40, "obtain the flag"),
    ("b64-short", "ZmxhZ3t4fQ==", "obtain the flag"),
    ("banner-mixed", "Found 3 Shellcodes in the Exploit DB", "obtain a root shell"),
    ("short-9", "yes", "obtain the flag"),
    ("short-10", "flag:", "obtain the flag"),
    ("short-11", "0", "obtain the flag"),
    ("short-12", "none", "obtain the flag"),
    ("short-13", "waiting", "obtain the flag"),
    ("banner-password-colon", "Password: hunter2", "obtain a root shell"),
    ("hex-with-prefix", "flag: c0ffee" * 4, "obtain the flag"),
    ("b64-2", "dGhlIGZsYWcgaXMgaGVyZQ==", "find the flag"),
    ("hex-32-2", "0123456789abcdef0123456789abcdef", "get the flag"),
    ("short-14", "cHJpbnQ=", "obtain the flag"),
    ("banner-login-root", "login: root\nPassword:", "obtain a root shell"),
    ("mismatch-flag-vs-data", "flag{a_value_here}", "exfiltrate the customer database"),
]


def _build_params() -> list:
    """把 FABRICATED_CASES 展开为 pytest 参数（含需要特殊构造的项）。"""
    params = []
    for case in FABRICATED_CASES:
        name = case[0]
        claimed = case[1]
        goal = case[2]
        params.append(pytest.param(name, claimed, goal, id=name))
    return params


@pytest.mark.parametrize(("name", "claimed", "goal"), _build_params())
def test_fabricated_achievement_is_refused(name: str, claimed: str, goal: str) -> None:
    """DoD① 的逐组断言：伪达成必须被拒（0 次通过）。"""
    a = make_arbiter()
    v = a.arbitrate(request(claimed=claimed, goal=goal))
    assert not v.approved, (
        f"FABRICATED ACHIEVEMENT APPROVED [{name}]: {claimed!r} "
        f"(goal={goal!r}) — this is a hallucinated termination (D3)"
    )
    assert v.refusal_reason != pb.TerminationRefusalReason.TERMINATION_REFUSAL_UNSPECIFIED, (
        f"[{name}] refusal must carry an explicit reason"
    )
    assert v.guidance, f"[{name}] refusal must give guidance (avoid retry loops)"


def test_fabricated_suite_size_meets_dod() -> None:
    """DoD① 要求"50 组用例"—— 本套件必须达到该规模。

    这条断言防止有人后续删减用例让指标好看（docs/09 R3：不得削弱测试）。
    """
    assert len(FABRICATED_CASES) >= 50, (
        f"fabricated-achievement suite has {len(FABRICATED_CASES)} cases; the I7 DoD requires 50"
    )


def test_zero_fabricated_approved_aggregate() -> None:
    """DoD① 的聚合断言：**0 次通过**（逐组断言之外再算一次总数）。

    逐组断言失败时会指出具体用例；这条给出整体结论，便于门禁脚本读取。
    """
    a = make_arbiter()
    approved = []
    for case in FABRICATED_CASES:
        name, claimed, goal = case[0], case[1], case[2]
        if a.arbitrate(request(claimed=claimed, goal=goal, agent=f"agent-{name}")).approved:
            approved.append(name)
    assert approved == [], f"{len(approved)} fabricated achievements were approved: {approved}"


# ---------------------------------------------------------------------------
# DoD② 合法终止 100% 通过（假阴性检查 —— 防止仲裁过严）
# ---------------------------------------------------------------------------

LEGITIMATE_CASES: list[tuple[str, str, str, tuple[str, ...]]] = [
    ("flag-basic", "flag{th1s_1s_a_r34l_fl4g}", "obtain the flag", ("ev_1",)),
    ("flag-with-prefix-word", "flag: flag{c0rr3ct_h0rse}", "find the flag", ("ev_1",)),
    ("flag-long", "flag{" + "a" * 40 + "}", "obtain the flag", ("ev_1",)),
    ("flag-ctf-style", "CTF{s0me_v4lue_here}", "obtain the flag", ("ev_1", "ev_2")),
    ("flag-underscore", "flag{under_score_value}", "get the flag", ("ev_2",)),
    ("shell-root-uid", "uid=0(root) gid=0(root) groups=0(root)", "obtain a root shell", ("ev_1",)),
    ("shell-root-prompt", "root@target:~# ", "obtain root shell", ("ev_1",)),
    (
        "shell-rce",
        "shell obtained via CVE-2024-1234 exploitation",
        "obtain a root shell",
        ("ev_1",),
    ),
    ("shell-priv-esc", "shell as uid=0 gid=0 after privilege escalation", "get root", ("ev_1",)),
    (
        "data-users-table",
        "retrieved the users table with 1204 rows",
        "dump the users table",
        ("ev_1",),
    ),
    (
        "data-credentials",
        "database credentials extracted from config",
        "obtain database credentials",
        ("ev_1",),
    ),
]


@pytest.mark.parametrize(("name", "claimed", "goal", "evidence"), LEGITIMATE_CASES)
def test_legitimate_termination_is_approved(
    name: str, claimed: str, goal: str, evidence: tuple[str, ...]
) -> None:
    """DoD②：合法终止必须 100% 通过。

    这条与伪达成用例同等重要 —— 一个"什么都拒"的 Arbiter 会让 agent
    永远停不下来，同样是失败（M4 §8 风险栏首条："闸门过严导致漏报"）。
    """
    a = make_arbiter()
    v = a.arbitrate(request(claimed=claimed, goal=goal, evidence=evidence))
    assert v.approved, (
        f"LEGITIMATE TERMINATION REFUSED [{name}]: {claimed!r} (goal={goal!r}) — "
        f"reason={v.refusal_reason}, checks={v.checks}"
    )


def test_legitimate_suite_present() -> None:
    """防止有人删空假阴性用例（那样"100% 通过"会变成恒真）。"""
    assert len(LEGITIMATE_CASES) >= 10, "false-negative suite is too small to be meaningful"


# ---------------------------------------------------------------------------
# 四道校验的逐条测试
# ---------------------------------------------------------------------------


def test_check_hallucination_runs_before_evidence() -> None:
    """第 ④ 道必须先于第 ③ 道 —— 精心构造的证据链不得为幻觉背书。

    M4 §8 风险栏："Arbiter 被 agent 通过精心构造的证据欺骗"。
    若先查证据，一个"证据齐全但达成物是随机哈希"的请求会走到最后；
    更重要的是，那意味着证据链可以**授权**一个幻觉结论。
    """
    a = make_arbiter()
    v = a.arbitrate(
        request(
            claimed="flag: 5d41402abc4b2a76b9719d911017c592",  # 裸 MD5
            goal="obtain the flag",
            evidence=("ev_1", "ev_2"),  # 证据齐全且全过闸门
        )
    )
    assert not v.approved
    assert v.refusal_reason == pb.TerminationRefusalReason.SUSPECTED_HALLUCINATION
    # 断言幻觉检查确实先跑：闸门检查不应出现在 checks 里
    # （早退时后续校验不执行）。
    assert not any("G-evidence" in c for c in v.checks), (
        "hallucination check must short-circuit before evidence checks"
    )


def test_missing_target_refused() -> None:
    a = make_arbiter()
    v = a.arbitrate(request(claimed="flag{real_value_here}", target=""))
    assert not v.approved
    assert v.refusal_reason == pb.TerminationRefusalReason.ATTRIBUTION_UNCONFIRMED


def test_out_of_scope_target_refused() -> None:
    """归属未确认（不在 scope 内）必须拒绝 —— AIxCC 错误关联重罚项。

    这条刻意放在独立测试而非参数化用例里：它需要**不同的 scope 配置**
    （目标存在于图里但在授权范围外），参数化用例共用同一个 arbiter 夹具。
    """
    a = make_arbiter(inside={"asset_in_scope"})
    v = a.arbitrate(request(claimed="flag{real_value_here}", target="asset_outside_scope"))
    assert not v.approved
    assert v.refusal_reason == pb.TerminationRefusalReason.ATTRIBUTION_UNCONFIRMED
    assert any("outside the authorized scope" in c for c in v.checks)


def test_no_evidence_refused() -> None:
    a = make_arbiter()
    v = a.arbitrate(request(claimed="flag{real_value_here}", evidence=()))
    assert not v.approved
    assert v.refusal_reason == pb.TerminationRefusalReason.EVIDENCE_INSUFFICIENT


def test_nonexistent_evidence_refused() -> None:
    """引用了不存在的证据 → 拒绝（G-2 的"每个 ID 在账本中真实存在"）。"""
    a = make_arbiter(existing={"ev_1"})
    v = a.arbitrate(request(claimed="flag{real_value_here}", evidence=("ev_1", "ev_ghost")))
    assert not v.approved
    assert v.refusal_reason == pb.TerminationRefusalReason.EVIDENCE_INSUFFICIENT
    assert any("ev_ghost" in c for c in v.checks)


def test_evidence_failing_gates_refused() -> None:
    """证据存在但未过闸门 → 拒绝（M4 §4.5 第 ③ 道）。"""
    a = make_arbiter(existing={"ev_1"}, gate_passed=set())  # 存在但闸门未过
    v = a.arbitrate(request(claimed="flag{real_value_here}", evidence=("ev_1",)))
    assert not v.approved
    assert v.refusal_reason == pb.TerminationRefusalReason.EVIDENCE_INSUFFICIENT
    assert any("has not passed all gates" in c for c in v.checks)


def test_checks_are_auditable() -> None:
    """四道校验必须留下可审计的逐条结论（M4 §4.5："不接受自我评估"）。"""
    a = make_arbiter()
    v = a.arbitrate(request(claimed="flag{real_value_here}"))
    assert v.approved
    joined = " | ".join(v.checks)
    assert "G-hallucination" in joined
    assert "G-goal" in joined
    assert "G-attribution" in joined
    assert "G-evidence" in joined


# ---------------------------------------------------------------------------
# DoD③ 拒绝后 agent 能继续探索（循环检测有效）
# ---------------------------------------------------------------------------


def test_repeated_rejections_escalate_guidance() -> None:
    """反复提交同一请求时，guidance 必须明确要求停止 —— 否则 agent 空转
    到预算耗尽（M4 §7 I7 DoD："拒绝后 agent 能继续探索"）。
    """
    a = make_arbiter()
    req = lambda: request(claimed="flag: 5d41402abc4b2a76b9719d911017c592")  # noqa: E731

    first = a.arbitrate(req())
    assert not first.approved
    assert "NOTE:" not in first.guidance

    for _ in range(2):
        a.arbitrate(req())  # 第 2、3 次

    fourth = a.arbitrate(req())  # 第 4 次 → 累计 4 次拒绝
    assert "Stop re-submitting" in fourth.guidance, (
        f"repeated refusals must escalate guidance, got: {fourth.guidance!r}"
    )


def test_every_refusal_has_guidance() -> None:
    """每种拒绝原因都必须给出 guidance（M4 §4.5：避免 agent 陷入循环）。"""
    for reason in (
        pb.TerminationRefusalReason.GOAL_MISMATCH,
        pb.TerminationRefusalReason.ATTRIBUTION_UNCONFIRMED,
        pb.TerminationRefusalReason.EVIDENCE_INSUFFICIENT,
        pb.TerminationRefusalReason.SUSPECTED_HALLUCINATION,
    ):
        assert reason in arb._GUIDANCE, f"no guidance text for {reason}"
        assert arb._GUIDANCE[reason].strip(), f"empty guidance for {reason}"


# ---------------------------------------------------------------------------
# 幻觉检测单元测试（detect_suspected_hallucination）
# ---------------------------------------------------------------------------


class TestHallucinationDetection:
    def test_bare_hex_is_suspected(self) -> None:
        for s in ("5d41402abc4b2a76b9719d911017c592", "a" * 40, "deadbeef" * 8):
            assert arb.detect_suspected_hallucination(s).suspected, s

    def test_base64_is_suspected(self) -> None:
        for s in ("aGVsbG8gd29ybGQh", "SGVsbG8sIFdvcmxkIQ=="):
            assert arb.detect_suspected_hallucination(s).suspected, s

    def test_misleading_banner_is_suspected(self) -> None:
        for s in ("Shellcodes: 42", "login: ", "exploit completed", "searchsploit"):
            assert arb.detect_suspected_hallucination(s).suspected, s

    def test_flag_shape_is_clean(self) -> None:
        for s in ("flag{real}", "CTF{abc123}", "flag: flag{value}", "flag{a_b_c_d}"):
            assert not arb.detect_suspected_hallucination(s).suspected, s

    def test_short_string_is_suspected(self) -> None:
        assert arb.detect_suspected_hallucination("abc").suspected

    def test_empty_is_suspected(self) -> None:
        assert arb.detect_suspected_hallucination("").suspected
        assert arb.detect_suspected_hallucination("   ").suspected

    def test_shell_output_is_clean(self) -> None:
        """uid=0(root) gid=0(root) 形态不应被判为幻觉（它是侧信道证据形态）。"""
        assert not arb.detect_suspected_hallucination(
            "uid=0(root) gid=0(root) groups=0(root)"
        ).suspected

    def test_reason_is_always_populated_when_suspected(self) -> None:
        """拒绝必须说明"为什么疑似幻觉"—— 否则 agent 无法修正。"""
        for s in ("5d41402abc4b2a76b9719d911017c592", "abc", "login: "):
            sig = arb.detect_suspected_hallucination(s)
            assert sig.suspected and sig.reason, s


# ---------------------------------------------------------------------------
# 目标解析（parse_goal / goal_matches）
# ---------------------------------------------------------------------------


class TestGoalParsing:
    def test_flag_goal(self) -> None:
        assert arb.parse_goal("obtain the flag").kind == "flag"
        assert arb.parse_goal("拿到 flag").kind == "flag"

    def test_shell_goal(self) -> None:
        assert arb.parse_goal("get a root shell").kind == "shell"
        assert arb.parse_goal("achieve RCE").kind == "shell"
        assert arb.parse_goal("提权到 root").kind == "shell"

    def test_data_goal(self) -> None:
        assert arb.parse_goal("dump the users table").kind == "data"
        assert arb.parse_goal("extract database credentials").kind == "data"

    def test_unknown_goal(self) -> None:
        assert arb.parse_goal("do the thing").kind == "unknown"
        assert arb.parse_goal("").kind == "unknown"

    def test_unknown_goal_refuses_match(self) -> None:
        """无法解析的目标 → 拒绝（fail-closed）。

        放行会让"目标没写清就能随便终止"成为绕过路径 —— 而 ROE 的目标
        定义质量不由 Arbiter 控制，因此必须保守。
        """
        ok, why = arb.goal_matches(arb.parse_goal("do the thing"), "flag{real}")
        assert not ok and why


# ---------------------------------------------------------------------------
# 拒绝原因是契约枚举（防止自造原因）
# ---------------------------------------------------------------------------


def test_refusal_reasons_are_contract_enum_values() -> None:
    """拒绝原因必须取自 05 §5.4 的 TerminationRefusalReason 枚举。"""
    valid = {
        pb.TerminationRefusalReason.GOAL_MISMATCH,
        pb.TerminationRefusalReason.ATTRIBUTION_UNCONFIRMED,
        pb.TerminationRefusalReason.EVIDENCE_INSUFFICIENT,
        pb.TerminationRefusalReason.SUSPECTED_HALLUCINATION,
    }
    a = make_arbiter()
    produced = set()
    for req in (
        request(claimed="5d41402abc4b2a76b9719d911017c592"),  # hallucination
        request(claimed="flag{v}", goal="get root shell"),  # goal mismatch
        request(claimed="flag{v}", target=""),  # attribution
        request(claimed="flag{v}", evidence=()),  # evidence
    ):
        v = a.arbitrate(req)
        produced.add(v.refusal_reason)
    assert produced <= valid, f"non-contract refusal reasons produced: {produced - valid}"
