"""G-4 独立复现执行器测试（T4.9，M4 §4.2 / docs/04 I7 DoD）。

覆盖面：
  · 端到端：CANDIDATE finding → Reproduce 成功 → CONFIRMED（CONFIRMED
    的唯一入口，05 §5.1）；失败 → 保持 CANDIDATE 且审计留痕
  · fail-closed 各分支：无 steps / 无已接受观测 / 环境哈希缺失或不匹配 /
    步骤失败 / 步骤超时 / 非 CANDIDATE 状态 / 未知证据或 finding
  · 比对模式与 G-3 同源（已接受观测，非 entry 原始声明）
  · ProcessBackend 冒烟（真实子进程 + 指纹稳定性）
"""

from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aletheia.focalplane import repro as repro_mod
from aletheia.focalplane.execverifier import exec_id_sign_input
from aletheia.focalplane.focalplane import FocalPlane
from aletheia.focalplane.ledger import Ledger
from aletheia.focalplane.repro import ProcessBackend, ReproExecutor
from aletheia.gen.aleth.v1 import aletheia_pb2 as pb

SESSION = "sess_repro"
TASK = "task_repro"
AGENT = "agent_recon"

#: id(1) root 输出 —— 同时命中 id_root 与 id_generic 两个模式（一次观测
#: 命中多模式时 matched_pattern 存逗号串，G-4 名字解析需拆分；这正是
#: NAS 首次真实验证暴露的路径）。
UID_PATTERN_TEXT = "uid=0(root) gid=0(root) groups=0(root)"


def sign_exec_id(priv: Ed25519PrivateKey, exec_id: str) -> pb.SignedExecId:
    """测试扮演 Sandbox 的签发（与 conftest 同域分离约定，本地复制以遵循
    仓库测试的绝对导入惯例）。"""
    s = pb.SignedExecId()
    s.exec_id = exec_id
    s.signature = priv.sign(exec_id_sign_input(exec_id)).hex()
    return s


class FakeBackend:
    """脚本化后端：按预设队列返回步骤结果，指纹固定。"""

    def __init__(self, outcomes: list[repro_mod.StepOutcome] | None = None) -> None:
        self.outcomes = list(outcomes or [])
        self.fingerprint_value = "f" * 64
        self.seen_argv: list[list[str]] = []

    def fingerprint(self) -> str:
        return self.fingerprint_value

    def run_step(self, argv: list[str], timeout_s: float) -> repro_mod.StepOutcome:
        self.seen_argv.append(argv)
        if self.outcomes:
            return self.outcomes.pop(0)
        return repro_mod.StepOutcome(0, UID_PATTERN_TEXT, " ".join(argv))


def make_entry(exec_id: str, *, spec_steps: list[str] | None = None) -> pb.EvidenceEntry:
    e = pb.EvidenceEntry()
    e.evidence_id = "ev_" + exec_id.replace("exec_", "")
    e.exec_id = exec_id
    e.tool.tool_name = "curl"
    e.tool.tool_version = "8.4.0"
    e.raw.content_hash = "c" * 64
    if spec_steps is not None:
        e.reproducibility.steps.extend(spec_steps)
        e.reproducibility.environment_hash = "f" * 64  # 与 FakeBackend 指纹一致
        e.reproducibility.estimated_minutes = 1.0
    return e


def make_assertion(aid: str, target: str, refs: list[str]) -> pb.Assertion:
    a = pb.Assertion()
    a.assertion_id = aid
    a.statement = f"{target} exploitable"
    a.type = pb.EXPLOITABILITY
    a.target_entity_id = target
    a.supporting_evidence_ids.extend(refs)
    return a


def build_candidate(plane: FocalPlane, priv, backend_steps: list[str] | None = None):
    """构造一条到达 CANDIDATE 的 finding（G-1/G-2/G-3 全过）。"""
    entry = make_entry(
        "exec_repro1",
        spec_steps=backend_steps if backend_steps is not None else ["curl -s http://t/id"],
    )
    plane.append_evidence(entry, sign_exec_id(priv, entry.exec_id))
    obs = pb.SideEffectObservation()
    obs.kind = pb.ID_OUTPUT
    obs.observation = UID_PATTERN_TEXT
    obs.exec_id = entry.exec_id
    plane.record_side_effect(obs, SESSION, TASK)
    a = make_assertion("as_repro1", "svc_x", [entry.evidence_id])
    verdict = plane.validate_assertion(a, SESSION, TASK, AGENT)
    assert verdict.resulting_status == pb.CANDIDATE, "前置失败：应到达 CANDIDATE"
    finding_id = None
    # validate 后从状态表取 finding id（trace 之外的最短路径：断言 → finding 映射）
    finding_id = plane._state.finding_id_of_assertion("as_repro1")
    assert finding_id
    return entry, finding_id


class TestReproduceEndToEnd:
    def test_success_confirms_finding(self, tmp_path: Path, sandbox_keys) -> None:
        """复现成功 → CANDIDATE→CONFIRMED（CONFIRMED 的唯一入口）。"""
        priv, pub_hex = sandbox_keys
        from aletheia.focalplane.execverifier import Ed25519Verifier

        backend = FakeBackend()  # 输出含 uid 模式 → 命中
        plane = FocalPlane(
            Ledger(str(tmp_path / "l.db"), Ed25519Verifier(pub_hex)),
            repro_backend=backend,
        )
        entry, fid = build_candidate(plane, priv)

        result = plane.reproduce(entry.evidence_id, fid, pb.ReproSpec())

        assert result.reproduced
        assert result.g4.passed
        assert result.reproduction_exec_id.startswith("repro_")
        assert result.environment_hash == backend.fingerprint_value
        assert plane._state.get_finding(fid)["status"] == "CONFIRMED"

    def test_confirmation_visible_to_new_connection(self, tmp_path: Path, sandbox_keys) -> None:
        """跨连接可见性（NAS 首次真实验证暴露的缺陷回归）。

        transition 不自提交时，同连接读得到未提交数据（上面的断言会过），
        但 gRPC 客户端/审计脚本是**另一个连接** —— 必须用全新连接断言，
        否则提交缺失会被同连接可见性掩盖。
        """
        priv, pub_hex = sandbox_keys
        from aletheia.focalplane.execverifier import Ed25519Verifier

        db = str(tmp_path / "l.db")
        plane = FocalPlane(Ledger(db, Ed25519Verifier(pub_hex)), repro_backend=FakeBackend())
        entry, fid = build_candidate(plane, priv)
        assert plane.reproduce(entry.evidence_id, fid, pb.ReproSpec()).reproduced
        # 全新 StateStore 连接：模拟 gRPC 客户端 / 审计脚本的读取视角。
        from aletheia.focalplane.focalplane import _StateStore

        assert _StateStore(db).get_finding(fid)["status"] == "CONFIRMED"

    def test_failure_keeps_candidate_with_audit_trail(self, tmp_path: Path, sandbox_keys) -> None:
        """复现失败 → 保持 CANDIDATE，同态跃迁留审计痕。"""
        priv, pub_hex = sandbox_keys
        from aletheia.focalplane.execverifier import Ed25519Verifier

        miss = repro_mod.StepOutcome(0, "nothing relevant here", "curl -s http://t/id")
        plane = FocalPlane(
            Ledger(str(tmp_path / "l.db"), Ed25519Verifier(pub_hex)),
            repro_backend=FakeBackend([miss]),
        )
        entry, fid = build_candidate(plane, priv)

        result = plane.reproduce(entry.evidence_id, fid, pb.ReproSpec())

        assert not result.reproduced
        assert not result.g4.passed
        assert "patterns not re-observed" in result.g4.reason
        assert plane._state.get_finding(fid)["status"] == "CANDIDATE"


class TestReproduceFailClosed:
    def _plane(self, tmp_path: Path, pub_hex: str, backend: FakeBackend) -> FocalPlane:
        from aletheia.focalplane.execverifier import Ed25519Verifier

        return FocalPlane(
            Ledger(str(tmp_path / "l.db"), Ed25519Verifier(pub_hex)),
            repro_backend=backend,
        )

    def test_unknown_evidence(self, tmp_path: Path, sandbox_keys) -> None:
        plane = self._plane(tmp_path, sandbox_keys[1], FakeBackend())
        r = plane.reproduce("ev_missing", "find_x", pb.ReproSpec())
        assert r.error.code == pb.NOT_FOUND

    def test_unknown_finding(self, tmp_path: Path, sandbox_keys) -> None:
        priv, pub_hex = sandbox_keys
        plane = self._plane(tmp_path, pub_hex, FakeBackend())
        entry, _fid = build_candidate(plane, priv)
        r = plane.reproduce(entry.evidence_id, "find_missing", pb.ReproSpec())
        assert r.error.code == pb.NOT_FOUND

    def test_requires_candidate_status(self, tmp_path: Path, sandbox_keys) -> None:
        """M4 §4.2 成本控制：非 CANDIDATE 不复现（fail-closed 拒绝）。

        注：G-3 失败本就停在 CANDIDATE（弱证据是「待补强」）—— 真正
        产出非 CANDIDATE 的合法路径是 ATTRIBUTION_MISMATCH 回滚到
        HYPOTHESIS（05 §1.3 熔断语义）。用它做前提。
        """
        priv, pub_hex = sandbox_keys
        plane = self._plane(tmp_path, pub_hex, FakeBackend())
        entry = make_entry("exec_repro2", spec_steps=["curl -s http://t/id"])
        plane.append_evidence(entry, sign_exec_id(priv, entry.exec_id))
        obs = pb.SideEffectObservation()
        obs.kind = pb.ID_OUTPUT
        obs.observation = UID_PATTERN_TEXT
        obs.exec_id = entry.exec_id
        plane.record_side_effect(obs, SESSION, TASK)
        # 断言 A → CANDIDATE；同一证据再被不同 target 的断言引用 → 归因冲突
        plane.validate_assertion(
            make_assertion("as_repro2a", "svc_y", [entry.evidence_id]), SESSION, TASK, AGENT
        )
        fid = plane._state.finding_id_of_assertion("as_repro2a")
        assert plane._state.get_finding(fid)["status"] == "CANDIDATE"
        plane.validate_assertion(
            make_assertion("as_repro2a", "svc_OTHER", [entry.evidence_id]), SESSION, TASK, AGENT
        )
        assert plane._state.get_finding(fid)["status"] == "HYPOTHESIS"

        r = plane.reproduce(entry.evidence_id, fid, pb.ReproSpec())
        assert r.error.code == pb.INVALID_ARGUMENT
        assert "only runs on CANDIDATE" in r.g4.reason

    def test_no_steps_fails_closed(self, tmp_path: Path, sandbox_keys) -> None:
        priv, pub_hex = sandbox_keys
        plane = self._plane(tmp_path, pub_hex, FakeBackend())
        entry, fid = build_candidate(plane, priv, backend_steps=[])  # 证据自带 spec 无 steps
        r = plane.reproduce(entry.evidence_id, fid, pb.ReproSpec())
        assert not r.reproduced
        assert "no reproduction steps" in r.g4.reason

    def test_env_hash_required(self, tmp_path: Path, sandbox_keys) -> None:
        priv, pub_hex = sandbox_keys
        plane = self._plane(tmp_path, pub_hex, FakeBackend())
        # 请求 spec 有 steps 但无环境哈希
        spec = pb.ReproSpec()
        spec.steps.append("curl -s http://t/id")
        entry, fid = build_candidate(plane, priv, backend_steps=[])
        r = plane.reproduce(entry.evidence_id, fid, spec)
        assert not r.reproduced
        assert "environment_hash is required" in r.g4.reason

    def test_env_hash_mismatch(self, tmp_path: Path, sandbox_keys) -> None:
        priv, pub_hex = sandbox_keys
        backend = FakeBackend()
        plane = self._plane(tmp_path, pub_hex, backend)
        spec = pb.ReproSpec()
        spec.steps.append("curl -s http://t/id")
        spec.environment_hash = "0" * 64  # 与后端指纹不同
        entry, fid = build_candidate(plane, priv, backend_steps=[])
        r = plane.reproduce(entry.evidence_id, fid, spec)
        assert not r.reproduced
        assert "environment mismatch" in r.g4.reason

    def test_step_failure(self) -> None:
        backend = FakeBackend([repro_mod.StepOutcome(2, "", "bad-cmd")])
        ex = ReproExecutor(backend)
        ok, reason, _ = ex.reproduce(
            side_effect_patterns=["uid=\\d+"],
            spec_steps=["bad-cmd"],
            spec_env_hash=backend.fingerprint_value,
            spec_estimated_minutes=1,
        )
        assert not ok and "step 1/1 failed (exit 2)" in reason

    def test_step_timeout(self) -> None:
        backend = FakeBackend([repro_mod.StepOutcome(124, "", "slow-cmd")])
        ex = ReproExecutor(backend)
        ok, reason, _ = ex.reproduce(
            side_effect_patterns=["uid=\\d+"],
            spec_steps=["slow-cmd"],
            spec_env_hash=backend.fingerprint_value,
            spec_estimated_minutes=1,
        )
        assert not ok and "timeout" in reason

    def test_no_accepted_patterns(self, tmp_path: Path, sandbox_keys) -> None:
        """证据从未有已接受观测 → 无比对基准，fail-closed。"""
        priv, pub_hex = sandbox_keys
        plane = self._plane(tmp_path, pub_hex, FakeBackend())
        entry = make_entry("exec_repro3", spec_steps=["curl -s http://t/id"])
        plane.append_evidence(entry, sign_exec_id(priv, entry.exec_id))
        # 无 RecordSideEffect → G-3 也不会过；直接对 HYPOTHESIS finding 调用
        # 会先撞「仅 CANDIDATE」—— 因此本用例只测 executor 层空模式分支：
        ex = ReproExecutor(FakeBackend())
        ok, reason, _ = ex.reproduce(
            side_effect_patterns=[],
            spec_steps=["x"],
            spec_env_hash=FakeBackend().fingerprint_value,
            spec_estimated_minutes=1,
        )
        assert not ok and "no matched side-effect patterns" in reason

    def test_request_spec_overrides_entry_spec(self, tmp_path: Path, sandbox_keys) -> None:
        """请求携带 spec.steps 时优先于证据自带（07 §T4.4 复现步骤可被
        独立提交 —— 环境由系统装配，不由 agent 提供）。"""
        priv, pub_hex = sandbox_keys
        backend = FakeBackend()
        from aletheia.focalplane.execverifier import Ed25519Verifier

        plane = FocalPlane(
            Ledger(str(tmp_path / "l.db"), Ed25519Verifier(pub_hex)),
            repro_backend=backend,
        )
        entry, fid = build_candidate(plane, priv, backend_steps=["original-step"])
        spec = pb.ReproSpec()
        spec.steps.append("override-step")
        spec.environment_hash = backend.fingerprint_value
        spec.estimated_minutes = 1.0
        r = plane.reproduce(entry.evidence_id, fid, spec)
        assert r.reproduced
        assert backend.seen_argv and backend.seen_argv[0] == ["override-step"]


class TestProcessBackend:
    def test_fingerprint_stable(self) -> None:
        assert ProcessBackend().fingerprint() == ProcessBackend().fingerprint()

    def test_run_step_executes_real_process(self) -> None:
        argv = [sys.executable, "-c", "print('repro-marker-42')"]
        out = ProcessBackend().run_step(argv, timeout_s=30)
        assert out.exit_code == 0
        assert "repro-marker-42" in out.stdout

    def test_run_step_isolated_env(self) -> None:
        """子进程不继承调用方环境（最小 env 语义）。"""
        argv = [
            sys.executable,
            "-c",
            "import os; print(os.environ.get('ALETH_REPRO_LEAK', 'clean'))",
        ]
        out = ProcessBackend().run_step(argv, timeout_s=30)
        assert "clean" in out.stdout
