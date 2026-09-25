"""FocalPlane 门面 —— LedgerService 的核心逻辑（T4.3/T4.5/T4.6/T4.7）。

把账本（ledger.py）、四道闸门、Finding 状态机、归因双向校验与幻觉计数
组合成一个组件。gRPC server（server.py）与测试都只面向这个门面。

闸门语义的精确化（modules/M4 §4.2 vs §4.3 图的张力，以 §4.2 为准）：

    G-1 失败（证据未绑定有效执行）→ **不产生 Finding**，幻觉计数 +1（D2 自言自语）
    G-2 失败（无证据支撑）       → **REJECTED**（记录原因，供 Refiner 学习）
    G-3 失败（无强证据）         → 停在 **CANDIDATE**（不是 REJECTED —— 弱证据
                                   是「待补强」，不是「已证伪」）
    G-4 失败（复现不过）         → 回退 CANDIDATE（I7 T4.9；I2 阶段 G-4 显式 pending，
                                   CONFIRMED 跃迁代码就绪但不可达）

归因双向校验（M4 §4.4 / 04 §I2 关键决策③）：证据首次被某断言引用时绑定
target；同一证据被**不同 target** 的断言引用 → ATTRIBUTION_MISMATCH →
回滚 finding 至 HYPOTHESIS（05 §1.3 熔断语义）+ P0 告警 + 人工复核标记。

「不产出断言」（M4 §3.2 N1）：本组件只校验调用方传入的断言 —— 断言的
生产者在 M5 Agent。这是制度设计，不是实现便利。
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from aletheia.focalplane import ids, patterns
from aletheia.focalplane.ledger import Ledger
from aletheia.gen.aleth.v1 import aletheia_pb2 as pb

# 幻觉熔断默认值（M4 §4.6；可注入覆盖，见 FocalPlane 构造参数）。
DEFAULT_AGENT_THRESHOLD = 3
DEFAULT_SESSION_RATIO = 0.1
# 比例熔断的最小样本量：样本不足时比例无统计意义（1/1 = 100% 会立即
# 熔断整场，压过 per-agent 阈值语义），此时只按 agent 阈值判定。
MIN_SESSION_SAMPLES = 10

_SCHEMA_VERSION = 1


class FocalPlaneError(Exception):
    """焦平面操作失败基类（P-4：显式向上传播）。"""


class UnknownFindingError(FocalPlaneError):
    """finding_id 不存在。"""


@dataclass(frozen=True)
class P0Alert:
    """P0 告警事件（04 §I2 DoD③：归因错误触发 P0 告警）。

    消费方注入回调（audit log / 告警通道）；I3 起 M6 审计日志承接。
    """

    code: str  # 如 "ATTRIBUTION_MISMATCH"
    finding_id: str
    detail: str
    at_ns: int


@dataclass(frozen=True)
class GateOutcome:
    """单道闸门的内部结论（映射 proto GateResult）。"""

    passed: bool
    reason: str = ""
    evidence_refs: tuple[str, ...] = ()

    def to_proto(self) -> pb.GateResult:
        return pb.GateResult(
            passed=self.passed,
            reason=self.reason,
            evidence_refs=self.evidence_refs,
        )


class FocalPlane:
    """LedgerService 核心逻辑。一个实例 = 一个会话域的账本 + 状态机。"""

    def __init__(
        self,
        ledger: Ledger,
        *,
        agent_hallucination_threshold: int = DEFAULT_AGENT_THRESHOLD,
        session_hallucination_ratio: float = DEFAULT_SESSION_RATIO,
        on_p0_alert: Callable[[P0Alert], None] | None = None,
    ) -> None:
        self._ledger = ledger
        self._agent_threshold = agent_hallucination_threshold
        self._session_ratio = session_hallucination_ratio
        self._on_p0_alert = on_p0_alert
        self._lock = threading.Lock()
        # 状态机表与账本共用同一 SQLite 文件（同库不同表；互不写对方列）。
        self._state = _StateStore(ledger.db_path)

    # ------------------------------------------------------------------
    # 证据入库（G-1 内建于 Ledger.append，此处只做透传 —— 无旁路）
    # ------------------------------------------------------------------

    def append_evidence(self, entry, signed_exec_id, *, idempotent: bool = False):
        return self._ledger.append(entry, signed_exec_id, idempotent=idempotent)

    # ------------------------------------------------------------------
    # RecordSideEffect（观测登记；G-3 的原料）
    # ------------------------------------------------------------------

    def record_side_effect(
        self, observation, session_id: str, task_id: str
    ) -> pb.RecordSideEffectResult:
        """登记副作用观测。

        三道关：exec_id 必须对应账本内真实证据（观测必须绑定真实执行）；
        命中模式由**服务端重算**（请求里的 matched_pattern 是自述，不采信）；
        未命中任何模式 → accepted=False（不计入 G-3 强度，但记录留痕）。
        """
        _ = (session_id, task_id)  # 审计字段；I3 审计日志落地时写入
        result = pb.RecordSideEffectResult()
        if not observation.exec_id:
            result.error.code = pb.EVIDENCE_INVALID
            result.error.message = "observation.exec_id is empty"
            return result
        evidence = self._find_evidence_by_exec(observation.exec_id)
        if evidence is None:
            result.accepted = False
            result.error.code = pb.EVIDENCE_INVALID
            result.error.message = (
                "observation.exec_id does not match any ledger evidence; "
                "unbound observation cannot count as side effect"
            )
            return result

        hits = patterns.find_hits(observation.kind, observation.observation)
        if not hits:
            result.accepted = False
            result.matched_pattern = ""
            result.error.message = f"no strong-evidence pattern matched for kind {pb.ObserverKind.Name(observation.kind)}"
        else:
            result.accepted = True
            result.matched_pattern = ",".join(h.name for h in hits)

        observation_id = ids.new_observation_id()
        self._state.record_side_effect(
            observation_id=observation_id,
            evidence_id=evidence.evidence_id,
            kind=pb.ObserverKind.Name(observation.kind),
            observation=observation.observation,
            matched_pattern=result.matched_pattern,
            exec_id=observation.exec_id,
            accepted=result.accepted,
        )
        result.observation_id = observation_id
        return result

    # ------------------------------------------------------------------
    # ValidateAssertion（四道闸门 + 状态机 + 归因 + 幻觉）
    # ------------------------------------------------------------------

    def validate_assertion(
        self,
        assertion,
        session_id: str,
        task_id: str,
        agent_id: str,
    ) -> pb.ValidateAssertionResult:
        """四道闸门校验。返回含各闸门结果与 resulting_status 的完整结论。"""
        _ = task_id  # 审计字段；I3 审计日志落地时写入
        result = pb.ValidateAssertionResult()
        self._state.bump_assertion_counter(session_id)

        refs = tuple(assertion.supporting_evidence_ids)

        # ---- G-1 执行绑定：引用的证据必须真实存在于账本 ----
        # （账本内的证据全部经过 append 路径的 G-1 验签 —— 不存在
        # 「在账本里但未验签」的证据；因此 G-1 在此等价于引用存在性。
        # 引用不存在的证据 = 引用了一个虚构的执行 = D2 自言自语。）
        missing = [rid for rid in refs if self._ledger.get(rid) is None]
        if missing or not refs:
            reason = (
                "no supporting evidence ids" if not refs else f"evidence not in ledger: {missing}"
            )
            result.g1_exec_bound.CopyFrom(GateOutcome(False, reason, refs).to_proto())
            result.g2_assertion.CopyFrom(GateOutcome(False, "g1 failed; not evaluated").to_proto())
            result.g3_strength.CopyFrom(GateOutcome(False, "g1 failed; not evaluated").to_proto())
            result.g4_reproduction.CopyFrom(self._g4_pending().to_proto())
            result.resulting_status = pb.HYPOTHESIS
            err = result.errors.add()
            err.code = pb.EVIDENCE_INVALID
            err.message = f"G-1 failed: {reason}"
            self._state.record_hallucination(session_id, agent_id, "G1_FAILED", err.message)
            return result
        result.g1_exec_bound.CopyFrom(
            GateOutcome(
                True, "all referenced evidence bound to verified executions", refs
            ).to_proto()
        )

        # ---- G-2 断言校验：支撑证据与断言语境一致 ----
        # 证据的副作用观测 exec 归属一致性（观测必须属于被引用的执行）。
        g2_reasons = []
        for rid in refs:
            entry = self._ledger.get(rid)
            if entry is None:  # g1 已过滤缺失引用；仍到不了时是内部不变量破坏
                raise FocalPlaneError(f"internal invariant broken: evidence {rid!r} vanished")
            for obs in entry.side_effects:
                if obs.exec_id and obs.exec_id != entry.exec_id:
                    g2_reasons.append(
                        f"evidence {rid} carries side effect bound to foreign exec {obs.exec_id}"
                    )
        if g2_reasons:
            result.g2_assertion.CopyFrom(GateOutcome(False, "; ".join(g2_reasons), refs).to_proto())
            result.g3_strength.CopyFrom(GateOutcome(False, "g2 failed; not evaluated").to_proto())
            result.g4_reproduction.CopyFrom(self._g4_pending().to_proto())
            result.resulting_status = pb.REJECTED
            err = result.errors.add()
            err.code = pb.EVIDENCE_INVALID
            err.message = "G-2 failed: " + "; ".join(g2_reasons)
            self._reject_or_record(assertion, target=assertion.target_entity_id, reason=err.message)
            return result
        result.g2_assertion.CopyFrom(
            GateOutcome(True, "supporting evidence present and consistent", refs).to_proto()
        )

        # ---- 归因双向校验（T4.6，先于状态落定）----
        mismatch = self._bind_and_check_attribution(assertion)
        if mismatch is not None:
            finding_id = self._state.finding_id_of_assertion(assertion.assertion_id)
            if finding_id:
                self._rollback_finding(finding_id, mismatch)
            else:
                # 冲突断言以 HYPOTHESIS 记录并直接进人工复核队列 —— 不给 CANDIDATE。
                finding_id = self._state.upsert_finding(
                    assertion=assertion,
                    to_status=pb.HYPOTHESIS,
                    reason=f"ATTRIBUTION_MISMATCH: {mismatch}",
                    needs_review=True,
                )
            # 共享该证据的其他 finding 一并标记复核（归因已被质疑，保守面）。
            for rid in assertion.supporting_evidence_ids:
                for fid in self._state.finding_ids_bound_via_evidence(rid):
                    self._state.mark_needs_review(fid)
            result.g3_strength.CopyFrom(
                GateOutcome(False, "attribution mismatch; not evaluated").to_proto()
            )
            result.g4_reproduction.CopyFrom(self._g4_pending().to_proto())
            result.resulting_status = pb.HYPOTHESIS
            err = result.errors.add()
            err.code = pb.ATTRIBUTION_MISMATCH
            err.message = mismatch
            self._emit_p0("ATTRIBUTION_MISMATCH", finding_id, mismatch)
            return result

        # ---- G-3 证据强度：被引用证据上是否存在「已接受的」强观测 ----
        # 按执行（exec_id）聚合：断言引用的证据集合上，全部已接受的强观测。
        referenced_execs = []
        for rid in refs:
            entry = self._ledger.get(rid)
            if entry is None:
                raise FocalPlaneError(f"internal invariant broken: evidence {rid!r} vanished")
            referenced_execs.append(entry.exec_id)
        accepted_by_evidence = self._state.accepted_observations_for_execs(referenced_execs)
        if accepted_by_evidence:
            result.g3_strength.CopyFrom(
                GateOutcome(
                    True,
                    "accepted side-effect observations: " + ",".join(accepted_by_evidence),
                    refs,
                ).to_proto()
            )
        else:
            result.g3_strength.CopyFrom(
                GateOutcome(
                    False,
                    "no accepted strong-evidence observation (weak/absent); capped at CANDIDATE",
                    refs,
                ).to_proto()
            )

        # ---- G-4 独立复现（I7 T4.9 交付；显式 pending，不是通过）----
        result.g4_reproduction.CopyFrom(self._g4_pending().to_proto())

        # ---- 状态落定 ----
        status = self._decide_status(result)
        finding_id = self._state.upsert_finding(
            assertion=assertion,
            to_status=status,
            reason=_transition_reason(result),
        )
        result.resulting_status = status
        _ = finding_id
        return result

    # ------------------------------------------------------------------
    # TraceFinding（证据链视图的数据源）
    # ------------------------------------------------------------------

    def trace_finding(self, finding_id: str) -> pb.TracedEvidenceChain:
        chain = pb.TracedEvidenceChain()
        finding = self._state.get_finding(finding_id)
        if finding is None:
            raise UnknownFindingError(f"finding {finding_id!r} not found")
        chain.finding_id = finding_id
        assertions, evidence, side_effects = self._state.collect_chain(finding_id, self._ledger)
        chain.assertions.extend(assertions)
        chain.evidence.extend(evidence)
        chain.side_effects.extend(side_effects)
        errors, consistent = self._verify_attribution(chain)
        chain.attribution_consistent = consistent
        chain.attribution_errors.extend(errors)
        return chain

    # ------------------------------------------------------------------
    # 幻觉计数（T4.7）
    # ------------------------------------------------------------------

    def report_hallucination(
        self, session_id: str, task_id: str, agent_id: str, hallucination_type: str, detail: str
    ) -> pb.HallucinationState:
        _ = task_id
        self._state.record_hallucination(session_id, agent_id, hallucination_type, detail)
        return self._hallucination_state(session_id, agent_id)

    def hallucination_state(self, session_id: str, agent_id: str) -> pb.HallucinationState:
        return self._hallucination_state(session_id, agent_id)

    # ------------------------------------------------------------------
    # Reproduce（I7 T4.9 —— 显式 pending，绝不静默假装通过）
    # ------------------------------------------------------------------

    def reproduce(self, evidence_id: str, finding_id: str, spec) -> pb.ReproduceResult:
        result = pb.ReproduceResult()
        result.reproduced = False
        result.g4.passed = False
        result.g4.reason = (
            "G-4 independent reproduction is delivered in I7 (T4.9); "
            "I2 explicitly does not fabricate a reproduction verdict"
        )
        result.error.code = pb.ERROR_CODE_UNSPECIFIED
        result.error.message = result.g4.reason
        _ = (evidence_id, finding_id, spec)
        return result

    # ------------------------------------------------------------------
    # 内部
    # ------------------------------------------------------------------

    def _g4_pending(self) -> GateOutcome:
        return GateOutcome(
            False,
            "G-4 reproduction pending (I7 T4.9); CONFIRMED is unreachable in I2 by design",
        )

    def _decide_status(self, result: pb.ValidateAssertionResult) -> pb.FindingStatus.V:
        """状态机（M4 §4.2/§4.3）：G-2 过 → CANDIDATE；G-3+G-4 都过 → CONFIRMED。

        I2 阶段 g4 恒为 pending → CONFIRMED 不可达 —— 这是**设计**而非缺失。
        """
        if not result.g2_assertion.passed:
            return pb.REJECTED
        if result.g3_strength.passed and result.g4_reproduction.passed:
            return pb.CONFIRMED
        return pb.CANDIDATE

    def _bind_and_check_attribution(self, assertion) -> str | None:
        """证据首次被引用时绑定 target；同证据异 target → 张冠李戴。"""
        for rid in assertion.supporting_evidence_ids:
            existing = self._state.attribution_target(rid)
            if existing is not None and existing != assertion.target_entity_id:
                return (
                    f"evidence {rid} already attributed to target {existing!r}; "
                    f"assertion targets {assertion.target_entity_id!r}"
                )
            self._state.bind_evidence(rid, assertion.target_entity_id, assertion.assertion_id)
        return None

    def _verify_attribution(self, chain: pb.TracedEvidenceChain):
        """链上复核：每条证据的绑定 target 与引用它的断言 target 一致。"""
        errors: list[pb.Error] = []
        consistent = True
        for e in chain.evidence:
            bound = self._state.attribution_target(e.evidence_id)
            if bound is None:
                continue
            for a in chain.assertions:
                if e.evidence_id in a.supporting_evidence_ids and a.target_entity_id != bound:
                    consistent = False
                    errors.append(
                        pb.Error(
                            code=pb.ATTRIBUTION_MISMATCH,
                            message=(
                                f"evidence {e.evidence_id} bound to {bound!r} but asserted "
                                f"for {a.target_entity_id!r}"
                            ),
                        )
                    )
        return errors, consistent

    def _reject_or_record(self, assertion, *, target: str, reason: str) -> None:
        self._state.upsert_finding(
            assertion=assertion,
            to_status=pb.REJECTED,
            reason=reason,
        )
        _ = target

    def _rollback_finding(self, finding_id: str, reason: str) -> None:
        """ATTRIBUTION_MISMATCH 的回滚：至 HYPOTHESIS（05 §1.3）+ 人工复核标记。"""
        self._state.transition(
            finding_id,
            pb.HYPOTHESIS,
            reason=f"ATTRIBUTION_MISMATCH: {reason}",
            actor="focalplane",
        )
        self._state.mark_needs_review(finding_id)

    def _emit_p0(self, code: str, finding_id: str, detail: str) -> None:
        alert = P0Alert(code=code, finding_id=finding_id, detail=detail, at_ns=time.time_ns())
        if self._on_p0_alert is not None:
            self._on_p0_alert(alert)

    def _find_evidence_by_exec(self, exec_id: str) -> pb.EvidenceEntry | None:
        for e in self._ledger.iter_entries():
            if e.exec_id == exec_id:
                return e
        return None

    def _hallucination_state(self, session_id: str, agent_id: str) -> pb.HallucinationState:
        state = pb.HallucinationState()
        state.session_id = session_id
        count = self._state.hallucination_stats(session_id, agent_id)
        state.hallucination_count = count
        state.threshold = self._agent_threshold
        state.agent_circuit_open = count >= self._agent_threshold
        # session 比例熔断：proto 无独立字段，以 error.message 显式披露（不静默）。
        # 最小样本门槛：比例判定在小样本下过敏（第 1 次断言即 100%），
        # 样本 < MIN_SESSION_SAMPLES 时只按 per-agent 阈值判定（M4 §8 阈值校准）。
        session_count = self._state.session_hallucination_count(session_id)
        session_total = self._state.session_assertion_total(session_id)
        if session_total >= MIN_SESSION_SAMPLES and session_count >= max(
            1, int(self._session_ratio * session_total)
        ):
            state.agent_circuit_open = True
            state.error.code = pb.EVIDENCE_INVALID
            state.error.message = (
                f"session hallucination ratio exceeded ({session_count} >= "
                f"{self._session_ratio:.0%} of {session_total} assertions); circuit open"
            )
        return state


class _StateStore:
    """Finding 状态机 / 归因绑定 / 幻觉计数的存储。

    表分两类：
    - ``evidence`` / ``finding_transitions`` / ``evidence_bindings`` /
      ``side_effects`` / ``hallucinations``：append-only 审计面
    - ``findings``：状态机当前态（每次变更必然伴随一条 transition 审计）
    """

    def __init__(self, db_path: str) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS findings (
                finding_id       TEXT PRIMARY KEY,
                target_entity_id TEXT NOT NULL,
                status           TEXT NOT NULL,
                needs_review     INTEGER NOT NULL DEFAULT 0,
                created_at_ns    INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS finding_assertions (
                assertion_id   TEXT PRIMARY KEY,
                finding_id     TEXT NOT NULL,
                assertion_bytes BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS finding_transitions (
                seq         INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id  TEXT NOT NULL,
                from_status TEXT NOT NULL,
                to_status   TEXT NOT NULL,
                reason      TEXT NOT NULL,
                actor       TEXT NOT NULL,
                at_ns       INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence_bindings (
                evidence_id      TEXT NOT NULL,
                target_entity_id TEXT NOT NULL,
                assertion_id     TEXT NOT NULL,
                at_ns            INTEGER NOT NULL,
                PRIMARY KEY (evidence_id, assertion_id)
            );
            CREATE TABLE IF NOT EXISTS side_effects (
                seq             INTEGER PRIMARY KEY AUTOINCREMENT,
                observation_id  TEXT NOT NULL UNIQUE,
                evidence_id     TEXT NOT NULL,
                kind            TEXT NOT NULL,
                observation     TEXT NOT NULL,
                matched_pattern TEXT NOT NULL,
                exec_id         TEXT NOT NULL,
                accepted        INTEGER NOT NULL,
                at_ns           INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS hallucinations (
                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                agent_id   TEXT NOT NULL,
                h_type     TEXT NOT NULL,
                detail     TEXT NOT NULL,
                at_ns      INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS session_counters (
                session_id TEXT PRIMARY KEY,
                assertions INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        self._conn.commit()

    # ---- findings ----

    def upsert_finding(
        self, assertion, *, to_status, reason: str, needs_review: bool = False
    ) -> str:
        with self._lock:
            now = time.time_ns()
            finding_id = self.finding_id_of_assertion(assertion.assertion_id)
            if finding_id is None:
                finding_id = ids.new_finding_id()
                self._conn.execute(
                    "INSERT INTO findings(finding_id, target_entity_id, status, needs_review, created_at_ns)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (finding_id, assertion.target_entity_id, "HYPOTHESIS", int(needs_review), now),
                )
                self._conn.execute(
                    "INSERT INTO finding_assertions(assertion_id, finding_id, assertion_bytes)"
                    " VALUES (?, ?, ?)",
                    (
                        assertion.assertion_id,
                        finding_id,
                        assertion.SerializeToString(deterministic=True),
                    ),
                )
                self.transition(finding_id, to_status, reason=reason, actor="focalplane", now=now)
                self._conn.commit()
                return finding_id
            # 既有 finding（重复校验/状态推进）
            self.transition(finding_id, to_status, reason=reason, actor="focalplane", now=now)
            self._conn.commit()
            return finding_id

    def transition(
        self, finding_id: str, to_status, *, reason: str, actor: str, now: int | None = None
    ) -> None:
        at = now if now is not None else time.time_ns()
        row = self._conn.execute(
            "SELECT status FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            raise UnknownFindingError(f"finding {finding_id!r} not found")
        from_status = row[0]
        to_name = pb.FindingStatus.Name(to_status) if isinstance(to_status, int) else to_status
        # 不可逆约束（05 §5.1）：CONFIRMED → CANDIDATE 仅允许 ATTRIBUTION_MISMATCH
        # 或人工复核触发；其余情况拒绝。
        if (
            from_status == "CONFIRMED"
            and to_name == "CANDIDATE"
            and "ATTRIBUTION_MISMATCH" not in reason
            and "MANUAL_REVIEW" not in reason
        ):
            raise FocalPlaneError(
                f"illegal transition CONFIRMED→CANDIDATE without ATTRIBUTION_MISMATCH/manual review: {reason!r}"
            )
        self._conn.execute(
            "INSERT INTO finding_transitions(finding_id, from_status, to_status, reason, actor, at_ns)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (finding_id, from_status, to_name, reason, actor, at),
        )
        self._conn.execute(
            "UPDATE findings SET status = ? WHERE finding_id = ?",
            (to_name, finding_id),
        )

    def mark_needs_review(self, finding_id: str) -> None:
        self._conn.execute(
            "UPDATE findings SET needs_review = 1 WHERE finding_id = ?", (finding_id,)
        )
        self._conn.commit()

    def get_finding(self, finding_id: str):
        row = self._conn.execute(
            "SELECT finding_id, target_entity_id, status, needs_review FROM findings"
            " WHERE finding_id = ?",
            (finding_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "finding_id": row[0],
            "target_entity_id": row[1],
            "status": row[2],
            "needs_review": bool(row[3]),
        }

    def finding_id_of_assertion(self, assertion_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT finding_id FROM finding_assertions WHERE assertion_id = ?", (assertion_id,)
        ).fetchone()
        return row[0] if row else None

    def collect_chain(self, finding_id: str, ledger: Ledger):
        """finding → assertions → evidence → side effects（证据链视图数据源）。"""
        rows = self._conn.execute(
            "SELECT assertion_bytes FROM finding_assertions WHERE finding_id = ?",
            (finding_id,),
        ).fetchall()
        assertions = []
        seen_evidence: dict[str, pb.EvidenceEntry] = {}
        for (blob,) in rows:
            a = pb.Assertion()
            a.ParseFromString(blob)
            assertions.append(a)
            for rid in a.supporting_evidence_ids:
                e = ledger.get(rid)
                if e is not None:
                    seen_evidence[rid] = e
        evidence = list(seen_evidence.values())
        side_effects = []
        for e in evidence:  # 逐条参数化查询：无动态 SQL 拼接面（S608）
            for _oid, kind, obs, pattern, exec_id in self._conn.execute(
                "SELECT observation_id, kind, observation, matched_pattern, exec_id"
                " FROM side_effects WHERE exec_id = ? AND accepted = 1",
                (e.exec_id,),
            ):
                so = pb.SideEffectObservation()
                so.kind = pb.ObserverKind.Value(kind)
                so.observation = obs
                so.matched_pattern = pattern
                so.exec_id = exec_id
                side_effects.append(so)
        return assertions, evidence, side_effects

    # ---- 归因 ----

    def bind_evidence(self, evidence_id: str, target: str, assertion_id: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO evidence_bindings(evidence_id, target_entity_id, assertion_id, at_ns)"
            " VALUES (?, ?, ?, ?)",
            (evidence_id, target, assertion_id, time.time_ns()),
        )
        self._conn.commit()

    def finding_ids_bound_via_evidence(self, evidence_id: str) -> list[str]:
        """引用过该证据的全部 finding（含冲突断言以外的既有引用者）。"""
        rows = self._conn.execute(
            "SELECT fa.finding_id FROM evidence_bindings eb"
            " JOIN finding_assertions fa ON fa.assertion_id = eb.assertion_id"
            " WHERE eb.evidence_id = ?",
            (evidence_id,),
        ).fetchall()
        return [r[0] for r in rows]

    def attribution_target(self, evidence_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT target_entity_id FROM evidence_bindings WHERE evidence_id = ? LIMIT 1",
            (evidence_id,),
        ).fetchone()
        return row[0] if row else None

    # ---- 副作用 ----

    def record_side_effect(
        self,
        *,
        observation_id: str,
        evidence_id: str,
        kind: str,
        observation: str,
        matched_pattern: str,
        exec_id: str,
        accepted: bool,
    ) -> None:
        self._conn.execute(
            "INSERT INTO side_effects(observation_id, evidence_id, kind, observation,"
            " matched_pattern, exec_id, accepted, at_ns) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                observation_id,
                evidence_id,
                kind,
                observation,
                matched_pattern,
                exec_id,
                int(accepted),
                time.time_ns(),
            ),
        )
        self._conn.commit()

    def accepted_observations_for_execs(self, exec_ids: list[str]) -> list[str]:
        if not exec_ids:
            return []
        out: list[str] = []
        for exec_id in exec_ids:  # 逐条参数化查询：无动态 SQL 拼接面（S608）
            rows = self._conn.execute(
                "SELECT observation_id, matched_pattern FROM side_effects"
                " WHERE exec_id = ? AND accepted = 1",
                (exec_id,),
            ).fetchall()
            out.extend(f"{oid}:{pattern}" for oid, pattern in rows)
        return out

    # ---- 幻觉 ----

    def record_hallucination(
        self, session_id: str, agent_id: str, h_type: str, detail: str
    ) -> None:
        self._conn.execute(
            "INSERT INTO hallucinations(session_id, agent_id, h_type, detail, at_ns)"
            " VALUES (?, ?, ?, ?, ?)",
            (session_id, agent_id, h_type, detail, time.time_ns()),
        )
        self._conn.commit()

    def hallucination_stats(self, session_id: str, agent_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM hallucinations WHERE session_id = ? AND agent_id = ?",
            (session_id, agent_id),
        ).fetchone()
        return int(row[0])

    def session_hallucination_count(self, session_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM hallucinations WHERE session_id = ?", (session_id,)
        ).fetchone()
        return int(row[0])

    def bump_assertion_counter(self, session_id: str) -> None:
        self._conn.execute(
            "INSERT INTO session_counters(session_id, assertions) VALUES (?, 1)"
            " ON CONFLICT(session_id) DO UPDATE SET assertions = assertions + 1",
            (session_id,),
        )
        self._conn.commit()

    def session_assertion_total(self, session_id: str) -> int:
        row = self._conn.execute(
            "SELECT assertions FROM session_counters WHERE session_id = ?", (session_id,)
        ).fetchone()
        return int(row[0]) if row else 0


def _transition_reason(result: pb.ValidateAssertionResult) -> str:
    parts = []
    for name in ("g1_exec_bound", "g2_assertion", "g3_strength", "g4_reproduction"):
        g = getattr(result, name)
        parts.append(f"{name}={'pass' if g.passed else 'fail'}")
    return "; ".join(parts)
