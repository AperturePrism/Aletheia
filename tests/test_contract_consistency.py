"""契约一致性测试 —— Go 生成物、Python 生成物与 docs/05 的一致性。

这是 I0 最重要的测试，理由来自 docs/05 §0 C1：

    **契约定死，实现可变。** 双语言（Go/Python）切换、模块重写均不得
    改动本文档定义的结构与语义。

双语言架构最大的风险不是"某侧写错"，而是**两侧悄悄漂移**：
Go 侧加了字段、Python 侧没跟上，接口调用时在运行期才炸 ——
而且是在扫描目标的时候炸。

因此本测试把"契约一致"变成可执行断言，对应三项 CI 门禁：

    Q10 契约一致性  代码接口与 `05` 文档一致
    Q14 前端类型生成  TS 类型由 Protobuf 生成（由 web 侧的 lint 承担）

**本测试不 mock 被验证对象**（docs/09 §R3）：它直接读生成产物本身，
不经过任何封装。
"""

from __future__ import annotations

import pathlib
import re

import pytest

# 本文件位于 <repo>/tests/，因此 REPO_ROOT 是其父目录。
# 用 parents[1] 而非拼相对路径 —— 相对路径依赖 pytest 的调用目录，
# 而 `make test` 与开发者手跑时的 cwd 经常不同。
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PROTO_DIR = REPO_ROOT / "proto"
CONTRACT_DOC = REPO_ROOT / "docs" / "05-接口契约与数据模型.md"

PROTO_FILE = PROTO_DIR / "aleth" / "v1" / "aletheia.proto"

GO_GEN = REPO_ROOT / "core" / "api" / "aleth" / "v1"
TS_GEN = REPO_ROOT / "web" / "src" / "gen"
PY_GEN = REPO_ROOT / "agents" / "src" / "aletheia" / "gen"

# 契约源（唯一真源）。任一侧生成物都必须与它对应。
assert PROTO_FILE.exists(), f"proto contract missing: {PROTO_FILE}"


# ---------------------------------------------------------------------------
# 工具：从 proto 抽取结构
# ---------------------------------------------------------------------------


def _proto_text() -> str:
    return PROTO_FILE.read_text(encoding="utf-8")


def _proto_messages() -> dict[str, set[str]]:
    """抽取 proto 中的 message 名 → 字段名集合。"""
    text = _proto_text()
    messages: dict[str, set[str]] = {}
    # 匹配 message X { ... }（非嵌套简化处理：按花括号配对）。
    for m in re.finditer(r"^message\s+(\w+)\s*\{", text, re.MULTILINE):
        name = m.group(1)
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        body = text[start : i - 1]
        fields: set[str] = set
        fields = set()
        for fm in re.finditer(
            r"^\s*(?:repeated\s+)?(?:map\s*<[^>]+>\s*)?\w+\s+(\w+)\s*=\s*\d+\s*;",
            body,
            re.MULTILINE,
        ):
            fields.add(fm.group(1))
        messages[name] = fields
    return messages


def _proto_services() -> dict[str, set[str]]:
    """抽取 proto 中的 service 名 → RPC 名集合。"""
    text = _proto_text()
    services: dict[str, set[str]] = {}
    for m in re.finditer(r"^service\s+(\w+)\s*\{", text, re.MULTILINE):
        name = m.group(1)
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        body = text[start : i - 1]
        rpcs = {r.group(1) for r in re.finditer(r"rpc\s+(\w+)\s*\(", body)}
        services[name] = rpcs
    return services


# ---------------------------------------------------------------------------
# Q14：前端 TS 类型由 Protobuf 生成，禁止手工维护重复类型
# ---------------------------------------------------------------------------


@pytest.mark.redline
def test_ts_generated_types_exist() -> None:
    """web/src/gen 下必须有生成产物，且带 "DO NOT EDIT" 标记。

    "DO NOT EDIT" 是 ts-proto 在文件头写的。它的存在同时说明两件事：
    ① 文件确实是生成物；② 工具链期望人不改它。
    """
    candidates = list(TS_GEN.rglob("*.ts"))
    assert candidates, f"no generated TypeScript found under {TS_GEN}"

    main = next(t for t in candidates if t.name == "aletheia.ts")
    header = main.read_text(encoding="utf-8")[:400]
    assert "DO NOT EDIT" in header, (
        f"{main} does not look like a generated file (missing DO NOT EDIT). "
        "Q14 requires frontend types to be generated from Protobuf."
    )


@pytest.mark.redline
def test_ts_generation_covers_all_proto_messages() -> None:
    """proto 中每个 message 都必须在生成产物中出现。

    漏一个 message 意味着某个能力在前端没有类型可用 ——
    开发者会"手工补一个"（违反 Q14），或直接弃用该能力。
    """
    ts = "".join(p.read_text(encoding="utf-8") for p in TS_GEN.rglob("*.ts"))
    messages = _proto_messages()
    missing = sorted(
        name
        for name in messages
        if f"export interface {name} " not in ts and f"export const {name} " not in ts
    )
    assert not missing, (
        f"proto messages missing from generated TypeScript: {missing}. "
        "Run `make proto` and check proto/buf.gen.yaml."
    )


@pytest.mark.redline
def test_no_handwritten_duplicate_contract_types() -> None:
    """web/src 中不得有手工声明的契约类型。

    这是 Q14 的静态检查侧。web/eslint.config.js 里有一条
    no-restricted-syntax 规则做同样的事（编译期），
    这里是 Python 侧的兜底 —— 两层都要有，因为 ESLint 可能被关掉，
    而测试不会（docs/09 §R2：不得为了让测试通过而削弱测试本身）。
    """
    src_files = [p for p in (REPO_ROOT / "web" / "src").rglob("*.ts*") if "gen" not in p.parts]
    # 与 eslint.config.js 中的名单保持一致。
    contract_types = {
        "EvidenceEntry",
        "Assertion",
        "Finding",
        "ContextBundle",
        "ScopeCheckResult",
        "EvidenceSpectrum",
        "ToolInvocation",
        "RawOutputRef",
        "SpectrumLine",
        "EntityDraft",
        "ParseQuality",
        "Entity",
        "Relation",
        "Provenance",
        "SideEffectObservation",
        "ReproSpec",
        "GateResult",
        "TerminationRequest",
        "TerminationDecision",
        "Task",
        "TaskGraph",
        "Report",
        "BudgetState",
        "SignedExecId",
        "LeakHit",
        "TokenMapping",
    }
    offenders: list[str] = []
    pattern = re.compile(r"\b(?:export\s+)?interface\s+(\w+)|type\s+(\w+)\s*=\s*\{")
    for path in src_files:
        text = path.read_text(encoding="utf-8")
        for m in pattern.finditer(text):
            name = m.group(1) or m.group(2)
            if name in contract_types:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {name}")
    assert not offenders, (
        "hand-written contract types found (Q14 violation): "
        + ", ".join(offenders)
        + " — import from web/src/gen instead."
    )


# ---------------------------------------------------------------------------
# 跨语言一致性：Go ↔ Python
# ---------------------------------------------------------------------------


@pytest.mark.redline
def test_go_and_python_generated_from_same_contract() -> None:
    """Go 与 Python 生成物都必须存在。

    docs/05 §0 C1：双语言切换不得改动契约。若一侧缺失，
    说明"契约定死"这条在实践中没有被执行。
    """
    go_msgs = list(GO_GEN.rglob("*.pb.go"))
    py_msgs = list(PY_GEN.rglob("*_pb2.py"))
    assert go_msgs, f"no generated Go protobuf under {GO_GEN}; run `make proto`"
    assert py_msgs, f"no generated Python protobuf under {PY_GEN}; run `make proto`"


@pytest.mark.redline
def test_go_generation_covers_all_proto_messages() -> None:
    """proto 中每个 message 都必须出现在 Go 生成物中。"""
    go = "".join(p.read_text(encoding="utf-8", errors="replace") for p in GO_GEN.rglob("*.pb.go"))
    messages = _proto_messages()
    missing = sorted(name for name in messages if f"type {name} struct" not in go)
    assert not missing, f"proto messages missing from generated Go: {missing}"


@pytest.mark.redline
def test_python_generation_covers_all_proto_messages() -> None:
    """proto 中每个 message 都必须出现在 Python 生成物中。"""
    py = "".join(p.read_text(encoding="utf-8", errors="replace") for p in PY_GEN.rglob("*_pb2.py"))
    messages = _proto_messages()
    missing = sorted(name for name in messages if name not in py)
    assert not missing, f"proto messages missing from generated Python: {missing}"


@pytest.mark.redline
def test_all_services_present_in_both_generations() -> None:
    """05 定义的每个 service 在 Go / Python 生成物中都要有对应注册函数。"""
    services = _proto_services()
    assert services, "no services found in proto — is the contract file intact?"

    go = "".join(
        p.read_text(encoding="utf-8", errors="replace") for p in GO_GEN.rglob("*_grpc.pb.go")
    )
    py = "".join(
        p.read_text(encoding="utf-8", errors="replace") for p in PY_GEN.rglob("*_pb2_grpc.py")
    )

    go_missing = sorted(n for n in services if f"Register{n}Server" not in go)
    py_missing = sorted(n for n in services if f"add_{n}Servicer_to_server" not in py)

    assert not go_missing, f"services missing from generated Go: {go_missing}"
    assert not py_missing, f"services missing from generated Python: {py_missing}"


# ---------------------------------------------------------------------------
# 契约与文档一致（Q10）
# ---------------------------------------------------------------------------


@pytest.mark.redline
def test_contract_doc_declares_same_services() -> None:
    """proto 中的 service 集合与 docs/05 中出现的 service 名一致。

    docs/05 是唯一真源（README §3）。若两边不一致，要么文档漏改，
    要么有人改了 proto 没走 `contract:` PR（docs/09 §R1）。
    """
    doc = CONTRACT_DOC.read_text(encoding="utf-8")
    # 05 中 service 以 `service X {` 形式出现在 protobuf 代码块里，
    # 或以 "XxxService" 出现在正文。用前者避免把正文提到的也算进来。
    doc_services = set(re.findall(r"^service\s+(\w+)\s*\{", doc, re.MULTILINE))
    assert doc_services, "could not find any `service X {` declarations in docs/05"

    proto_services = set(_proto_services())
    only_doc = sorted(doc_services - proto_services)
    only_proto = sorted(proto_services - doc_services)
    assert not only_doc, f"services in docs/05 but not in proto: {only_doc}"
    assert not only_proto, (
        f"services in proto but not in docs/05: {only_proto} — "
        "if this is intentional, it requires a `contract:` PR (docs/09 §R1)"
    )


@pytest.mark.redline
def test_error_codes_match_contract_doc() -> None:
    """05 §1.3 的错误码必须与 proto enum 一致。

    错误码是熔断语义的载体（SCOPE_VIOLATION / BUDGET_EXCEEDED /
    EVIDENCE_INVALID / ATTRIBUTION_MISMATCH / PRIVACY_LEAK_DETECTED）。
    改一个值就等于改熔断行为，因此必须锁死。
    """
    doc = CONTRACT_DOC.read_text(encoding="utf-8")
    proto = _proto_text()

    required = {
        "SCOPE_VIOLATION": 10,
        "BUDGET_EXCEEDED": 11,
        "BUDGET_NEAR_LIMIT": 12,
        "EVIDENCE_INVALID": 13,
        "ATTRIBUTION_MISMATCH": 14,
        "PRIVACY_LEAK_DETECTED": 15,
    }
    for name, value in required.items():
        # 契约文档中声明。
        assert re.search(rf"\b{name}\b", doc), (
            f"{name} missing from docs/05 — the contract no longer documents a "
            "fail-closed error code"
        )
        # proto 中同值。
        assert re.search(rf"{name}\s*=\s*{value}\s*;", proto), (
            f"proto ErrorCode.{name} must equal {value} (docs/05 §1.3)"
        )


@pytest.mark.redline
def test_finding_status_machine_preserved() -> None:
    """05 §5.1 的状态机四态必须完整存在。

    这是项目反幻觉机制的核心（docs/09 §R4）：不存在任何其他方式
    让一个结论变成 CONFIRMED。缺一个状态 = 状态机被削弱。
    """
    proto = _proto_text()
    for status in ("HYPOTHESIS", "CANDIDATE", "CONFIRMED", "REJECTED"):
        assert re.search(rf"\b{status}\s*=\s*\d+\s*;", proto), (
            f"FindingStatus.{status} missing from proto — the 05 §5.1 state machine is incomplete"
        )
