"""授权凭证示例与冻结 Schema 的一致性。

对应 docs/08 §2：

    **机器可校验定义：** 完整的 JSON Schema 见 `schemas/roe.schema.json`
    （JSON Schema Draft 2020-12）。

同时对应 docs/README §2 的清单条目：
    `schemas/roe.schema.json` ｜ 授权与范围定义的机器可校验 Schema ｜**冻结**

**为什么值得一条测试**：
    示例文件（examples/roe.example.yaml）是新使用者第一个接触的东西，
    也是 I3 实现 Authorization Anchor 时的第一批输入。若它悄悄偏离了
    Schema，结果是：文档说"这样填"，代码说"不合法"，使用者在第一次启动时就
    撞墙 —— 而且撞的是一个看起来很随意的错误。

Schema 的 `examples` 字段里也有一份完整示例，但它不经 YAML 解析路径。
这里测的是**仓库中那份给人复制使用的 YAML**，那条路径才是真实的。

本测试需要 pyyaml 与 jsonschema。它们不在 dev 依赖里 ——
理由：I0 的 Python 侧不解析 YAML（那是 I3 的 ScopeKernel 的职责）。
用 uv 的临时环境跑，避免为一个测试引入两个运行时依赖
（docs/09 §5 #3：新增依赖需说明用途与替代方案）。
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_FILE = REPO_ROOT / "docs" / "schemas" / "roe.schema.json"
EXAMPLE_FILE = REPO_ROOT / "examples" / "roe.example.yaml"

pytestmark = pytest.mark.redline


def _validate_with_uv(schema_text: str, doc_text: str) -> list[str]:
    """在临时 uv 环境里跑 JSON Schema 校验，返回错误信息列表。

    用 uv 而不是本仓库 .venv：jsonschema/pyyaml 不是本项目的运行时依赖，
    装进 .venv 会让每个贡献者的环境都变重（见模块 docstring 的理由）。
    """
    script = f"""
import json, sys
import yaml
from jsonschema import Draft202012Validator

schema = json.loads({json.dumps(schema_text)})
doc = yaml.safe_load({json.dumps(doc_text)})

validator = Draft202012Validator(schema)
errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
for e in errors:
    print(f"{{list(e.path)}}: {{e.message}}")
sys.exit(1 if errors else 0)
"""
    # S603（untrusted input）/ S607（partial executable path）：
    #   执行的是 uv —— 本仓库文档指定的依赖管理工具，不是外部输入；
    #   且 uv 从 PATH 解析，本测试不假设它的安装位置。
    #   bandit 是文件级规则，无法按调用点区分来源，因此显式豁免并记录理由
    #   （docs/09 §R2：豁免需说明，不得删除规则本身）。
    argv = [
        "uv",
        "run",
        "--no-project",
        "--with",
        "jsonschema",
        "--with",
        "pyyaml",
        "python",
        "-c",
        script,
    ]
    result = subprocess.run(  # noqa: S603
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=REPO_ROOT,
        check=False,
    )
    if result.returncode not in (0, 1):
        pytest.skip(f"uv 环境不可用，无法执行 Schema 校验：{result.stderr[:200]}")
    return [line for line in result.stdout.splitlines() if line.strip()]


@pytest.mark.skipif(
    shutil.which("uv") is None, reason="uv 未安装（本测试用 uv 的临时环境加载 jsonschema）"
)
def test_example_matches_frozen_schema() -> None:
    """examples/roe.example.yaml 必须通过 roe.schema.json 校验。"""
    assert SCHEMA_FILE.exists(), f"Schema 缺失：{SCHEMA_FILE}"
    assert EXAMPLE_FILE.exists(), f"示例缺失：{EXAMPLE_FILE}"

    errors = _validate_with_uv(
        SCHEMA_FILE.read_text(encoding="utf-8"),
        EXAMPLE_FILE.read_text(encoding="utf-8"),
    )
    assert not errors, (
        "examples/roe.example.yaml 不符合 docs/schemas/roe.schema.json：\n  "
        + "\n  ".join(errors)
        + "\n\n说明：Schema 是冻结的（docs/README §2）。示例要改，"
        "不要为了让示例通过而改 Schema —— 那是 R1 违规。"
    )


def test_schema_is_frozen_and_wellformed() -> None:
    """Schema 文件本身必须存在、可解析、且是 Draft 2020-12。

    docs/08 §2 指定了 Draft 2020-12。若有人降级到 draft-07，
    某些约束（如 unevaluatedProperties）语义会变，校验结果随之不同 ——
    而这种变化在测试里很难被发现。
    """
    assert SCHEMA_FILE.exists(), f"Schema 缺失：{SCHEMA_FILE}"
    schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))

    assert schema.get("$schema", "").endswith("2020-12/schema"), (
        f"Schema 须为 Draft 2020-12（docs/08 §2），实际：{schema.get('$schema')}"
    )

    # 08 §2 声明的关键约束：authorization 至少提供 ticket_id 或 document_hash。
    auth = schema.get("$defs", {}).get("authorization", {})
    assert "anyOf" in auth, (
        "authorization 缺少 anyOf 约束 —— "
        "「ticket_id 或 document_hash 至少提供一个」（docs/08 §2）没有表达出来"
    )

    # 14 个动作枚举（08 §4）。缺一个 = 某个动作无法被授权或禁止。
    action_enum = schema.get("$defs", {}).get("actionName", {}).get("enum", [])
    required_actions = {
        "recon",
        "scan",
        "fuzz",
        "exploit",
        "post_exploit",
        "enumerate",
        "persistent_backdoor",
        "dos",
        "destructive",
        "ransomware_sim",
        "social_engineering",
        "physical",
        "supply_chain",
        "data_exfiltration",
    }
    assert set(action_enum) == required_actions, (
        f"动作枚举与 docs/08 §4 不一致。\n  缺少：{sorted(required_actions - set(action_enum))}\n"
        f"  多出：{sorted(set(action_enum) - required_actions)}"
    )
