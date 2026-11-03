"""manifest 驱动型基准适配器的测试。

# 重点：没有 ground truth 的清单必须被拒绝

`BenchmarkTask.ground_truth` 是算精确率/召回率/假阴性的唯一依据。
若加载器允许它为空，评测就会产出"0/0 任务通过"这种**看起来像数据、
实际什么都没有**的结果 —— 那正是 `docs/10` §0 说的"用绿灯替换有效性"。

因此本文件大量用例在验证"坏清单被拒"，而不是"好清单能加载"。

# 为什么用 tmp_path 而不是仓库里的真实清单

本仓库 `benchmarks/` 目前为空（无 docker，无法实跑）。测试必须能独立
验证加载器逻辑，因此用临时目录构造清单 —— 这样即便将来有了真实清单，
这些用例仍然只校验加载器本身。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aletheia.harness.manifest_adapter import (
    ManifestBenchmarkAdapter,
    ManifestError,
    TargetUnavailableError,
    load_manifest,
)


def _mk(tmp_path: Path, name: str, payload: dict) -> Path:
    """在 tmp 下建 `name/tasks.json` 并返回路径。

    目录名要等于 manifest 的 `benchmark` 字段（加载器会校验一致性）。
    """
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    p = d / "tasks.json"
    p.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return p


def _good(name: str = "cybench", **over) -> dict:
    base = {
        "benchmark": name,
        "version": "1.0.0",
        "source": "https://example.test/dataset@1.0.0",
        "tasks": [
            {
                "task_id": "t1",
                "description": "在 192.0.2.10 上找到隐藏路径",
                "difficulty": "easy",
                "ground_truth": ["/admin"],
                "category": "web",
            },
            {
                "task_id": "t2",
                "description": "利用 192.0.2.11 的 IDOR 读取他人订单",
                "difficulty": "medium",
                "ground_truth": ["order_42"],
                "category": "web",
            },
        ],
    }
    base.update(over)
    return base


# ---------------------------------------------------------------------------
# 正向
# ---------------------------------------------------------------------------


def test_loads_valid_manifest(tmp_path: Path) -> None:
    p = _mk(tmp_path, "cybench", _good())
    m = load_manifest(p)
    assert m.benchmark == "cybench"
    assert m.version == "1.0.0"
    assert len(m.tasks) == 2
    assert m.tasks[0].ground_truth == ("/admin",)
    # 来源必须保留 —— 分数要能追溯到数据集版本（M9 §2）。
    assert "1.0.0" in m.source


def test_adapter_exposes_tasks(tmp_path: Path) -> None:
    a = ManifestBenchmarkAdapter(_mk(tmp_path, "cybench", _good()))
    assert a.name == "cybench"
    assert [t.task_id for t in a.tasks()] == ["t1", "t2"]


def test_target_absent_means_no_probe(tmp_path: Path) -> None:
    # 任务自带目标时不需要探测 —— setup 不应尝试连任何东西。
    a = ManifestBenchmarkAdapter(_mk(tmp_path, "cybench", _good()))
    a.setup()  # 不应抛异常


# ---------------------------------------------------------------------------
# 反向：清单不合法必须拒绝
# ---------------------------------------------------------------------------


def test_missing_top_level_field_rejected(tmp_path: Path) -> None:
    for key in ("benchmark", "version", "source", "tasks"):
        bad = _good()
        bad.pop(key)
        with pytest.raises(ManifestError, match=key):
            load_manifest(_mk(tmp_path, "cybench", bad))


def test_empty_tasks_rejected(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="非空数组"):
        load_manifest(_mk(tmp_path, "cybench", _good(tasks=[])))


def test_task_without_ground_truth_rejected(tmp_path: Path) -> None:
    """★ 没有标准答案的任务不算基准任务。"""
    bad = _good()
    bad["tasks"][0]["ground_truth"] = []
    with pytest.raises(ManifestError, match="ground_truth"):
        load_manifest(_mk(tmp_path, "cybench", bad))


def test_task_with_missing_ground_truth_key_rejected(tmp_path: Path) -> None:
    bad = _good()
    del bad["tasks"][0]["ground_truth"]
    with pytest.raises(ManifestError, match="ground_truth"):
        load_manifest(_mk(tmp_path, "cybench", bad))


def test_duplicate_task_id_rejected(tmp_path: Path) -> None:
    bad = _good()
    bad["tasks"][1]["task_id"] = "t1"
    with pytest.raises(ManifestError, match="重复"):
        load_manifest(_mk(tmp_path, "cybench", bad))


def test_task_missing_description_rejected(tmp_path: Path) -> None:
    bad = _good()
    bad["tasks"][0]["description"] = "   "
    with pytest.raises(ManifestError, match="description"):
        load_manifest(_mk(tmp_path, "cybench", bad))


def test_benchmark_name_must_match_directory(tmp_path: Path) -> None:
    """清单放进错误目录必须被拒 —— 否则会把 HTB 的清单当 cybench 用。"""
    p = _mk(tmp_path, "htb", _good("cybench"))
    with pytest.raises(ManifestError, match="目录"):
        load_manifest(p)


def test_missing_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="不存在"):
        load_manifest(tmp_path / "nope" / "tasks.json")


def test_malformed_json_rejected(tmp_path: Path) -> None:
    d = tmp_path / "cybench"
    d.mkdir()
    p = d / "tasks.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ManifestError, match="JSON"):
        load_manifest(p)


def test_non_string_ground_truth_rejected(tmp_path: Path) -> None:
    bad = _good()
    bad["tasks"][0]["ground_truth"] = ["/admin", 42]
    with pytest.raises(ManifestError, match="ground_truth"):
        load_manifest(_mk(tmp_path, "cybench", bad))


# ---------------------------------------------------------------------------
# 靶场不可达：必须显式失败，不得空跑
# ---------------------------------------------------------------------------


def test_unreachable_target_raises(tmp_path: Path) -> None:
    """★ 靶场没起来时必须抛错，而不是"跑一轮报 0 分"。

    0 分与"系统真的很差"无法区分 —— 那是本文件最重要的一条断言。
    用一个几乎不可能有服务的本地端口（1 号端口需要 root 且通常无服务）。
    """
    p = _mk(tmp_path, "cybench", _good(target="127.0.0.1:1"))
    a = ManifestBenchmarkAdapter(p)
    with pytest.raises(TargetUnavailableError, match="不可达"):
        a.setup()


def test_reset_is_explicitly_unsupported(tmp_path: Path) -> None:
    """★ manifest 适配器不能自行重置靶场 —— 必须显式抛错。

    M9 §8 要求每次评测后状态完全重置。若这里"假装重置成功"，
    下一轮就是在被污染的状态上跑的，而结果看起来依然可信。
    """
    a = ManifestBenchmarkAdapter(_mk(tmp_path, "cybench", _good()))
    with pytest.raises(NotImplementedError, match="重置"):
        a.reset()


def test_teardown_is_a_noop_not_a_lie(tmp_path: Path) -> None:
    # 靶场生命周期归 compose 管；teardown 无事可做是正确语义。
    a = ManifestBenchmarkAdapter(_mk(tmp_path, "cybench", _good()))
    assert a.teardown() is None
