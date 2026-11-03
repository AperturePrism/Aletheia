"""基于 manifest 的通用基准适配器（`M9` §5.1 的四个公开基准共用）。

# 为什么做成"通用 + manifest"，而不是四个独立的适配器类

`adapter.BenchmarkAdapter` 的文档已经说明：具体适配器（CyBench /
CVE-Bench / XBOW / HTB）需要外部环境（CTFd、容器编排、靶场 API）。
它们**真正不同的地方只有两处**：

1. 任务清单从哪来（含 ground truth）；
2. 靶场怎么起停。

其余全部相同：任务结构、评分口径、状态重置、失败归档。
因此把"相同"的部分实现一次，把"不同"的部分外化为 manifest ——
**加一个基准 = 加一个 manifest 文件**，而不是复制粘贴一份适配器。

这同时避免了一个具体的风险：四份近似代码会**各自漂移**
（例如只有其中一份实现了"每次评测后重置"），而 M9 §8 的重置要求
是全局性质，不该取决于某个适配器作者记不记得。

# ground truth 的来源必须显式

`BenchmarkTask.ground_truth` 是算精确率/召回率/假阴性的唯一依据。
manifest 里**必须**提供它，且加载器会拒绝空 ground truth ——
一个没有标准答案的任务无法产生可复现的分数，只能产生"感觉"。

同理，本模块**不生成**任何 ground truth。是否可信取决于 manifest 的
来源（应来自基准官方发布物，并在 manifest 里记录来源与版本）。

# 无外部环境时的行为（本仓库当前状态）

`setup()` 会检查靶场可达性；不可达时抛 `TargetUnavailableError` 并说明
**具体缺什么**。绝不静默降级为空跑 —— 空跑会产出"0/0 任务通过"
这种看起来像数据、实际什么都没有的结果。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aletheia.harness.adapter import BenchmarkAdapter, BenchmarkTask


class ManifestError(ValueError):
    """manifest 不合法（fail-closed，不做自动修补）。"""


class TargetUnavailableError(RuntimeError):
    """靶场不可达 —— 没有 docker / 没有网络 / 没有启动靶场。"""


#: manifest 必需字段。
_REQUIRED_TOP = ("benchmark", "version", "source", "tasks")
_REQUIRED_TASK = ("task_id", "description")


@dataclass(frozen=True)
class Manifest:
    """一份基准任务清单。

    `source` 与 `version` 不是为了好看：M9 §2 的可复现性清单要求
    "分数能追溯到具体的数据集版本"。没有版本号的分数，隔一个月就
    无法解释它与现在的关系。
    """

    benchmark: str
    version: str
    source: str
    tasks: tuple[BenchmarkTask, ...]
    #: 靶场入口（如 `http://127.0.0.1:3000`）。空串表示"任务自带目标"。
    target: str = ""
    #: 是否要求 docker 起靶场。
    requires_docker: bool = True


def load_manifest(path: Path) -> Manifest:
    """从 JSON 文件加载并校验 manifest。

    校验项（全部拒绝式）：
      1. 顶层字段齐全；`tasks` 非空
      2. 每个任务有 `task_id` 与 `description`，且 `task_id` 唯一
      3. 每个任务有**非空** `ground_truth`（无标准答案的任务不算基准任务）
      4. `benchmark` 与文件名一致（防止把 HTB 的清单塞进 cybench 目录）
    """
    if not path.exists():
        raise ManifestError(f"manifest 不存在：{path}")
    try:
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{path} 不是合法 JSON：{exc}") from exc

    if not isinstance(raw, dict):
        raise ManifestError(f"{path} 顶层必须是对象")

    for key in _REQUIRED_TOP:
        if key not in raw:
            raise ManifestError(f"{path} 缺少必需字段 {key!r}")

    tasks_raw = raw["tasks"]
    if not isinstance(tasks_raw, list) or not tasks_raw:
        raise ManifestError(f"{path} 的 tasks 必须是非空数组 —— 空基准无法产出可复现分数")

    tasks: list[BenchmarkTask] = []
    seen: set[str] = set()
    for i, t in enumerate(tasks_raw):
        where = f"{path} tasks[{i}]"
        if not isinstance(t, dict):
            raise ManifestError(f"{where} 必须是对象")
        for key in _REQUIRED_TASK:
            if not isinstance(t.get(key), str) or not t[key].strip():
                raise ManifestError(f"{where} 缺少非空字符串 {key!r}")
        tid = t["task_id"].strip()
        if tid in seen:
            raise ManifestError(f"{where} task_id 重复：{tid!r}")
        seen.add(tid)

        truth = t.get("ground_truth") or []
        if not isinstance(truth, list) or not truth:
            raise ManifestError(
                f"{where}({tid}) 缺 ground_truth —— 没有标准答案就无法算"
                "精确率/召回率/假阴性，只能得出「感觉」"
            )
        if not all(isinstance(x, str) and x.strip() for x in truth):
            raise ManifestError(f"{where}({tid}) 的 ground_truth 含非字符串或空值")

        tasks.append(
            BenchmarkTask(
                task_id=tid,
                description=t["description"].strip(),
                difficulty=str(t.get("difficulty", "")).strip(),
                ground_truth=tuple(x.strip() for x in truth),
                category=str(t.get("category", "")).strip(),
            )
        )

    bench = str(raw["benchmark"]).strip()
    if path.parent.name and bench != path.parent.name:
        raise ManifestError(
            f"{path} 声明 benchmark={bench!r}，但所在目录是 "
            f"{path.parent.name!r} —— 清单与目录必须一致，避免串味"
        )

    return Manifest(
        benchmark=bench,
        version=str(raw["version"]).strip(),
        source=str(raw["source"]).strip(),
        tasks=tuple(tasks),
        target=str(raw.get("target", "")).strip(),
        requires_docker=bool(raw.get("requires_docker", True)),
    )


class ManifestBenchmarkAdapter(BenchmarkAdapter):
    """从 manifest 驱动的基准适配器。

    `target` 非空时，`setup()` 会做一次 TCP 可达性探测；不可达则抛
    `TargetUnavailableError`。**这是刻意的**：靶场没起来时最糟的行为是
    "跑完一轮、报告 0 分"，因为那与"系统真的很差"无法区分。
    """

    #: 状态重置由**外部**（容器重建）承担。
    #:
    #: `driver.run_benchmark` 会读这个标记：为真时任务间跳过 `reset()` ——
    #: 因为本适配器**无法**在进程内重置靶场（见下方 `reset()`）。
    #:
    #: 这不是"假装已重置"：`scripts/labs-up.sh` 每次评测前强制 `down -v`
    #: 把靶场重建，因此重置确实发生了，只是发生在容器层而非本对象里。
    #: 若不声明它，驱动器会调用 `reset()` 并抛 `NotImplementedError`，
    #: 整场评测直接失败 —— 那会把"重置方式不同"变成"不能跑"。
    reset_is_external: bool = True

    def __init__(self, manifest_path: Path) -> None:
        self._path = Path(manifest_path)
        self._manifest = load_manifest(self._path)

    @property
    def name(self) -> str:
        return self._manifest.benchmark

    @property
    def manifest(self) -> Manifest:
        return self._manifest

    def setup(self) -> None:
        if self._manifest.target:
            _probe_target(self._manifest.target)

    def tasks(self) -> list[BenchmarkTask]:
        return list(self._manifest.tasks)

    def teardown(self) -> None:
        # manifest 驱动型适配器不拥有靶场生命周期（靶场由 compose 管理）。
        # 但接口要求实现它 —— 显式说明"无事可做"而不是留空实现让人猜。
        return None

    def reset(self) -> None:
        # M9 §8 要求每次评测后状态完全重置。manifest 驱动型适配器
        # **无法自行重置**（它不知道靶场内部状态），因此这里明确抛错，
        # 而不是假装重置成功 —— 后者会让被污染的下一轮结果看起来可信。
        raise NotImplementedError(
            "manifest 驱动型适配器不能自行重置靶场状态；"
            "请用 scripts/labs-up.sh 重建靶场容器（compose down && up），"
            "并在报告中记录重建次数。M9 §8：状态不重置的连续评测结果不可采信。"
        )


def _probe_target(target: str, timeout_s: float = 2.0) -> None:
    """探测靶场 TCP 可达性（只连不写，不产生副作用）。"""
    import socket
    import urllib.parse

    parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}")
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        raise TargetUnavailableError(f"靶场地址无法解析出 host：{target!r}")
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return
    except OSError as exc:
        raise TargetUnavailableError(
            f"靶场不可达 {host}:{port}（{exc}）。"
            "本仓库当前**没有 docker**，因此公开基准与自建靶场都无法实跑 —— "
            "这不是被测系统的问题，是环境缺失。"
        ) from exc
