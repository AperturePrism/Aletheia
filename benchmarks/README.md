# benchmarks/ —— 公开基准适配器

> **当前状态：本目录没有任何真实任务清单。**
> P2 阶段门禁（"公开基准可复现分数"）**仍未通过**。
> 原因：本机**没有 docker**，四个基准都需要起靶场才能跑。
> 这不是被测系统的问题，是环境缺失 —— 但门禁不会因为"原因是环境的"就变绿。

真源：`docs/04` §P2 阶段门禁 ｜ `docs/modules/M9-评测框架.md` §5.1

---

## 1. 这里有什么

| 路径 | 内容 |
|---|---|
| `agents/src/aletheia/harness/manifest_adapter.py` | **通用** manifest 驱动型适配器（四个基准共用） |
| `agents/tests/harness/test_manifest_adapter.py` | 16 个用例（重点在"坏清单被拒"） |
| `README.md`（本文件） | manifest 规范 + 缺什么 |

**尚未有**：四个基准的 `tasks.json`。原因见 §4 —— 我不会编造 ground truth。

---

## 2. 为什么是 manifest 而不是四个适配器类

`adapter.BenchmarkAdapter` 的文档已说明：CyBench / CVE-Bench / XBOW / HTB
真正不同的只有两处 —— 任务清单从哪来、靶场怎么起停。其余（任务结构、评分
口径、状态重置、失败归档）完全相同。

写成四个类会产生一个具体风险：**四份近似代码各自漂移**（例如只有其中
一份实现了"每次评测后重置"），而 `M9` §8 的重置要求是全局性质的，
不该取决于某个适配器作者记不记得。

因此：加一个基准 = 加一个 `tasks.json`。

---

## 3. manifest 规范

文件位置必须是 `benchmarks/<benchmark>/tasks.json`，且 `benchmark`
字段必须与目录名一致（加载器会校验，防止把 HTB 的清单塞进 cybench 目录）。

```json
{
  "benchmark": "cybench",
  "version": "2026.10",
  "source": "https://<官方发布物地址>@<提交或版本>",
  "target": "http://127.0.0.1:3000",
  "requires_docker": true,
  "tasks": [
    {
      "task_id": "cybench-web-001",
      "description": "对 192.0.2.10 做信息收集并定位管理接口",
      "difficulty": "easy",
      "ground_truth": ["/admin"],
      "category": "web"
    }
  ]
}
```

| 字段 | 必需 | 说明 |
|---|---|---|
| `benchmark` | ✅ | 必须等于目录名 |
| `version` | ✅ | 数据集版本 —— **分数要能追溯到具体版本**（M9 §2 可复现性清单） |
| `source` | ✅ | 官方发布物地址（含版本/提交），便于他人复核 |
| `tasks` | ✅ | 非空数组 |
| `target` | ⬜ | 靶场入口；非空时 `setup()` 会做 TCP 可达性探测 |
| `requires_docker` | ⬜ | 默认 `true` |
| `tasks[].task_id` | ✅ | 唯一 |
| `tasks[].description` | ✅ | 给被测系统的输入 |
| `tasks[].ground_truth` | ✅ | **非空**。没有它就无法算精确率/召回率/假阴性 |
| `tasks[].difficulty` | ⬜ | 分难度统计（M9 §5.1 要求） |
| `tasks[].category` | ⬜ | 分场景统计（"不混合"承诺） |

### 为什么 `ground_truth` 是强制的

一个没有标准答案的任务**无法产生可复现的分数，只能产生"感觉"**。
加载器会直接拒绝空 ground truth，而不是"先收下再说" ——
因为一旦收下，报告里就会出现"0/0 任务通过"这种看起来像数据、
实际什么都没有的结果。

---

## 4. 缺什么（以及我不会做什么）

### 4.1 我不会编造 ground truth

四个基准的任务与标准答案来自各自官方发布物。**凭空写一份"看起来像
CyBench"的清单，比留空更糟**：它会产出无法追溯来源的分数，而分数一旦
出现在报告里，就没人会再追问它从哪来。

因此本目录保持为空，直到有人导入真实数据。

### 4.2 导入真实数据需要什么

```bash
# 以 CyBench 为例（具体命令取决于官方发布形态）
# 1. 取得官方数据集（含每题的标准答案）
# 2. 转成本节 §3 的 manifest 形态，写入 benchmarks/cybench/tasks.json
# 3. 校验：加载器会拒绝任何不合规项
.venv/Scripts/python.exe -c "
from pathlib import Path
from aletheia.harness.manifest_adapter import load_manifest
m = load_manifest(Path('benchmarks/cybench/tasks.json'))
print(m.benchmark, m.version, len(m.tasks), 'tasks')
"
```

### 4.3 靶场（`labs/`）

四个自建靶场同样为空，且**我不会伪造 compose 文件**：

* 写一份没跑过的 compose，等于交付一个"看起来能起"的靶场 ——
  而 `07` §T6 还要求镜像按 **digest** 固定，我拿不到真实 digest；
* 没验证过的编排与没有编排，在下一次接手时是同一回事，但前者更危险
  （它看起来已完成）。

`labs/` 的设计约束（供实现者参考）：镜像必须 digest 固定 · 容器内无宿主
凭据 · 每次评测后必须重建（M9 §8 状态重置）· 仅回环可达（Q13）。

---

## 5. 未实跑时的行为（已实现并有测试）

| 情形 | 行为 |
|---|---|
| `target` 非空但不可达 | `setup()` 抛 `TargetUnavailable`，说明缺什么 |
| 需要重置靶场 | `reset()` 抛 `NotImplementedError`，指向 `scripts/labs-up.sh` 重建 |
| 清单不合规 | `load_manifest` 抛 `ManifestError`，指出具体哪一条 |

三条都是**显式失败**，没有"静默降级为空跑"。理由一致：
空跑产出的 0 分与"系统真的很差"无法区分。

---

## 6. 复现

```bash
.venv/Scripts/python.exe -m pytest agents/tests/harness/ -q
# → 全部通过（含 16 个 manifest 用例；不需要 docker）
```
