# cybench —— CyBench 公开基准

> **状态（2026-11-03）：官方任务清单已入库，但本基准尚未运行、没有任何分数。**
>
> | 项 | 状态 |
> |---|---|
> | 官方任务清单 | ✅ `official_task_list.txt`（40 个任务，逐字入库，带 URL + blob sha） |
> | ground truth（flag） | ❌ 未入库（刻意）—— 见 §2 |
> | `tasks.json`（适配器可读） | ❌ 未创建 —— 缺 ground truth 时适配器必须 fail-closed |
> | 实测分数 | ❌ **无** |

真源：`docs/04` §P2 阶段门禁 ｜ `docs/modules/M9` §5.1 ｜ 上游 https://github.com/andyzorigin/cybench

---

## 1. 官方任务清单已入库

`official_task_list.txt` 是官方 `task_list.txt` 的**逐字副本**，并记录了：

* 来源 URL；
* blob sha `29941d79…`（2600+ bytes）—— 可用于校验"这份清单没被改过"；
* 获取时间与获取方式。

**为什么必须逐字 + 记来源**：P2 门禁要求"可复现"。若清单是"我们自己整理的"，
就无法证明与官方一致，复跑也就失去意义。

清单覆盖 **40** 个任务（实测 `grep -c '^benchmark/'`）。

按类别（官方路径第 4 段，实测 `awk | sort | uniq -c`）：

| 类别 | 数量 |
|---|---|
| crypto | 15 |
| web | 6 |
| reversing | 4 |
| misc | 4 |
| forensics | 4 |
| rev | 2 |
| pwn | 2 |
| hkcert `CTF-2022`（路径该段为赛事名，非类别） | 2 |
| intro | 1 |
| **合计** | **40** |

按来源组织：hackthebox 17 ｜ project-sekai-ctf 12 ｜ LosFuzzys 9 ｜ hkcert-ctf 2。

难度标注见 HackTheBox 系列（`[Very Easy]` … `[Hard]`），赛题系列本身不带难度。

> 注：`reversing` 与 `rev` 是**上游自己的两种写法**（HTB 用 `reversing`，
> GlacierCTF 用 `rev`）。我没有合并它们 —— 保持官方原样便于逐条比对。

---

## 2. 为什么不把 flag 抄进仓库

CyBench 每个任务的答案在各任务目录里，**不在** task_list。本仓库不代为搬运：

* 把 flag 抄进来后，它就从"从官方取得"变成"我们声称的"；
* 复现时应由脚本按需从官方目录读取并**校验**，而不是依赖本仓库里的一份快照。

因此 `tasks.json` 目前**不存在**：适配器的 manifest 校验要求非空
`ground_truth`，缺它必须 fail-closed。

**这一点很重要**：让缺 ground truth 的基准"照跑"，会产出一个"0 分"，
而 0 分与"系统真的很差"在报告里无法区分 —— 这正是 `manifest_adapter` 的
`TargetUnavailableError` / 校验存在的理由。

---

## 3. 为什么还没有分数（真实原因，不是没做）

**渠道限流。** 2026-11-03 实测：LLM 渠道在约 46 次调用后持续返回
`HTTP 429 Too Many Requests`，等待 1 小时后重试仍是 429。

因此本基准**未运行**。任何"CyBench 得分 X%"的表述目前都**没有依据**，
不得出现在本仓库任何文档里。

> 自建基准（`labs/bizlogic`）已有真实分数，但那是 **self_built_benchmark**，
> 不可与 CyBench 横向比较 —— 见 `labs/bizlogic/README.md` §4.3。

---

## 4. 复跑步骤（待渠道恢复后）

```bash
# 1) 官方数据集（各任务目录含题目与答案）
git clone --depth 1 https://github.com/andyzorigin/cybench /tmp/cybench

# 2) 按 official_task_list.txt 逐条生成 tasks.json
#    每条需从官方目录读取 flag 作为 ground_truth，
#    并记录该目录的 git sha（保证"这条 ground truth 来自哪一版官方数据"）

# 3) 跑（靶场需 docker；本机 docker 在 WSL2 内）
PYTHONPATH=agents/src .venv/Scripts/python.exe scripts/bench-harness.py \
    --manifest benchmarks/cybench/tasks.json --out benchmarks/cybench/last_run.json
```

第 2 步**没有捷径**：它要求逐任务读取并校验，正是为了让"分数可追溯"。

---

## 5. 与其他基准目录的关系

| 目录 | 状态 |
|---|---|
| `cybench/` | 官方清单已入库；未运行 |
| `cve-bench/` `xbow/` `htb/` | 无清单（其官方数据获取方式待确认） |
