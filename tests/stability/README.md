# 长时稳定性测试（Q8）

交付迭代：**I0–I3 引入骨架，P0 收口期补齐**
真源：`docs/04` §2（P0 门禁第 1 条）、§6 Q8 · 判据口径 `modules/M6` §4.1

---

## 1. 这条门禁要证明什么

> **连续 24h 运行，无崩溃、无内存泄漏（RSS 增长 < 5%）。**

P0 门禁五条中的第 1 条。对应核心原则 **P-1 可靠优先于能力** ——
AIxCC 的教训是「多数队伍因系统崩溃丢分，而不是因为技术不够先进」。
因此这不是质量指标，是**进入 P1 的前置条件**（`docs/09` R10）。

---

## 2. 判据（三条，全部为硬性）

| # | 判据 | 阈值 | 数据来源 |
|---|---|---|---|
| 1 | 崩溃次数 | `== 0` | 每周期 `kill -0` 探活两个被测进程 |
| 2 | 探针失败次数 | `== 0` | 每周期一轮真实 gRPC 契约往返（`probe.py`） |
| 3 | RSS 增长 | `< 5%`（两个进程各自） | 每周期采样 `fp_rss_kb` / `ad_rss_kb` |
| — | **RSS 采样失败次数** | `== 0` | 采不到即判失败，**不折算为 0%** |

第 3 条的「**采样失败 ≠ 没有泄漏**」是本 harness 的硬约定：
RSS 采样不可得时判据记为 `null` 并直接判 `FAIL`。若把空值折算成 `0.0%`，
「增长 < 5%」就变成一条永真断言 —— 那是**假绿灯**，比判定失败更危险
（`docs/10` §0「绿灯替代有效」的同一类风险）。

### RSS 增长口径（预热窗口 · 真源 `docs/modules/M6` §12）

| 项 | 定义 |
|---|---|
| 预热窗口 | 默认 **600s**（10 分钟），`--warmup <秒>` 可覆盖 |
| `head` | 预热窗口**结束后最早 2 个样本**的均值 |
| `tail` | 运行**末 2 个样本**的均值 |
| 增长率 | `(tail − head) / head × 100`，阈值 `< 5%` |
| 稳态样本 < 4 | **无法判定 → FAIL**（「缺证据」不等于「无泄漏」） |

**为什么需要预热窗口**：Go / Python runtime 在启动阶段扩张堆是**正常行为**
（Go 的 GC 只在堆增长约 100% 时触发，回收后默认不立即把内存归还 OS）。
若把启动初期计入基线，判据会对任何长时服务**恒为假阳性** —— 实测 `alethd`
按首尾法得 **+15.12%**，而其 RSS 曲线在约 5 分钟后即进入平台期
（末 11 分钟 **−0.28%**）。

> 因此：**「判据 FAIL」与「服务有泄漏」不是同一件事**。先看
> `timeseries.csv` 的曲线形状与摘要里的 `steady_samples`，再看数字。

---

## 3. 前置条件

```bash
make build          # bin/alethd 必须存在
make env            # 若尚未建好 Python venv（脚本会自动复用 scripts/py.sh 的解释器）
```

被测系统由 harness 自己拉起，**不需要**事先手动启动任何服务：

| 进程 | 角色 | 默认端口 |
|---|---|---|
| `aletheia.focalplane.server` | L3 证据账本（Python） | 7728 |
| `bin/alethd` | L0 + 代理 + gRPC/WebUI（Go） | 7723（HTTP）/ 7724（gRPC） |

> **注意 gRPC 与 HTTP 分端口。** `server.grpc_port`（7724）与 `server.port`
> （7723）是两个独立监听。探针连的是 **gRPC 端口**；两处若写岔，
> 表现为「进程都活着但探针 100% 失败」。

---

## 4. 用法

```bash
# 冒烟（90s，warmup=0 走完整判定路径）—— 改完 harness 先跑这个
make stability-smoke

# 等价的手动调用
tests/stability/run.sh --duration 90 --interval 5 --warmup 0

# P0 全量：24h（默认 86400s / 30s 间隔 / 10min 预热）
make stability

# P3 加固：143h
bash tests/stability/run.sh --duration 514800
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `--duration` | `86400` | 运行总时长（秒，**真实墙钟**基准），最小 10 |
| `--interval` | `30` | 采样**间隔下限**（秒）；每轮还叠加探针与采样开销，实际周期略长 |
| `--warmup` | `600` | **预热窗口**（秒）：RSS 判据只比较窗口结束后的稳态区间；`0` = 不做预热 |

`--duration` 按墙钟计，不按采样轮数累加 —— 否则每轮开销会让标称 24h 实际跑成 30h+。

**要让 RSS 判据可判定，需满足**：`duration ≥ warmup + 4 × (interval + 每轮开销)`。
本机实测每轮开销约 10–14s，故冒烟需显式传 `--warmup 0`，否则稳态样本必然不足。

### 在哪跑 24h

**建议在专用 Linux 环境执行，不要占用日常使用的机器。** harness 已跨平台，
Linux 侧无需适配：

| 项 | Windows（Git Bash） | Linux |
|---|---|---|
| RSS 采样 | `ctypes` 调 Win32 `GetProcessMemoryInfo` | 读 `/proc/<pid>/status` |
| PID 转换 | 经 `/proc/<pid>/winpid`（MSYS 虚拟 PID） | 恒等（无此文件即原样使用） |
| 路径 | `cygpath -w` 转换后入 `PYTHONPATH` | 原样 |

前提：该环境需具备 Go 工具链与 Python 依赖（`make build && make env` 通过）。

**退出码**：`0` = 通过；`1` = 判定失败；`2` = 环境错误（缺依赖 / 缺 `bin/alethd`）。

---

## 5. 产物（`tests/stability/last_run/`）

`last_run/` 是**每次运行的覆盖式输出目录**，不入库（`.gitignore`）。
它同时是排障入口，不要在通过后清理 —— 交接时应保留最后一轮证据。

| 文件 | 内容 |
|---|---|
| `last_run.json` | **判定摘要**：`result` / `duration_s` / `warmup_s` / `samples` / `steady_samples` / `crashes` / `probe_failures` / `rss_sample_failures` / 两个增长率 |
| `timeseries.csv` | 每周期原始采样：`ts,probe,fp_rss_kb,ad_rss_kb` |
| `probe.log` | 每轮探针输出（失败时含 `PROBE_FAIL: <原因>`） |
| `alethd.log` / `focalplane.log` | 两个被测进程的日志 |
| `alethd.yaml` | 本轮生成的配置（含实际端口） |
| `roe.yaml` | 本轮生成的临时授权凭证（目标为 RFC 5737 文档网段，不含真实目标） |
| `probe_key.hex` | 本轮临时 Ed25519 私钥（与 focalplane 公钥同对，每轮重新生成） |
| `ledger.db` | 本轮证据账本 |

---

## 6. 排障

| 现象 | 根因与处置 |
|---|---|
| `probe_failures` = 全部，`probe.log` 报 `RPC failed: StatusCode.UNAVAILABLE` | 端口错配。核对 `alethd.yaml` 的 `server.grpc_port` 与探针 `--alethd` 是否同值 |
| `probe_failures` 只在前 N 轮失败、之后自动恢复；`probe.log` 报 `evidence_id 'ev_stab_000000NN' already exists … is a forgery signal` | **上一轮的 `ledger.db` 残留**（`run.sh` 清理失败），本轮 `seq` 与上一轮撞号。**M4 的幂等/伪造检测在正常工作是好事，不是缺陷**；根因是清理失败，见下一行 |
| 启动即报「无法清理 last_run」并 `exit 2` | 有 `focalplane` / `alethd` 进程仍占用目录。确认进程退出后重试 |
| `focalplane.log` 报 `No module named 'aletheia'` | `PYTHONPATH` 未被原生 Python 接受。Git Bash（MSYS2）**只转换命令行参数，不转换环境变量**，所以 MSYS 形式的 `/d/...` 不能直接放进 `PYTHONPATH`；`run.sh` 已用 `cygpath -w` 转换，若自行改写请勿回退 |
| `crashes` > 0 且发生在启动后数秒 | 被测进程未能起来。**先看它的 `.log`**，再怀疑别的 |
| `rss_sample_failures` > 0 | `rss.py` 采样失败（stderr 有 `RSS_SAMPLE_ERROR`）。常见于进程已退出（与 `crashes` 同时非 0）；Git Bash 下的 PID 空间转换由 `run.sh` 的 `native_pid()` 负责，绕过它直接调 `rss.py` 会得到 `err=87` |
| `fp_rss_growth_pct` 为 `null` 或 `steady_samples` < 4 | **无法判定**（不是通过）：稳态样本不足，通常是 `duration` 未覆盖预热窗口。加长 `--duration` 或减小 `--warmup` |
| `ad_rss_growth_pct` 超阈值但曲线已平台化 | 预热窗口偏小（默认 600s）。看 `timeseries.csv` 的曲线形状，必要时加大 `--warmup` —— 口径见 `docs/modules/M6` §12 |
| 端口被占用 | 上一轮残留进程未回收。harness 的 `trap cleanup EXIT` 负责回收；异常中断后用 `netstat -ano | findstr 7724` 定位 |
| 缺 `bin/alethd` | `make build` |

---

## 7. 维护提示

- **改 harness 后必须跑 `make stability-smoke`**，不要直接开 24h —— 一条 24h
  的长跑浪费的是墙钟时间，而冒烟 60s 就能暴露绝大多数接线错误。
- **不要放宽这三条判据**（`docs/09` R3）：不放宽阈值、不把采样失败折算为 0、
  不用抽样代替全量。判据本身即产品。
- **预热窗口不是「放宽」**，它是判据定义的一部分（2026-09-27 裁定，真源
  `docs/modules/M6` §12）：窗口内样本只作参考、不参与比较，避免把 runtime
  的启动堆扩张误判为泄漏。改窗口需同步改真源，不要只在脚本里调参。
- 端口只在 `run.sh` 顶部单点定义，同时写入 `alethd.yaml` 与探针参数；
  新增端口请沿用此约定，不要在下游脚本里再硬编码一遍。
