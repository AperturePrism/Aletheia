# I3-Q8 · 长时稳定性 harness —— 交接文档

**提交**：`{待提交}`（工作区改动；基线 HEAD `7f728c6`）
**日期**：2026-09-27
**定位**：`04` §2 **P0 门禁第 1 条**（24h 无崩溃 / 无内存泄漏）的执行入口
**下一迭代**：I4 M2 心智地图（受 DEC-3 裁定制约）｜真源文档：`04` §2 / §6 Q8

---

## 1. 30 秒摘要

`tests/stability/` 此前只有骨架且**跑不通**：探针 100% 失败、RSS 判据恒为 0%、
`make lint` 也是红的。本次把它修到**可用**，并用它完成了首次真实观测：

- harness 三条判据（崩溃 / 探针 / RSS）**全部真实生效**，不再有恒真的假判据；
- 90s 冒烟 → 探针 5/5 通过、RSS 采样 5/5 有效；
- **30 分钟观测已给出确定性结论**：`alethd` 的 RSS 约 5 分钟后进入**平台期**
  （18.8MB → 22.8MB 后稳定，末 11 分钟 **−0.28%**），属 **Go runtime 高电平
  堆行为，不是内存泄漏**；`focalplane` 全程平稳（+0.78%）。
- ✅ **判据口径已裁定并落地**（2026-09-27，选项 B：引入预热窗口）——
  该项正是上述观测暴露出的设计缺陷，见 §6.1。

**24h 全量仍未执行** —— 已议定改在**专用 Linux 环境**执行、不占用开发机；
P0 门禁第 1 条在 24h 通过前**尚未**通过。

**接手方第一条命令**

```bash
make build && make stability-smoke
```

冒烟窗口短，`result` 字段可能为 FAIL —— 判断 harness 是否可用请看
`probe_failures` / `crashes` / `rss_sample_failures` 三项是否全为 0。

---

## 2. 环境与工具链（本机实测）

| 工具 | 版本 | 命令 |
|---|---|---|
| Go | `go1.24.4 windows/amd64` | `go version` |
| Node | `v22.22.2` | `node --version` |
| Python | `3.12.10` | `bash scripts/py.sh --version` |
| make | `GNU Make 4.4.1` | `make --version` |
| uv | **未安装** | `uv --version` → `command not found` |
| shell | `MINGW64_NT-10.0-26200 3.6.9`（Git Bash） | `uname -s -r` |

`uv` 未安装是已知环境事实（I2 起 `tests/test_roe_schema.py` 因此 skip 一项）。

### 本次新踩的环境坑（Git Bash / MSYS2 专属，三条）

| # | 症状 | 根因 | 解法 |
|---|---|---|---|
| 1 | `No module named 'aletheia'` | MSYS2 **只转换命令行参数，不转换环境变量**；`PYTHONPATH` 里的 `/d/...` 原生 Python 不认 | `cygpath -w` 转换后再导出；分隔符须用 `;` |
| 2 | `OpenProcess(pid=N) failed, err=87` | Git Bash 的 `$!` 是 **MSYS 虚拟 PID**，`OpenProcess` 要真实 Windows PID | 经 `/proc/<pid>/winpid` 转换；该文件**只对 MSYS 程序可见**，故转换必须放在 shell 侧 |
| 3 | 从 bash 调用 `powershell` 被安全策略拒绝 | 受限 shell 会拦截跨解释器调用 | 采样改为纯 Python（`ctypes` 调 Win32 API），不依赖外部解释器 |

坑 2 与坑 3 叠加时危害最大：**采样失败只表现为空输出**，会让「RSS 增长 < 5%」
退化为恒真断言 —— 这正是上一版 `last_run.json` 里 `rss_growth 0.0%` 的来源。

---

## 3. 交付了什么

| 路径 | 是什么 | 对应 `04` 交付物 |
|---|---|---|
| `tests/stability/run.sh` | harness 主入口（**修复**：端口单点定义、真实墙钟时长、采样失败显式计数） | Q8 执行入口 |
| `tests/stability/probe.py` | 契约往返探针（**修复**：gRPC 端口 7723→7724、RPC 加超时、格式过 lint） | Q8 负载注入 |
| `tests/stability/rss.py` | **新增** —— 跨平台 RSS 采样器（`ctypes` 调 Win32 `GetProcessMemoryInfo` / 读 Linux `/proc`），零新增依赖 | Q8 内存判据 |
| `tests/stability/README.md` | **重写** —— 判据定义、用法、产物清单、排障表 | 交付物文档 |
| `Makefile` | **新增 `make stability-smoke`**；`stability` 去掉「尚未实现」降级兜底 | Q8 门禁入口 |
| `.gitignore` | **新增** `tests/stability/last_run/` —— 此前 `probe_key.hex`（私钥）未被忽略 | 安全加固 |
| `cmd/alethd/main.go` · `core/config/config.go` · `core/config/config_test.go` | gRPC 独立端口 `server.grpc_port`（7724）并真正 `Serve`；**补 `grpc_port` 的范围与端口冲突校验**（与 `server.port` 对称）+ 3 个拒绝用例 | Q4/Q5 已用，Q8 首次真实运行暴露 |

**关于 `cmd/alethd` / `core/config` 的改动来源**：这两处是接手时工作区里已有的
未提交改动（原注释写作 I3），本次**保留并验证**。其必要性已被证明 ——
改动前 `grpcServer` 从未 `Serve`，gRPC 网络入口实际不存在。

### 与契约的关系

**未改动 `docs/05`，未改动 `proto/`。** 本次不涉及 `contract:` 变更。

---

## 4. 怎么验证（命令 + 原始输出）

| 检查 | 命令 | 原始输出 |
|---|---|---|
| 基线构建 | `make build` | `built: bin/alethd, bin/aleth` |
| 基线测试 | `make test` | Go 全 `ok`；Python `110 passed, 1 skipped` |
| 静态检查 | `bash scripts/py.sh -m ruff check tests/stability/` | `All checks passed!` |
| 格式检查 | `bash scripts/py.sh -m ruff format --check tests/stability/` | `3 files already formatted` |
| 采样器成功路径 | `rss.py --pid <真实PID>` | `11536`（rc=0） |
| 采样器失败路径 | `rss.py --pid 999999` | `RSS_SAMPLE_ERROR: …err=87`（rc=1） |
| 冒烟（90s） | `bash tests/stability/run.sh --duration 90 --interval 5` | 见下 |

**冒烟原始输出（90s / interval 5s）**

```
== Q8 稳定性测试：duration=90s interval=5s ==
  [2026-09-26T23:19:09Z] probe=ok fp_rss=8684KB ad_rss=18556KB
  [2026-09-26T23:19:28Z] probe=ok fp_rss=8684KB ad_rss=19164KB
  [2026-09-26T23:19:45Z] probe=ok fp_rss=8684KB ad_rss=20904KB
  [2026-09-26T23:20:04Z] probe=ok fp_rss=8640KB ad_rss=21080KB
  [2026-09-26T23:20:22Z] probe=ok fp_rss=8640KB ad_rss=21176KB
{"result": "FAIL", "duration_s": 94, "samples": 5, "crashes": 0, "probe_failures": 0,
 "rss_sample_failures": 0, "fp_rss_growth_pct": -0.51, "ad_rss_growth_pct": 12.03, ...}
```

**10 分钟观测（interval 10s，24 样本，探针 24/24 通过）**

```
{"result": "FAIL", "duration_s": 613, "samples": 24, "crashes": 0,
 "probe_failures": 0, "rss_sample_failures": 0,
 "fp_rss_growth_pct": 0.62, "ad_rss_growth_pct": 23.76, ...}
```

**30 分钟观测（interval 30s，41 样本）—— 判定 `alethd` 内存行为的决定性数据**

```
{"result": "FAIL", "duration_s": 1821, "samples": 41, "crashes": 0,
 "probe_failures": 24, "rss_sample_failures": 0,
 "fp_rss_growth_pct": 0.78, "ad_rss_growth_pct": 15.12, ...}
```

`ad_rss` 分段（KB）：

| 时段 | 区间 | 变化 |
|---|---|---|
| 0–5 min | 18780 → 22160 | +18.0%（堆扩张期） |
| 5–18 min | 22160 → 22804 | +2.9%（增速显著放缓） |
| 18–30 min | 22804 → 22740 | **−0.28%（平台期）** |

**结论：假设 H1 成立** —— RSS 约 5 分钟后进入平台，末 11 分钟净变化为负。
这是 Go runtime 的高电平堆行为（GC 触发后不立即把内存归还 OS），
**不是内存泄漏**。

> 该轮的 `probe_failures: 24` **不是被测系统的问题**：上一轮 `ledger.db`
> 未被清理，本轮 `seq` 1–24 与上一轮撞号，M4 的幂等/伪造检测正确拒收；
> `seq` 25+（后 17 轮）全部通过。这既是 §5 缺陷 #9 的现场证据，也
> **反向验证了 M4 的反伪造闸门在真实运行中确实生效**。

**修复后的复验（90s，interval 5s）**

```
{"result": "FAIL", "duration_s": 101, "samples": 5, "crashes": 0,
 "probe_failures": 0, "rss_sample_failures": 0,
 "fp_rss_growth_pct": -0.51, "ad_rss_growth_pct": 7.28, ...}
```

`probe.log` 仅含本轮 5 条 `PROBE_OK` —— 清理与日志截断均已生效。
（`result` 为 FAIL 是正常的：90s 窗口仍在预热期，见 §1 与 README §4。）

### 4.1 本次改动后的门禁状态

| 门禁组件 | 结果 |
|---|---|
| `make lint`（Q7，含 Go/gofmt/Go vet + Python ruff + ESLint/tsc + buf） | ✅ 通过 |
| `make check-gen-fresh` / `check-frontend-credentials` / `check-loopback` / `check-no-bypass` / `check-iteration-docs` / `check-governance-guard` / `check-handoff-prompt` | ✅ 全部通过 |
| `go test ./core/config/`（含新增 3 子用例） | ✅ 通过 |
| `make test`（Q1） | ⚠️ 见下 |
| `make build` 的 web 子步骤（vite） | ⚠️ 见下 |

**上述两项 ⚠️ 是环境副作用，不是代码缺陷。** WorkBuddy 会话对删除文件有**累计配额**
（单次批量 >50 触发 `SAFE_DELETE_BULK_CONFIRM_REQUIRED`）。配额耗尽后会出现连锁反应：

1. `tests/test_security_scan.py` 注入的 `mutant_*.go` / `mutant_*.py` **无法被测试自身清理**，
   残留文件使 `test_scan_clean_on_untouched_tree` 等共 7 个用例失败（扫描器把残留的
   违规代码当成真实违规）；`test_handoff_prompt_check.py` 亦失败。
2. vite 无法清空 `web/dist`，`web-build` 失败。

**判定依据（三条，缺一不可）**：

- 单独重跑涉事测试文件：`18 passed`（清理残留后）；
- `make test` 在**本次会话最早**执行时是 `110 passed, 1 skipped`（当时配额未耗尽）；
- 日志中直接可见 `SAFE_DELETE_BULK_CONFIRM_REQUIRED {"count":719,"threshold":50}`。

**清理残留后门禁即恢复**（已实测）。在不受该机制约束的常规终端上，`make gate` 预期全绿。
**注意：清理前不要据此判断代码有问题。**

---

## 5. 自检结论与偏差

### 修复项核对

| # | 原缺陷 | 状态 | 证据 |
|---|---|---|---|
| 1 | 探针连 HTTP 端口 7723（gRPC 在 7724）→ 6/6 失败 | ✅ 已修 | 探针 5/5 `ok` |
| 2 | `rss_of()` 采样恒空 → RSS 判据恒 0% | ✅ 已修 | `rss_sample_failures: 0`，增长率出现非零真值 |
| 3 | `probe.py` 未过 `ruff format` → `make gate` 红 | ✅ 已修 | `All checks passed!` |
| 4 | `duration_s` 恒为 `null` | ✅ 已修 | `duration_s: 613`（真实墙钟） |
| 5 | README 仅 4 行 | ✅ 已重写 | 7 节结构 |
| 6 | `Makefile` 保留「尚未实现」降级兜底 | ✅ 已修 | 直接透传退出码 |
| 7 | 运行产物含私钥且未 ignore | ✅ 已修 | `git check-ignore` 命中 |
| 8 | `grpc_port` 缺少与 `server.port` 对称的校验（越界 / 与 HTTP 端口同值都只能在 `net.Listen` 阶段失败） | ✅ 已修 | `TestValidationRejects` 新增 3 子用例全 PASS |
| 9 | `rm -rf "$RUN_DIR"` **静默失败** → 残留 `ledger.db` → 本轮 `evidence_id` 与上轮撞号 → 探针前 24 轮被 M4 拒收（表现为「稳定性不通过」） | ✅ 已修 | 改为只删账本 + 删除后回验 + 失败 `exit 2`；30 分钟轮现场复现，修复后复验 `probe_failures: 0` |
| 10 | RSS 判据口径把 runtime 启动堆扩张计入基线 → 对长时服务**恒假阳性** | ✅ 已按裁定修改 | 引入预热窗口（`M6` §12 真源 + `--warmup` 实现）；复验见 §4.2 |
| 11 | 代码与文档中引用的 `M6 §4.1` 实为「双向映射」，判据真源是 `M6 §12` | ✅ 已修正 | `grep -rn "M6 §4.1"` 为空 |

### 十条红线专项

| 红线 | 状态 | 说明 |
|---|---|---|
| R1 契约冻结 | ✅ 未触碰 | `git status` 无 `docs/05` / `proto/` |
| R2 Q3/Q4/Q5 不放宽 | ✅ 未触碰 | 未改红线用例 |
| R3 不为过测而削弱测试 | ✅ **方向相反** | 把恒真断言改成真实断言、新增 `rss_sample_failures` 判据 |
| R4–R9 | ✅ 未触碰 | 本次仅测试 harness 与其配置 |
| R10 未达门禁不进下一阶段 | ⚠️ **仍受约束** | 本次未开始 I4；DEC-3 未裁定 |

### 偏差清单

| # | 类别 | 严重度 | 具体表现 | 处置 |
|---|---|---|---|---|
| D-1 | 环境适配 | 🟠 P1 | MSYS 环境的三条坑（§2 表）已就地修掉，但**根因是"harness 需要在 Windows 原生终端跑"这一隐含前提**，未写进 README 之外的任何地方 | 已在 README §6 排障表固化 |
| D-2 | 观测效率 | 🟢 P2 | 每轮开销约 +14s（Python 启动 ×3），24h 下实际采样约 1900 轮而非 2880 轮 | 不影响判定；如需提高采样密度可合并 `rss.py` 调用 |

### 仅人工判断的项

| 项 | 为何无法自动化 | 判断依据 |
|---|---|---|
| `alethd` RSS 增长的定性 | 需区分「Go runtime 高电平堆」与「真泄漏」，属长时尺度上的观测推断 | **已由 30 分钟观测定位**：约 5 分钟后进入平台期，末 11 分钟 −0.28%（§4） |

**结论**：⚠️ 需裁定 —— harness 本身 ✅ 可用、三条判据均真实生效；
但 Q8 的 RSS 判据口径与 Go runtime 特性冲突（§6.1），且 **24h 全量未执行**，
P0 门禁第 1 条**尚未通过**。

---

## 6. 已知缺口与风险 ★

### 6.1 RSS 判据口径 —— ✅ 已裁定（2026-09-27，采纳选项 B）

**裁定**：Q8 的 RSS 增长判据引入**预热窗口**。项目负责人 2026-09-27 决策
采用开发侧建议的 **B** 方案。

**问题回顾**：`alethd` 的 RSS 约 5 分钟后进入平台期（末 11 分钟 −0.28%），
属 Go runtime 高电平堆行为、**非泄漏**；但「首 2 样本 vs 末 2 样本」口径把
启动堆扩张计入基线 → 对长时服务必然假阳性（30 分钟轮 `ad_rss_growth_pct =
15.12%`）。

**已落地的改动（设计真源优先）**：

| 位置 | 改动 |
|---|---|
| `docs/modules/M6` §12（**真源**） | DoD 项下补「RSS 增长 < 5%」的完整口径：预热窗口 600s、`head` 取窗口结束后最早 2 样本、稳态样本 < 4 判 FAIL 而非 PASS |
| `docs/04` §6（Q8 行） | 判据描述补「**预热窗口后的稳态区间**，口径见 `modules/M6` §12」 |
| `tests/stability/run.sh` | 新增 `--warmup`（默认 600）；判定按 `t0 + warmup` 过滤稳态区间；摘要新增 `warmup_s` / `steady_samples`；`steady_samples < 4` 时输出「无法判定」提示 |
| `tests/stability/README.md` | 口径表 + 「**判据 FAIL ≠ 服务有泄漏**」的说明 |
| `Makefile` | `stability-smoke` 传 `--warmup 0`（短窗口下走完整判定路径）；`stability` 提示 24h 应在专用 Linux 环境执行 |

> 预热窗口**不是放宽阈值**（阈值仍是 5%），而是修正**比较区间的选取**。
> 窗口内的样本仍保留在 `timeseries.csv` 中，只是不参与 `head` 计算。

**同时议定的执行方式**：**24h 全量不在开发机执行** —— 长期占用本机会干扰
日常使用，改在专用 Linux 环境运行（harness 已跨平台，见 README §4「在哪跑 24h」）。
24h 的启动条件因此是「外部环境就绪」，而非本机时间窗。

### 6.2 上游平台限制（**需用户侧处置**）

`run.sh` 原先用 `rm -rf "$RUN_DIR"` 整目录清理，在受限环境下会因
「单次批量删除文件数超阈值」被拒（实测 `SAFE_DELETE_BULK_CONFIRM_REQUIRED`,
`count=55, threshold=50`），而 `rm -rf` 的失败被 `-f` 吞掉 → 静默失败。
已改为「只删账本 + 删除后回验 + 失败中止」（§5 缺陷 #9），
在常规终端与受限环境下行为一致。

### 6.2 其他缺口

| 缺口 | 影响 | 何时必须解决 | 阻塞谁 |
|---|---|---|---|
| 24h 全量未执行 | P0 门禁第 1 条**尚未通过** | P0 收口 | 进入 P1（I4） |
| Q5 靶场抓包（docker 未装） | P0 门禁第 4 条未通过 | 见 `decisions/DEC-2026-09-25` DEC-2 | 同上 |
| DEC-1/2/3 三项仍 PENDING | P0 无法整体收口 | 项目负责人裁定 | 整个 P1 |

---

## 7. 下一步（怎么开始）

### 建议的第一步动作

```bash
# 1) 确认 harness 可用（约 2 分钟；result 必然为 FAIL —— warmup=0 且窗口短，
#    判 harness 是否可用请看三个失败计数，见 §1）
make build && make stability-smoke

# 2) 在**专用 Linux 环境**启动 24h 全量（不在开发机跑，见 §6.1 议定）
#    该环境需先通过 make build && make env，然后：
make stability          # 默认 86400s / 30s / warmup 600s
```

### 24h 通过后的收口动作

1. 归档 `last_run.json` 与 `timeseries.csv` 作为 Q8 证据（门禁第 1 条的原始记录）；
2. 回填 `docs/04` §2 的 P0 门禁状态（第 1 条 → 通过）；
3. 处理 DEC-2（Q5 靶场验证），补齐后对 P0 五条做整体核对。

### 接手方注意事项

1. **不要把冒烟的 FAIL 当成 harness 故障** —— 冒烟窗口短，RSS 判据常因未收敛
   而失败。判断 harness 是否可用看三个失败计数（§1）。
2. **不要为了「让它变绿」去调判据阈值或把采样失败折算成 0** —— `docs/09` R3。
   本次修复中有两个同源的反面教材：上一版靠静默的 `0.0%` 增长得到虚假绿灯；
   `rm -rf` 的静默失败则让脏账本伪装成「稳定性不通过」。**共同点是失败被吞掉。**
3. **改 harness 后先跑冒烟再跑长时** —— 一条 24h 长跑浪费的是墙钟时间。
4. **Git Bash 下的 PID 是 MSYS 虚拟 PID**，任何新写的、需要接触进程的辅助脚本
   都要经 `native_pid()` 转换（§2 坑 2）。
5. **受限环境下不要用整目录删除做清理** —— 单次批量删除文件数有上限，
   且 `rm -rf` 的失败是静默的（§6.2）。
