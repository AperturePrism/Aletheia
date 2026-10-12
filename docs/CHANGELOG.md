# Changelog

> 项目：**Aletheia** ｜ 团队：**AperturePrism**
> 格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。
>
> **变更类型：** `Added` 新增 ｜ `Changed` 变更 ｜ `Deprecated` 弃用 ｜ `Removed` 移除 ｜ `Fixed` 修复 ｜ `Security` 安全

---

## [Unreleased]

### OTel 接线 + 稳定性实测通过（Q8 首次给出 PASS）（2026-10-12）

**Added**
- **OTel 接线**（`cmd/alethd/obs.go`）：`core/obs`（M6 T6.2）自 I0 起
  就实现了 span 属性键、context 传播与闸门结果记录，但
  **`grep -rn 'core/obs' cmd/ core/` 返回空** —— 6.3KB 死代码、0% 覆盖。
  后果不是"少个功能"，而是 `M6` §8.2 承诺的三条可追溯链路
  （agent 为什么这么做 / 这个结论的证据是什么 / 这行数据从哪来）
  **只是声明** —— 三条链路的载体（span）从未被创建。
  - `installTracing` 默认装 **noop provider**（零遥测，D18）；
    ★ **未开启导出时 span 仍被创建与传递** —— 这让"接线正确"与
    "是否导出"解耦，否则"默认零遥测"这个最需要验证的形态反而无法验证。
  - `obsUnaryInterceptor` / `obsStreamInterceptor` 按**层归属**
    （而非方法名前缀）映射 `SpanKind`。
  - `traceStatusFor` 区分"预期内的拒绝"与"真故障"：
    `APERTURE_OVER_BUDGET` / `PermissionDenied` / `FailedPrecondition`
    是 `M3` §2.2 N4 与 `07` §8.2 认可的**正确拒绝**，标 Error 会让 trace
    充满噪声、掩盖真实故障 —— 但仍记录错误事件（"被拒绝了"要可追溯）。
- **`core/obs/obs_test.go`**：13 用例，覆盖率 **0% → 100%**。
  用 OTel 官方 `tracetest.SpanRecorder` 断言 span 真的产生
  （断言"符合 OTel 规范的 span"而非"符合我实现的 span"）；
  `TestAttributeKeysAreStable` 锁死属性键取值（它是**对外契约**，
  改名会让已导出的 trace 与看板失联）。

**Verified（Q8 的首次实测结论）**
- **稳定性测试按规格口径实测 PASS**：

```
{"result": "PASS", "duration_s": 1015, "warmup_s": 600, "samples": 45,
 "crashes": 0, "probe_failures": 0,
 "fp_rss_growth_pct": -0.4, "ad_rss_growth_pct": 2.77}
```

  方法：先跑 `warmup=60s` 得 8.04%（超阈值），再按 `M6` §12 的规格口径
  跑 `warmup=600s` 得 **2.77%（通过）**。
  **结论：此前的 8.04% 是 Go runtime 的启动堆扩张，不是泄漏** ——
  规格里的预热窗口正是为此而设（原文："Go 的 GC 只在堆增长约 100% 时
  触发，回收后默认不立即把内存归还 OS"）。

  这同时验证了该判据的**口径设计是必要的**：若无预热窗口，
  任何长时 Go 服务都会恒被判为泄漏（假阳性）。

**Fixed**
- `go.mod` 补齐 OTel 的四项说明（许可证 / 维护活跃度此前缺失），
  并写入**版本约束**：`go get` 默认拉 v1.47.0，它要求 **go >= 1.26**，
  会顶掉 CI 的 `GO_VERSION=1.24` —— 必须锁 v1.29.0。

### 修复稳定性 harness 的两个缺陷（此前从未跑通）（2026-10-12）

> `tests/stability/run.sh`（P0 门禁第 1 条 / Q8 的执行入口）在 I0 之后
> 被实现，但**从未真正跑通过** —— 一跑即崩。两个缺陷叠加，
> 且都属"不跑就发现不了"的类型。

**Fixed**
- **非 ASCII 路径下的解释器解析失败**：项目路径含 `渗透`，
  Windows 上 Python 的 stdout 默认按**控制台代码页**（本机 GBK）编码，
  `渗透` 输出为 GBK 字节 `311 370 315 270`；而 Git Bash 的文件系统层按
  **UTF-8** 解释同一串字节 → `$PY` 指向不存在的路径 → 脚本在第一处调用即崩。
  修法：`PYTHONIOENCODING=utf-8`（实测字节变为 UTF-8 的
  `346 270 227 351 200 217`，正常找到）。
- **grpcio 版本与生成代码不匹配**：生成代码要求 `grpcio>=1.84.0`，
  实际运行的解释器是 1.82.1。这是上一条的**下游症状**，
  解释器选对后自动消失（非独立缺陷）。

**Changed**
- 修正 `04` §I0 的陈旧记录：原文写「`tests/stability/run.sh` 尚未实现」，
  但该脚本后来已交付（含 `make stability` / `make stability-smoke`）。

**踩坑记录（值得留痕）**：我第一版"修法"是改用 `command -v python`
绕开非 ASCII 路径 —— 那其实把解释器换成了**系统 Python**
（无本项目 venv 依赖），于是 focalplane 启动即崩，错误信息从
"找不到文件"变成一个看起来像依赖问题的版本冲突。
**"用错解释器"比"路径乱码"更隐蔽。** 已改回绝对路径 + 强制 UTF-8。

**实测证据**（修复后冒烟 20s）：

```
focalplane serving on 127.0.0.1:7728 (ledger: .../ledger.db; ...)
probe=ok fp_rss=4944KB ad_rss=15612KB
{"result": "FAIL", ..., "crashes": 0, "probe_failures": 0, ...}
  注：steady_samples=0 < 4 —— 属「无法判定」而非「未通过」：
      运行时长不足以覆盖预热窗口（--warmup 600s）。
```

末尾的"FAIL"是**正确行为**：26s 覆盖不了 600s 预热窗口，
harness 如实说"无法判定"而非假装通过（`docs/10` §0）。

**仍未完成**：24h 全量运行（需专用环境）。

### test(redline): R9 机械化守护 —— 三个核心视图不得被省略（2026-10-12）

> R9 此前是十条红线里**唯一没有机械化守护**的一条：只出现在注释与
> ★ 图标里，没有任何检查会因"删掉一个核心视图"而失败。
> 这正是 `docs/10` §0 点名的模式 —— **用"绿灯"替换"有效性"**。

**Added**
- **`tests/test_redline_r9_core_views.py`**（8 用例，`pytest.mark.redline`）：
  - 三个核心视图的路由必须存在，**且不得指向 `NotImplementedPage`**
    （占位等价于省略）；
  - 导航里**恰好** 3 个核心视图标记；
  - ★ **标记必须正好在那三个视图上** —— 若只断言"有 3 个"，
    把别的页面标上也能过，那会让红线变成形式；
  - 核心视图不得渲染硬编码示例数据；
  - **元断言**：若有人从 `docs/09` 删掉 R9 本测试失败，
    暴露"守护的是一个已不存在的规则"。

**变异验证（4 种破坏方式全部被抓）**：

| 变异 | 结果 |
|---|---|
| 删掉「冲突矩阵视图」的核心标记 | ✅ 2 用例失败 |
| 核心视图路由改成占位页 | ✅ 1 用例失败 |
| 删掉核心视图路由 | ✅ 2 用例失败 |
| 把 ★ 标到别的页面（成本面板） | ✅ 2 用例失败 |

**接入 CI**：用与 `tests/redline/` 相同的 marker，`make redline` 与 CI 的
redline job 自动收集 —— 无需改 CI 配置，也不会因"忘记登记"而失效。
redline 门禁由 33 → **41 passed**。

### I5 补充 · 光圈连续调节 + 契约缺口登记（2026-10-12）

> `M3 §7` 的 DoD 原文是「三档光圈 **+ 连续调节**可用」，
> 而 I5 只交付了三档 —— **"连续调节"从未实现**，
> 且 I5 的回填表把整条标为"✅ 达成"（不准确，已修正）。

**Added**
- **光圈连续调节**（`core/aperture`）：
  - `Overrides` —— 三轴调节层（`max_hops` / `max_entities` /
    `depth_per_entity`）。zero value = 不覆盖，因此**三档仍是主入口**。
  - `Interpolate(from, to, t)` —— 相邻档位间的线性插值。
    要求在**相邻**档位间插值：跨越档位会跳过中间档的语义，故拒绝。
  - `validateApertureSemantics` —— 守护"恒定曝光"**物理语义**：
    不允许"深且宽"。没有它，连续调节就是绕过 `M3 §4.1` 硬约束的后门。
  - `Assembler.AssembleWithOverrides` / `Server.AssembleWithOverrides`。

**Fixed**
- **审计记录失真**（由新测试抓到）：装配路径原用 `SettingFor(stop)`，
  它总是从档位名重新解析档案，**无法表达调节后的参数** ——
  `bundle.aperture` 记成档位原值而实际装配用调节值，
  即"审计说 A、实际做 B"，比没有审计更糟。
  拆出 `settingFromProfile` 修复。该缺陷在只支持三档时不会暴露
  （档位值与实际值恒等），是连续调节把它逼出来的。
- **截断让连续调节在小整数轴上退化**：`uint32(2.5)=2` 会让
  hops 2→3 的 t=0.5 仍等于 2，该轴退化成"只有档位值"。
  改为四舍五入（t≥0.5 至少走到 to 的方向）。

**Changed**
- **修正 I5 回填中不准确的一行**：原「三档光圈 + 连续调节可用 ✅ 达成」
  拆为两行，明确标注"原 I5 只交付三档，该条当时标注达成是不准确的"。
  按维护铁律保留判断痕迹，不抹掉"曾经漏了"这个事实。

### 已登记的三个契约缺口（需 `contract:` PR，2026-10-12）

> 按 `docs/09` R1（契约冻结）**未自造 RPC、未改 `proto/`**。
> 两个缺口都在页面上显式声明，未知字段留空并说明（不编造）。

| # | 缺口 | 影响 | 位置 |
|---|---|---|---|
| 1 | `OrchestratorService` 无「读取任务图」RPC | 决策队列（页面 7）只能消费 `NextReady.blocked_reasons`，无法渲染 `06 §7.1` 的完整四要素卡片 | `04` §I6 回填；`I6-交接` D-3 |
| 2 | 全契约无「列会话」RPC（只有 `ListAdapters` 一个 List 方法） | 会话总览（页面 1）无法渲染"会话列表、状态、成本、进度、风险摘要" | `04` §I0 回填 |
| 3 | `AssembleRequest` 是 `[frozen]`，无可放光圈覆盖参数的字段 | 连续调节只能走进程内 API；gRPC 调用方与 MCP 的 `assemble_context` 只能三档 | `04` §I5 回填 |

**三个缺口的共性（第 3 个与前两个不同）**：
· 缺口 1、2 是**缺"枚举"语义** —— 契约只定义了"写"与"按已知 ID 查"。
· 缺口 3 是**缺"参数化"语义** —— 契约把可调参数固化成了枚举档位，
  于是"档位之间"的表达无处可放。

提议在同一个 `contract:` PR 里补齐：
· 只读 `GetGraph(session_id) → TaskGraph`
· 只读 `ListSessions() → repeated SessionSummary`
· `AssembleRequest` 加三个可选覆盖字段
  （`max_hops` / `max_entities` / `depth_per_entity`）

### I11 补充 · MCP 接口（双向中的提供者方向）+ 两个服务的接线（2026-10-12）

> 逐服务的装配审计发现：契约的 10 个 service 里只有 6 个真正注册到
> `registry`，且 `04 §I11` 明确要求的「MCP 接口」一直是空占位目录。
> 本轮补齐。

**Added**
- **MCP 接口**（`06` §3.4 的"作为提供者"）：
  - `core/mcp/gate.go` —— `Gate` 接口 + **默认拒绝一切**的闸门。
    MCP 的调用方是外部 agent，**不受本项目红线约束**，
    因此"未配置闸门"必须是拒绝（与 `08` §1.1「无凭证不启动」同源）。
  - `core/mcp/server.go` —— 5 个工具：`trace_finding` / `project_mind_map` /
    `assemble_context` / `list_adapters`（只读）+ `execute_tool`（有副作用）。
    **不暴露"终止会话"** —— `09` §R6 规定终止唯一入口是内部仲裁通道。
  - `core/mcp/servicegate.go` —— 闸门实现**复用既有服务**
    （ScopeService / GatewayService / GovernorService），不重新判断。
  - `cmd/aleth/mcp.go` —— `aleth mcp` 子命令（stdio transport）。
    daemon 不可达时**启动即失败**并给出可操作提示。
- **`core/gateway/server.go`** —— GatewayService 的 gRPC 适配。
  `core/gateway` 在 I3 就实现并测试了，但此前**只在进程内**被 Ingest 消费，
  从未注册为 gRPC 服务。
- **`core/focalplane` 的 TerminationProxy** —— I7 的终止仲裁已在 Python
  实现并测试（51 组伪达成用例），但 Go 侧从未装代理，
  因此 `registry.Termination` 一直是 `unimplementedTermination`。

**Changed**
- **契约的 10 个服务由 6 个装配到 9 个**。唯一未装的是 `SandboxService`
  （无实现，需容器运行时签发 `exec_id`）。

**Security / 诚实性**
- **MCP 不得有绕过闸门路径**（`06` §3.4）：`execute_tool` 走
  **本地回环 gRPC** 而非直连 Go 结构体 —— 直连会绕过 gRPC 拦截器链
  （观测 + 脱敏），"走与 WebUI 相同的路径"这句承诺就不成立。
  有测试断言**闸门拒绝时工具绝不执行**（即闸门是事前阻断而非事后告警）。
- **GatewayService：真实值不出现在任何响应里**（`07` §A2）。
  契约的 `TokenMapping` 只有 category/token/masked_value ——
  **没有可放真实值的字段**，因此这是类型系统层面的保证。
  另有测试断言"Tokenize → ScanOutbound 组合必然干净"（Q5 的核心性质）。
- **MCP 闸门范围裁决失败时不执行后续步骤** —— 越界请求不消耗预算（P-4）。

**Fixed**
- `go.mod` 此前**缺少新增依赖的四项说明**（`docs/09` §5 #3 要求
  用途/许可证/维护活跃度/替代方案）。已为 grpc-web、sqlite 与
  新增的 go-sdk 补齐，并标注**版本约束**：
  `go-sdk v1.0.0` 是最后一个 `go 1.23` 的版本，v1.1+ 要求 go >= 1.25
  会顶掉 CI 的 `GO_VERSION=1.24`。

### I12 前置 · 闭合 I6 遗留的两处缺口（2026-10-12）

> I6 交付时留下两处明确登记的缺口：熔断器只实现 6/8 类、
> 检查点的跨模块状态字段恒为空。本轮全部闭合。

**Added**
- **熔断器补齐 2 类**（`M5` §4.4 的完整 8 类）：
  - 「总运行时长上限 → 硬熔断」：新增 `MaxSessionDuration`（默认 24h，
    与 P0 门禁的稳定性测试时长对齐）与 `CircuitState.SessionElapsed`。
    判定**排在幻觉占比之前** —— 时长是确定性的客观边界，
    而幻觉占比依赖计数质量，已超时数倍的会话应先停。
  - 「单任务 token 超预算 → 强制收窄光圈重试 1 次」：
    新增 `MaxTaskTokens`（默认 50000）与 `CircuitState.CurrentTaskTokens`。
    动作是 `ActionNarrowAperture` 而**非** `ActionStopAgent` ——
    规格原文明确要求"重试 1 次，失败则 SKIPPED"。
- **检查点记录跨模块状态快照**：新增 `orchestrate.SnapshotSource` 接口
  + `cmd/alethd/checkpoint_adapter.go`（M2 的 `StateHash` → `graph_version`；
  预算状态哈希 → `budget_snapshot_hash`）。
  **`CheckpointInfo` 的两个字段不再是空的** ——
  此前恒空让检查点无法与其他模块状态对齐，而那正是
  `04 §I6 DoD③`「rewind 后证据一致性校验」需要比对的东西。

**Fixed**
- **Q12 门禁回归**：I5 的光圈页 placeholder 写了实例内网地址
  （`10.40.23.5`），触发"前端源码中出现内网 IP"检查。
  **修源码而非门禁**（`docs/09` R2）—— 改用文档安全示例域名。
  根因是 I5 提交时只跑了 `lint.sh`（不含 Q12），未跑整套门禁。
- **熔断器零阈值语义不一致**：无进展条件是六类里唯一缺
  `th.MaxNoProgressSteps > 0` 守卫的一处 ——
  零值会让"任何一步"都触发 rewind，与其余五类的"零值 = 显式禁用"
  语义相反。由新增的 `TestZeroThresholdDisablesThatCondition` 抓到。

**Security / 诚实性**
- 检查点快照取不到时**留空并告警，不编造值** ——
  伪造的版本号会让"rewind 后证据一致"看起来有据可依而实际没有
  （`docs/10` §0）。`Checkpoint.Warnings` 记录具体原因
  （"来源没版本概念"与"根本没接线"的处置完全不同）。
- 两个快照来源**各自独立**：一个失败不影响另一个（有测试覆盖）。

### I11 · M9 评测 Harness + 报告导出页（十个页面全部交付）（2026-10-12）

> 定位：`04` §I11 ｜ `modules/M9`。**M9 是项目诚实性的技术保障 ——
> 所有对外数字必须由它产生**（M9 §1）。详见
> `docs/iterations/I11-交接.md`。

**Added**
- **`agents/src/aletheia/harness/`** —— M9 评测 Harness：
  - **7 个自定义指标**（M9 §4）：幻觉率 / 证据可复现率 / 越界尝试数 /
    实体召回率 / 每个 CONFIRMED 成本 / 假阴性率 / 证据归因准确率，
    加 2 个标准指标（精确率 / 召回率）；
  - **七节报告生成**（M9 §6）：运行元信息 / 主结果 / 指标 / 成本 /
    **失败案例分析 ★** / 能力边界声明 / 附录；
  - **基准适配器框架** + `ReproducibilityManifest`（T9.1/T9.12）；
  - **引用纪律**（M9 §3）：`BaselineClaim` 强制四项标注。
- **前端报告与导出页**（`06` 页面 8）：分层浏览（主报告 / 附录 / 调试）
  + 导出 Markdown / PDF / SARIF。
  **至此 `06 §6.1` 的十个页面全部交付真实实现。**

**Changed**
- 报告在**无失败记录时显式说明**而非省略该节 —— 省略会让读者分不清
  "没有失败"与"没写失败"（M9 §2.2 N3）。
- `limitations` 为空时报告标注"⚠ 未声明任何能力边界 —— 这本身是一个
  失真信号"（M9 §11 承诺 3：不隐藏）。

**Security / 诚实性（API 层面的强制）**
- `build_report` 的 `failures` / `limitations` 是**必填关键字参数**
  （无默认值）—— 调用方不能"忘了写"。
- `HarnessRun.aggregate()` **不提供**过滤参数（有 `inspect.signature`
  断言守护）—— M9 §10："全部基准跑全量任务，不做筛选"。
- **分母为 0 时返回 `None` 而非 0** —— 填 0 会让"没测"看起来像
  "测了且结果为 0"，对幻觉率而言是**把未测量伪装成完美达成**
  （`docs/10` §0 点名的失真模式）。
- **越界用绝对计数而非比率** —— 规格目标是"0（非 0 即缺陷）"；
  越界不可稀释。
- **基线表同时收录 87%（有描述）与 7%（无描述）** —— M9 §3 的反面
  案例正是"只报 87% 而不带条件"；有专门测试守护。

### I10 · M8 业务逻辑意图建模（六类违背 + 双模式检出）（2026-10-12）

> 定位：`04` §I10 ｜ `modules/M8` §4。填补行业空白 G2 —— ARTEMIS 研究
> （2025-12，8,000 台真实企业网络）指出：**关键 Web 漏洞中约 70% 属于
> 业务逻辑缺陷，当前没有任何自主 agent 能可靠检测**。这是全行业唯一
> 被明确点名的 0% 区域。详见 `docs/iterations/I10-交接.md`。

**Added**
- **`agents/src/aletheia/intent/`** —— M8 业务逻辑意图建模：
  - **契约模型与抽取**：OpenAPI（1.0）、源码注解（0.9）、流量（0.6）、
    文档（0.4）四级置信度，每个字段带 `source` + `confidence`；
  - **六类契约违背判定**（BL1 越权 / BL2 价格篡改 / BL3 流程绕过 /
    BL4 配额绕过 / BL5 权限提升链 / BL6 竞态），全部以
    `ProbeResult` 为输入、`Violation` 为输出；
  - **自建靶场**：13 个缺陷覆盖 BL1–BL6 全部六类，业务语义取自真实
    电商/银行/审批流场景；
  - **双模式检出统计**：分母按模式收缩（WITH_CONTRACT 13/13、
    WITHOUT_CONTRACT 11/13），漏报与误报分别统计并渲染清单。
- **前端**（待办，见 `04` §4 I11 的报告导出页）。

**Fixed（由测试与全量门禁抓到）**
- **`from_openapi` 的 `UnboundLocalError`**：`for ctype, media in ...`
  的循环变量在循环外被引用；`GET` 请求通常无 `requestBody` → 变量未
  绑定 → **运行时崩溃**。测试用真实形态 OpenAPI 立刻抓到。
- **`core/checkpoint` 的 `TestListOrdering` 间歇失败（约 1/6）**：
  `List()` 用秒级截断时间排序、同秒回退到 ID —— 三次快速 `Save` 若
  **跨越整秒边界**，顺序变成创建顺序而非 ID 顺序。
  **后果不止测试不稳**：`Latest()` 依赖该顺序，顺序不确定意味着
  `Latest` 可能返回错误检查点，让 `rewind` 恢复到非预期状态。
  改为**完全按 ID** 排序（P-5 要求完全确定）；修复后连续 20 次运行
  0 失败。

**Security**
- **强证据门禁**（`M8` §4.3 末句的机械化）：`judge()` 要求
  `data_returned=True`，仅 200 状态码**不计入检出**。这是 M4 的 G-3
  在业务逻辑场景的应用，避免"只看状态码就判定成功"这类 D1 幻觉式
  成功。**不提供放松该门禁的入口**。

### I9 · M5 后渗透（多跳路径 + 痕迹记录）（2026-10-12）

> 定位：`04` §I9 ｜ `modules/M5` §5。详见 `docs/iterations/I9-交接.md`。

**Added**
- **`agents/src/aletheia/postexploit/`** —— 后渗透规划与记录：
  - **多跳跳板链求解**（Dijkstra）：代价表按现实成本标定
    （凭据复用最便宜），**外置可调**；低置信关系代价更高；
  - **逐跳任务派生**：每跳带结构化 `target_entity_hints`（供 M3
    Autofocus）与独立 `evidence_id`（供取证校验）；
  - **痕迹记录**（T5.13）：7 类痕迹，append-only，**无任何删除入口**。

**Fixed**
- **Dijkstra 实现缺陷（由测试抓到）**：初版用全局 `seen` 在**入堆时**
  标记已访问节点，让"第一次到达某节点的路径"永久占用该节点 ——
  实测选了代价 100 的路径而非代价 2 的路径。
  **危险处在于默认代价下两条路代价相近，选错不明显**；而真实环境里
  "凭据复用"与"穿透两个服务"的代价差异恰好很大。
  修复：visited 集合随路径携带，另加 `best_cost` 上界表保留剪枝效率；
  新增 2 个回归测试（含菱形拓扑）。

**Security**
- `TraceLedger` **不提供任何删除/清理入口** —— M5 §5 T5.13 原文
  "不做自动清理，避免破坏取证"。理由：清理会销毁证据、破坏 G-4 复现
  的环境指纹、且不可逆。有测试守护该约束（若有人加 `clear()` 则失败）。

### I8 · M7 三路融合（冲突矩阵）（2026-10-12）

> 定位：`04` §I8 ｜ `modules/M7` §4。填补行业空白 G4 —— 调研 39+ 个
> 开源项目后确认**没有任何项目统一了黑盒/白盒/二进制三路观测**。
> 详见 `docs/iterations/I8-交接.md`。

**Added**
- **`agents/src/aletheia/fusion/`** —— M7 三路融合：
  - **观测器统一接口**（`Observer` / `StaticObserver`）+ `SourceKind`
    语义映射。`StaticObserver` 基类**强制** `exploitability_verified=False`
    且不提供覆盖入口 —— 这正是矩阵赖以成立的不对称（黑盒能验证可利用性，
    静态只能指出缺陷存在）；
  - **四象限冲突矩阵**：完整实现 `M7 §4.4` 表格四行，且断言四象限是
    两个独立维度的**完整笛卡尔积**；
  - **冲突驱动下游任务派生**（R6）：派生的任务带**结构化**
    `target_entity_hints`（M3 §8 要求），并明确提醒
    "**不要当作失败的利用尝试而跳过**"；
  - **覆盖度声明**（§9）：结构化三级（COMPLETE/PARTIAL/UNAVAILABLE）
    而非布尔 —— "跑了但没发现"与"没跑"是不同的观测事实。
- **前端 ★冲突矩阵视图**（`06` 页面 6）：2×2 矩阵 + 计数 + 点击下钻。
  **这是三个核心视图的最后一个**（R9 完整）。
  视觉权重刻意不同：最高价值象限用最高对比度 + 独立高亮条，
  低优先级象限弱化 —— 若四象限同等权重，用户无法一眼看出
  "哪几条才是本次评估最有价值的部分"。

**Changed**
- **融合对齐键不含 `location`**（由测试暴露的设计修正）：三路对"位置"
  的表述天然不同（黑盒 URL / 白盒源码行号 / 二进制文件偏移），
  含 location 会让三路对同一缺陷的观测**永远无法对齐**。代价是已知的
  过度对齐（同载体的同类缺陷会合并），属刻意取舍。

**Fixed（预防性 —— 由实测确认的静默失效）**
- 记录并测试了写回 M2 的集成契约：`core/prism` 的 DEFECT 身份键含位置，
  而 `MergeBranch` 只在**同一 entity_id** 上生成 `CONTRADICTS`。
  因此写回时必须用融合对齐键决定身份位置字段。
  **违约后果实测为静默失效**：`merged=true, conflicts=0, CONTRADICTS=0`
  —— 没有报错，只是不工作。已用 `TestM2WritebackContract` 固定。

### I7 · M4 终止仲裁（幻觉终止 0 次通过）（2026-10-12）

> 定位：`04` §I7 ｜ `modules/M4` §4.5。消除 D3（发现随机哈希就宣告
> 胜利并终止会话）。详见 `docs/iterations/I7-交接.md`。

**Added**
- **`agents/src/aletheia/focalplane/arbiter.py`** —— Termination Arbiter：
  - 四道独立结构化校验（目标匹配 / 归属确认 / 证据闸门 / 幻觉检测），
    **不采信 agent 的任何自我评估**；
  - **判定顺序刻意按"最便宜且最致命"排**：幻觉检测放最前。若先查证据，
    精心构造的证据链可以为幻觉背书（`M4` §8 风险栏）；
  - 幻觉检测三类判据：误判 banner（`searchhsplit`/`login:` 等
    **100% 假阳性**来源）/ 裸哈希 / 长 Base64；
  - `GoalSpec` 目标解析（flag/shell/data/unknown），**解析不出则拒绝**
    （fail-closed —— 放行会让"目标没写清就能随便终止"成为绕过路径）；
  - 循环检测：同一 agent 被拒 3 次后 guidance 升级为"停止重复"。
- **`TerminationService` 接线**（`focalplane/server.py`）：
  `FocalPlaneServicer` 同时承载 LedgerService 与 TerminationService ——
  两者共享同一 FocalPlane 实例（Arbiter 需查询账本，拆进程反而引入
  跨进程查询）。
- **测试套件**（`test_arbiter.py`）：**51 组伪达成用例**
  （6 类来源）+ **11 组合法终止用例** + 26 个单元测试。

**Changed**
- `FocalPlane` 新增 `request_termination()` 与 `set_scope_checker()`；
  scope 未注入时第 ② 道 **fail-closed（全部拒绝）**—— 归属未确认是
  AIxCC 重罚项（错误关联 -7 分）。

**Fixed**
- **`root@target:~#` 被误判为幻觉**（由假阴性用例抓到）：token 提取
  按 `:` 切分把它切成 `~#`（2 字符）→ 落入"信息量不足"分支，
  **真实的 root shell 达成物被拒**，agent 将永远无法合法终止。
  修复：新增 `_ACCESS_INDICATOR` 优先判定；`:` 切分限制在"前缀是
  短标签"时（避免切坏 URL）。
- **16 字符 Base64 未被识别**（同由假阴性用例抓到）：正则长度下限 20
  过高 → 落进"长度不足"分支。两者都拒绝但**原因不同**，而原因要写进
  审计（agent 据此修正）。修复：下限降到 16。

### I6 · M5 编排层（确定性骨架）（2026-10-11）

> 定位：`04` §I6。本轮交付**确定性部分**，LLM 接线（Agent 池 /
> Planner prompt / 模型分级路由）有意分离为下一步 —— 详见
> `docs/iterations/I6-交接.md` §6「为什么分离」。

**Added**
- **`core/orchestrate/`** —— M5 编排层：
  - 任务图构造与校验（`NewGraph`）：拒绝空/重复 `task_id`、悬空依赖、
    **有环图**（有环图无法求解，必须在进入调度前拒绝 —— 否则表现为
    "任务永远不 ready"，伪装成"暂时没有可做的任务"）；
  - **确定性规划器**：Kahn 拓扑排序 + 声明序 tie-break、资源约束裁剪、
    关键路径（`NextReady` / `CriticalPath`）；
  - 状态流转（`ApplyResult`）：FAILED **必须**带 `FailureRecord`
    （Refiner 的输入契约）、DONE 为终态不可静默重入；
  - **Refiner**：六类结构化失败类型各有**不同**的定向动作
    （`CONTEXT_MISSING` → 提高光圈档位；`WRONG_HYPOTHESIS` → 回滚分支
    重规划；`HALLUCINATION` → 停 agent 重新取证 等），未知类型**拒绝
    而非猜**；
  - **熔断器**：6 类动作，评估顺序从严到宽，**范围越界最高优先级**
    （fail-closed 终止整场会话）；
  - 检查点 / rewind / fork：账本**不回滚**（记水位而非副本）、
    RUNNING 任务恢复为 READY、里程碑检查点不被淘汰。
- **前端 gRPC-Web 桥接**（`cmd/alethd/support.go`）：HTTP 端口挂载
  `grpcweb.WrapServer`，含**挂载前缀剥离**。
- **`ConflictEntityIDs`**（`core/prism`）：M3 消费的冲突判据
  （当前有效版本 `version > 1`）。
- **`GovernorService` gRPC 接线**（`core/governor/server.go`，补齐 I3
  遗留）：I3 已实现并测试 CostGovernor，但当时未接 gRPC。两点设计：
  预扣被拒返回**业务结论**（`reserved=false` + 状态 + 原因）而非 gRPC
  传输错误；无预算来源时 **fail-closed**（不给默认值 —— 猜测的上限
  比"显式拒绝执行"更危险）。
- **配置项 `budget.session_tokens`**（默认 0 = 未配置，启动时高亮告警）。
- **前端人机协同决策队列**（`06` 页面 7）：按 `06 §7.1` 四要素渲染
  （证据摘要 / **不确定性标注** / 选项 + 影响评估）。不确定性**刻意
  放在选项之前** —— 先让决策者看到"系统有多确定、缺什么信息"，
  避免被"看起来很确定"的表述诱导直接点按钮。终止选项仅在触发
  「涉及会话终止」或「涉及范围边界」时出现（否则是伪选择）。
- **前端成本与预算面板**（`06` 页面 10）：gauge 上直接画出
  **80% 收窄线与 100% 熔断线**，并单列「剩余余量」给出到两条线的
  确切 token 数 —— 只显示"已用 60%"而不显示"还有多少碰到硬约束"
  无法让使用者判断风险。

**Fixed**
- **前端 RPC 全断**（I0 起存在，直至本次暴露）：HTTP mux 只挂了静态资源，
  `/grpc` 前缀从无 handler，因此**所有**前端 RPC 表现为
  `Transport error: Failed to fetch` —— I2 证据链视图与 I4 心智地图在
  浏览器里都不可达。三处独立修复缺一不可（详见 `I4-交接.md` §1）。
- **`url_prefix` 授权绕过**（`core/scopekernel`）：解析时只保留 host、丢弃
  path，且用裸 `strings.HasPrefix` 比较 —— `https://api.example.com/v2/`
  连带授权 `/`、`/admin`，且命中 `api.example.com.evil.com`。改为
  保留 `PathPrefix` + host 精确相等 + **按路径段边界**比较。
- **`Governor` 预扣被拒即永久熔断**（`core/governor`）：预扣失败是**瞬时
  并发争用**（零消耗），旧实现直接置 `circuitOpen` 且无解除路径，把剩余
  预算永久锁死。改为熔断只由「已消耗 ≥ 总额」触发；`Consume` 改为幂等；
  新增 `Release` 归还预扣。
- **`RawStore.Put` 并发写入竞态**（`core/ingest`）：临时名是确定性的
  `哈希 + ".tmp"`，并发写同一内容时争抢同一文件（实测 200 并发失败 90 次）。
  改用 `os.CreateTemp` 唯一名 + `fsync` + rename 冲突收敛。

**Security**
- `url_prefix` 绕过修复属**授权范围放大**（`07` §T5.5 级别）。
  该规则此前**全仓库零测试覆盖**，是它未被发现的原因；本轮补齐
  8 个用例，并做**变异验证**（回退旧逻辑 → 新套件报出 8 处
  `AUTHORIZATION BYPASS` 并 FAIL）。

### I5 · M3 光圈控制 ★核心创新（2026-10-11）

> 定位：`04` §I5。详见 `docs/iterations/I5-交接.md`。

**Added**
- **`core/aperture/`** —— M3 光圈控制：
  - 三档光圈模型（f/1.4 / f/4 / f/16，数值逐项取自 `M3` §4.1）；
  - Autofocus：实体引用抽取（URL/CIDR/IP/域名，**刻意保守不误抽**）+
    关系权重表（§4.3）+ 六维相关度打分（§4.2 步骤 3）；
  - Context Assembly：**不允许截断**（§2.2 N4），超预算返回
    `APERTURE_OVER_BUDGET` 并自动降档重试；
  - 保守 Token 估算器（§4.5 系数）+ 省略维度**显式**声明（§4.4）；
  - **召回率测试套件**：100 组跨任务依赖链（任务 B 的 hint **只含
    自己知道的主机名**，不传实体 ID）。
- **前端光圈上下文视图**（`06` 页面 5 ★核心视图）：档位阶梯、摘要、
  **省略声明与入选清单同等显眼**（诊断价值所在）、选取依据审计。

**Changed**
- `M3` §4.2 步骤 5 标题写"按预算**截断**"，与 §2.2 N4「不允许截断」
  矛盾 —— 按 N4 实现（贪心装入 + 显式省略），测试注释记录该判断。

### I4 · M2 棱镜分解与心智地图（2026-10-11）

> 定位：`04` §I4。详见 `docs/iterations/I4-交接.md`。

**Added**
- **`core/prism/`** —— M2 心智地图（系统的唯一真源）：
  - 单一属性图（SQLite，纯 Go 驱动**无 cgo**）+ 七类实体 schema；
  - **确定性实体身份**：`entity_id = 类型前缀 + sha256(kind‖规范业务键)`，
    使同一主机被 nmap 与 httpx 分别发现时落到**同一个** ID；
  - **多源写入不覆盖不合并**（§4.3，对 D12 级联失败的回应）：值冲突
    生成新版本 + `Conflict{VALUE_MISMATCH}`；值相同只追加 provenance；
  - **时间版本与回放**（§4.4）：严格区间查询，回放保真；
  - **假设分支**（§4.5）：创建/回滚/合并，合并闸门拒绝未验证假设；
  - 子图投影（§4.2）+ 幂等写入 + 分支并发上限。
- **前端心智地图浏览器**（`06` 页面 3）：表视图 / 关系视图 / 时间回放。

**Security**
- `RawStore.Put` 加入 `fsync`：证据必须在返回 URI 前真正落盘，
  否则崩溃会留下"有引用无内容"。
- M2 `graph_meta.schema_version` 版本不符拒绝打开（fail-closed）。

### Q8 · 长时稳定性 harness 补齐（2026-09-27）

> 定位：`04` §2 P0 门禁第 1 条（24h 无崩溃 / 无内存泄漏）的执行入口。
> 此前为「骨架但跑不通」状态。详见
> `docs/iterations/I3-Q8稳定性harness-交接.md`。

**Added**
- **RSS 采样器**（`tests/stability/rss.py`）：标准库 `ctypes` 调 Win32
  `GetProcessMemoryInfo` / 读 Linux `/proc/<pid>/status`，**零新增依赖**；
  采样失败以非零退出码显式上报。
- **`make stability-smoke`**：90s 冒烟入口，用于改 harness 后先验证接线。
- **判定摘要新增 `rss_sample_failures`**：采样不可得时直接判失败，
  不再折算为 0% 增长。
- **gRPC 独立端口**（`server.grpc_port`，默认 7724）：I0 骨架里 `grpcServer`
  从未 `Serve`（唯一 listener 被 HTTP/WebUI 占用），gRPC 网络入口实际不存在
  —— 由 Q8 harness 首次真实运行暴露。与 HTTP（7723）双端口，零 h2c 分流歧义。

**Fixed**
- `tests/stability/probe.py` 探针目标端口 7723（HTTP/WebUI）→ **7724**（gRPC）：
  此前探针 100% 失败，`last_run.json` 恒为 `FAIL`。
- `run.sh` 的 `rss_of()` 改为不依赖从 bash 调用 `powershell`（受限 shell 会拦截，
  失败仅表现为空输出）—— 这是「RSS 增长 < 5%」退化为**恒真断言**的根因，
  比判定失败更危险（`docs/10` §0「绿灯替代有效」的同类风险）。
- `probe.py` 全部 RPC 增加超时：此前无超时，长跑中一次对端无响应即永久挂起。
- `run.sh` 的 `duration_s` 此前恒为 `null`；时长基准由「累加 interval」改为
  **真实墙钟**，避免标称 24h 实际跑 30h+。
- `probe.py` 未通过 `ruff format` 导致 `make lint`（Q7）失败；已修复。
- `server.grpc_port` 补**范围与端口冲突校验**（`core/config`）：此前越界或与
  HTTP 端口同值都要等到 `net.Listen` 阶段才失败，错误信息不如配置校验清晰；
  现与 `server.port` 的校验对称（`TestValidationRejects` 新增 3 子用例）。
- `run.sh` 的整目录清理改为**只删账本 + 删除后回验**：`rm -rf` 在受限环境下
  会因单次批量删除超阈值被拒，而失败被 `-f` 静默吞掉；残留的 `ledger.db`
  会让本轮 `evidence_id` 与上一轮撞号，被 M4 的幂等/伪造检测拒收 ——
  表现成「probe 全程失败」，实为脏状态污染（误导性结论）。清理失败现
  显式 `exit 2`。

**Changed**
- **RSS 判据引入预热窗口**（真源 `docs/modules/M6` §12，`docs/04` §6 同步）：
  判据改为比较**预热窗口（默认 600s）结束后的稳态区间**。依据：30 分钟观测
  确认 `alethd` 的 RSS 约 5 分钟后进入平台期（末 11 分钟 −0.28%），属
  Go runtime 高电平堆行为、**非内存泄漏**；旧口径把启动堆扩张计入基线，
  对任何长时服务恒为假阳性（实测 `ad_rss_growth_pct = 15.12%`）。
  `run.sh` 新增 `--warmup`；摘要新增 `warmup_s` / `steady_samples`；
  稳态样本 < 4 判 FAIL 并显式提示「无法判定」（**缺证据 ≠ 无泄漏**）。
  **阈值 5% 未变** —— 改的是比较区间的选取，不是放宽断言（`docs/09` R3）。

**Security**
- `.gitignore` 补 `tests/stability/last_run/`：此前 `probe_key.hex`
  （一次性 Ed25519 私钥）与运行采样不在忽略范围内。

**已知缺口**
- **24h 全量未执行** —— P0 门禁第 1 条尚未通过。已议定改在**专用 Linux
  环境**执行（不占用开发机）；harness 已跨平台，Linux 侧经 `/proc` 采样。

### I3 · M6 范围内核与隐私网关（2026-09-25）

**Added**
- **Scope Kernel**（`core/scopekernel/`）：三重校验（network / tool_param /
  post_dns）；七类绕过防御（十进制/八进制/十六进制 IP、IPv6 映射、userinfo、
  尾点/大小写、超长域名拒绝）；匹配语义不可协商（exclude 优先 → include →
  默认拒绝）；post_dns 无 resolver fail-closed；按目标+会话限流（M6 §3.4）。
- **Privacy Gateway**（`core/gateway/`）：确定性 token 映射（同会话同值同
  token）；执行前回注；五类泄漏模式出站扫描命中即阻断；告警摘录掩码 +
  真实值哈希。PATH_INTERNAL 的 Python lookbehind 以独立扫描函数等价实现
  （Go RE2 限制）。
- **CostGovernor 最小实现**（`core/governor/`）：预扣制（失败即拒）+ 双阈值
  （≥0.8 收窄 / ≥1.0 熔断）+ 熔断无逃逸；零预算为配置错误（Q9 执行体）。
- **接线**：Ingest 的 Scope/Gateway 依赖真实化（I1 预留接口）；ScopeService
  gRPC 适配；越界 SCOPE_VIOLATION 与执行依赖失败在错误码上可区分。
- **页面 9**：范围与授权管理（只读形态；录入走 CLI，06 §6.1 原文）。

**Changed**
- `make redline`：追加 Go 侧 Q4/Q5 用例（scopekernel + gateway）。

**已知缺口**
- Q5 真实靶场抓包未执行（docker 未装）—— 机制层已验证；P0 门禁第 4 条
  在靶场验证前不得视为通过（I3 自检报告 🟠 P1）。
- Sandbox 与 GovernorService gRPC 未做（04 §I3 清单未列；顺延待项目负责人确认）。

### I2 · M4 证据账本与四道闸门（2026-09-25）

**Added**
- **Evidence Ledger**（`agents/src/aletheia/focalplane/ledger.py`）：SQLite WAL
  append-only + `prev_hash/self_hash` 哈希链（域分隔 + 长度前缀 + 确定性 proto
  序列化）；账本级 fail-closed 校验（拒绝调用方自带哈希/时间戳 —— 时间戳
  权威在账本）；幂等 = 重放语义（同 ID 内容不同 = 伪造信号，幂等不得吞掉）；
  `verify_chain` 检出中间记录篡改/删除的断点（07 §T4.3）。
- **G-1 执行绑定**（`execverifier.py`）：Ed25519 独立验签进入 append 路径
  （`Ledger` 构造器强制注入 verifier —— 不存在不验签的账本实例）；
  签名输入域分离（`aleth/exec-id/v1`），M4 只持 Sandbox 公钥（07 §T4.1）。
- **G-2/G-3/G-4 与状态机**（`focalplane.py`）：G-2 失败 → REJECTED（原因记录
  供 Refiner）；G-3 失败封顶 CANDIDATE（弱证据是待补强不是已证伪）；
  G-4 显式 pending（I7）—— CONFIRMED 跃迁代码就绪但 I2 不可达；
  transition 审计（append-only）+ CONFIRMED→CANDIDATE 不可逆约束。
- **G-3 强证据模式库**（`patterns.py`）：最小可信集，每条带出处注释；
  `audit_text` 反例审计器 —— searchsploit「Shellcodes」等 D1 反例
  在任何 kind 下零命中。
- **归因双向校验**：证据首引绑定 target；异 target 引用 → 张冠李戴检出 →
  ATTRIBUTION_MISMATCH + 冲突断言记 HYPOTHESIS + 既有引用者标 needs_review
  + P0 告警回调（04 §I2 DoD③）。
- **幻觉双熔断**：per-agent 阈值（3）+ session 占比（10%，最小样本 10）。
- **LedgerService gRPC server**（Python）+ **Go 转发代理**（`core/focalplane/`）
  + registry 接线；server 未运行 → 显式 UPSTREAM_UNAVAILABLE。
- **Q3 红线进 CI**：`tests/redline/test_q3_forged_evidence.py`（三类注入 ×
  对抗变体，14 用例）+ ci.yml `redline (Q3)` job。
- **前端证据链视图**（06 页面 4，★核心视图）：finding → assertions →
  evidence → side_effects 全链 + 交叉引用双向渲染 + 归因状态条。

**Changed**
- **契约（contract:）**：`AppendEvidenceRequest.signed_exec_id`（[derived]
  扩展；G-1 验签输入，frozen 面零改动；双人 review 待项目负责人复核）。
- 运行时依赖从零到二：`grpcio`（显式化）、`cryptography`（Ed25519，
  非对称是 T4.1 防御前提）—— 四项说明在 pyproject 注释。
- ci.yml：coverage job 收紧（I0 遗留的 continue-on-error 移除）；
  新增 redline (Q3) job。

**Fixed**
- `.gitattributes` 缺失 + autocrlf 把工作区文件 CRLF 化（gofmt/解析器
  测试受扰）—— 全仓统一 LF + fixtures 禁转换。

### I1 · M1 光谱摄入（2026-09-25） · M1 光谱摄入（2026-09-25）

**Added**
- **参数化适配器框架**：`core/ingest/adapter.go` —— Adapter 统一接口（M1 §4.1）、
  ParamSchema DSL（Target/PortRange/Enum/EnumList/BoolFlag/Path 六种类型，
  **没有自由字符串类型** —— R5 的类型级防线）、含端点的版本区间门禁、
  Catalog 工具白名单（threat-model T2 缓解）。未知参数与参数名变体显式
  `INVALID_ARGUMENT`，常见别名归一（M1 §4.3 翻车点 3）。
- **三个工具适配器与确定性解析器**：`core/ingest/{nmap,httpx,nuclei}/`。
  nmap 走 `-oX` XML（破损整体 fail-closed），httpx/nuclei 走 JSONL（单行破损
  显式降级为 RAW 记录 + unparsed 计数，不静默丢弃）。M1 §4.3 三个翻车点全部
  显式处理并有测试：版本串前导数字守卫（`^\d+\s*\(`）、进入解析前统一
  strip ANSI、参数名变体。实体草稿（ASSET/SERVICE/ENDPOINT/DEFECT）按
  05 §3.1 抽取，`source_line` 回指原始输出行号。
- **归一化与无损折叠**：`core/spectrum/` —— UTF-8 消毒、ANSI 清洗、
  CRLF/LF/CR 归一、单行 1MB 截断（T9 资源耗尽缓解）；折叠要求相邻同模板 +
  行号连续 + span 相同，`ExpandFolded(Fold(x)) == x` 与
  `LinesContaining` 语义查询等价性是可验证判据（DoD③）。
- **IngestService 真实实现并接线**：`core/ingest/service.go` +
  `cmd/alethd/main.go`（`registry.Ingest` 替换 `unimplementedIngest{}`）。
  Execute 实现 05 §7.1 步骤 3–7 全链路，Scope/Gateway/Sandbox 以接口注入，
  依赖缺失时显式 `UPSTREAM_UNAVAILABLE`（fail-closed）；ListAdapters（字典序
  分页）与 ValidateTool（版本门禁）真实可用。原始输出落内容寻址存储
  `RawStore`（`RawOutputRef` 契约）。
- **uuid7 与 ID 约定**：`core/ingest/parseutil.go` 的 `newSpectrumID()`
  （`sp_{uuid7}`，时间有序，10 §P4 豁免项）。
- **Q2 门禁脚本**：`scripts/coverage-go.sh` —— Go 解析器覆盖率 ≥90%
  （排除测试辅助包 testutil），`make coverage` 调用。
- **测试**：三适配器 + 框架 + 折叠的边界用例与确定性测试（Go 侧新增 40+
  用例）；fixtures 真源在 `tests/parsers/fixtures/{nmap,httpx,nuclei}/`
  （RFC 5737 文档网段与 `.test` 保留域，无真实目标信息）。

**Changed**
- `Makefile` `coverage`：追加 Go 解析器阈值检查（此前 Go 侧无 90% 强制）。
- `Makefile` `test-determinism`：从恒失败的占位（pytest `-m determinism`
  零匹配 → exit 5）改为 Go 侧真实门禁；Python 侧显式注明 I2 恢复。
  **不是放宽** —— 原状态是永假占位，新状态是真实门禁 + 显式声明。
- `core/config`：`validateStorage` 补 `storage.evidence_dir` 非空断言
  （默认值仍由 `DefaultFilePaths()` 派生）。
- 测试迁移说明：Q6 确定性验证必须用 `proto.MarshalOptions{Deterministic: true}`
  —— go/protobuf 对 map 字段的默认序列化顺序是故意随机的。

**Security**
- 参数值全类型强制校验：shell 元字符 / 空白 / 前导 `-`（选项注入）/
  路径穿越（`..`）全部显式拒绝；argv 以独立元素传递，不存在字符串拼接路径。
- ScanOutbound 命中即阻断光谱出站（`PRIVACY_LEAK_DETECTED`）；
  Sandbox 返回空 `exec_id` 视为违约（`EVIDENCE_INVALID`）。

### I0 · 仓库骨架与抽象层（2026-09-24）

**Added**
- **Protobuf 契约的机器可读形式**：`proto/aleth/v1/aletheia.proto`，逐字转写 `05-接口契约与数据模型.md`。每个 message/service/enum 标注 `[frozen]`（来自 05 原文）或 `[derived]`（05 在 RPC 中引用但未给字段表，按语义补齐最小集以让契约可编译）。
- **三侧代码生成管线**：`proto/buf.gen.yaml` + `scripts/gen-proto.sh`
  - Go（消息 + 服务骨架）→ `core/api/aleth/v1/`
  - TypeScript（WebUI 类型唯一来源，Q14）→ `web/src/gen/`
  - Python（grpcio-tools）→ `agents/src/aletheia/gen/`
- **接口契约的空实现**：`core/api/server/registry.go`，`05` 定义的 10 个服务全部显式返回 `UNIMPLEMENTED`（不是返回空响应 —— 空响应会被调用方误判为"能力已存在但没有结果"）。
- **配置系统**：`core/config/config.go`。安全默认：仅监听 `127.0.0.1`、Privacy Gateway 默认开启、零遥测。对外监听必须提供 TLS 证书，否则拒绝启动（不降级为自签）。
- **结构化日志 + 确定性脱敏**：`core/log/log.go`。在 `zap` 的 `WriteSyncer` 出口处统一脱敏（五类：私有 IP / 内网域名 / email / 凭据 / 内部路径），而非依赖每个调用点记得脱敏。
- **Observability 骨架**：`core/obs/obs.go`。span 属性键与 `05` 的 ID 约定一致。
- **Checkpoint 存储**：`core/checkpoint/checkpoint.go`。内容寻址 + 增量；快照不可变（同 ID 不同内容报错）；blob 缺失时 fail-closed 报错而非返回空组件。
- **daemon 启动顺序的安全边界**：`cmd/alethd/main.go`。Authorization Anchor 校验位于绑定端口之前（`08` §1.1 硬约束 2），凭证缺失时退出码 3。
- **CLI 控制平面**：`cmd/aleth/`。`daemon start/stop`、`status`、`version`。状态查询如实报告"I0 客户端未接线"，不返回假成功。
- **WebUI 脚手架**：`web/`（Vite 7 + React 19 + TS 5.9）。交付 `04` §I0 要求的页面 1（会话总览）与页面 2（实时执行流）最小可用版；三个核心视图（页面 4/5/6）路由已注册并标注交付迭代。
- **CI 流水线**：`.github/workflows/ci.yml`，6 个 job 覆盖 Q1/Q7/Q10–Q14，并在末尾明确列出尚未自动化的门禁（Q3/Q4/Q5/Q6/Q8/Q9）及补齐迭代 —— 不做假通过。
- **安全静态检测**：`scripts/check-no-bypass.sh`，覆盖 R4/R5/R6/P-4/R7/R8。
- **门禁脚本**：`scripts/gen-proto.sh`、`check-gen-fresh.sh`（Q14）、`check-frontend-credentials.sh`（Q12）、`lint.sh`（Q7）、`embed-web.sh`、`smoke-embed.sh`（Q11）。
- **测试**：38 个 Python 测试（契约一致性 10 + 门禁变异验证 10 + ROE Schema 2 + Release Notes 9 + CI 工作流 7）+ Go 测试（config / log / checkpoint）。
- `examples/roe.example.yaml` 授权凭证示例（已通过 `roe.schema.json` 校验）。

**Added（自检机制）**
- `tests/test_security_scan.py` —— 对安全扫描脚本本身做**变异验证**：注入真实违规代码，断言脚本必须 FAIL。缺少这一条，一个永真的扫描脚本会让所有"门禁已通过"的结论失去依据（`10` §0「绿灯替代有效」）。
- `docs/iterations/I0-自检报告.md` —— 按 `10` §5 模板产出，每条红线附实际执行的命令与原始输出。

**Changed**
- `pyproject.toml` / `Makefile` / `go.mod` 中的 Go 命令显式限定 `./cmd/... ./core/...`，不用 `./...` —— `web/node_modules` 下的第三方 Go 包（flatted，无自己的 go.mod）会被算进本模块，污染测试输出。

**Fixed**
- （开发过程中发现并修复的三个真实缺陷，均已由测试锁定）
  1. `core/checkpoint` 的 blob shard 子目录未创建，写 blob 时报 "cannot find the path specified"
  2. `core/checkpoint.List` 用纳秒级时间戳排序，同批次创建的 checkpoint 顺序不确定（违反 P-5 确定性）
  3. `scripts/check-no-bypass.sh` 的 R5 规则只覆盖 Python f-string，漏掉 Go 的 `fmt.Sprintf`（双语言项目的单侧漏检）

**Known gaps（I0 未达成项，按 `09` §10 第 4 项如实记录）**
- ~~CI 工作流未实际执行~~ —— **已解决**，见下方「CI/CD 落地」节（6 job 全绿）
- Q3/Q4/Q5 三条红线无 CI 覆盖（需真实靶场，按 `04` 时间表在 I2/I3 补齐）
- Go race 检测在无 C 编译器的开发机上不可用（`GO_TEST_RACE=1` 显式启用；CI 的 ubuntu-latest 会自动启用）

### CI/CD 落地（2026-09-24，仓库已建 + 首跑七连败复盘）

仓库：`github.com/AperturePrism/Aletheia`。I0 已 push，**CI 6 job 全绿**
（Q1 / Q2 / Q10+Q14 / Q7 / Q11 / security static）。DoD②「CI 干净环境从零构建」达成。

**过程：CI 连败 7 次才全绿**，7 次全部是本地验证覆盖不到的问题
（本地 `.venv` 一直存在、PATH 上的 `python` 恰好有 pytest、`web/node_modules` 早已装好）。

**Changed**
- `.github/actions/setup`（composite action）：工具链 setup 收敛到一处定义。
  逐 job 手写 setup 的坏处是新增 job 时会漏 —— 这正是首跑两次失败的原因
- `Makefile` `web-build` 增加 `env-web` 依赖：把"装 web 依赖"从**记得做的事**
  变成**结构性前提**。已用"移走 web/node_modules 后 make build 自动重装"验证
- `Makefile` 新增 `PYTEST_ARGS` 变量（CI 跑单文件用）
- `Makefile` 新增 `check-governance-guard` / `check-iteration-docs` 目标并接入 `gate`
- 根 `README.md`：GitHub 占位内容替换为真实项目说明

**Added**
- `.github/workflows/release.yml`：tag 触发（`v0.1.0` 形式，对应 `04` §5）。
  gate 先行（不过门禁不产出二进制，R10）→ 6 平台矩阵构建 → sha256 校验和
  → 从 CHANGELOG 提取 Release Notes → 发布。`-alpha/-rc` 后缀自动标 prerelease
- `scripts/extract-release-notes.py` + 9 项测试：Release Notes 从 CHANGELOG 提取
  而非手写（`09` §10 第 8 项 + `README` §3「任何事实只写在一个地方」）。
  **找不到段落时 exit 2 而非输出空内容** —— 空 Notes 的 Release 比失败的更糟
- `scripts/py.sh`：Python 解释器解析移到 recipe 内（规避 Make parse-time 陷阱），
  逐个候选验证 `import pytest`，venv 缺失时用 uv 自动创建
- `tests/test_ci_workflows.py`（7 项）：断言每个 job 都调统一 setup、
  workflow 不含已废弃写法、CI 显式记录未自动化的门禁。
  **已变异验证**：删掉某 job 的 setup 步骤后测试 FAIL

**Fixed**
- `pyproject.toml` exclude `docs/**/*.md`：ruff 会把 md 的 ```python 代码块
  当源文件格式化，涉及 25 个冻结文档

**三条方法论教训（比修复本身重要）**
1. **本地全绿 ≠ CI 能跑。** 干净环境是唯一诚实的验证
2. **"更健壮的回退"可能比明确的失败更危险。** 把显式 127 换成隐密的
   `No module named pytest`，后者会被误读成"测试在跑但没过"
3. **`$(shell)` 的结果不能依赖任何 recipe 的副作用。** 这是第 7 次全挂的根因

---


### 指令文档冲突裁决（2026-09-24，按 C + D 处置）

项目负责人裁定 **C + D**：治理模型按 `08`/`09` 执行，方法论按 D1–D8 计划吸收，
指令文档降级为参考。账号池 / CPA / 临时邮 / 2captcha 等个人基建段落原样保留、不处置。

**Added**
- `docs/11-指令文档与冻结架构冲突分析.md` —— 4 处 P0 冲突的逐条分析、
  8 处实质一致的对照表、D1–D8 吸收计划登记表，以及裁决记录（§5）
- 两份指令文档入库（`docs/instruction.ctf.md`、`docs/Dev-optimized-ai-digao.md`），
  头部加「方法论参考」状态横幅 —— 只加声明，**未修改其内容**
- `scripts/check-governance-guard.sh` —— 治理模型护栏。把裁决中可用代码验证的
  4 条固化为检查：裁决文档状态、指令文档横幅、`alethd` 保留无凭证不启动、
  默认监听仍为回环、无「临时批准越界」入口。**已变异验证**：移除横幅 →
  FAIL；把 `authPath == ""` 改为 `false` → FAIL
- 明确标注 2 项本脚本**无法**检查（报告合规声明 / scope 不可热改），
  不建永真假检查（`docs/10` §0 硬要求 3）

**Changed**
- `docs/README.md` §2 清单、§3 唯一真源映射、§6 演进记录同步登记
- `Makefile` 新增 `check-governance-guard` 目标并接入 `gate`
- CI `security-static` job 增加一步，确保 remote 侧同样强制

**Fixed**
- `pyproject.toml` 的 ruff 配置：`docs/**/*.md` 加入 exclude。
  根因：**ruff 会把 markdown 里的 ```python 代码块当作源文件 scan + format** ——
  这会重排冻结设计文档（`07`/`08`/`11`）与两份指令参考文档中的示例片段。
  已在 25 个 md 文件上生效，排除后仅 10 个真实 `.py` 参与检查

---

### 协作机制（2026-09-24，I0 之后追加）

**Changed**
- `09` §10 交付物清单**新增第 10 项「交接文档」**，并升级为硬要求：
  - 不假定开发始终由同一工具完成；交接文档必须是"给下一位开发者的操作手册"
  - 五项硬性要求：不假定工具（每步给可执行命令）、环境实测（版本号附命令）、
    第一条命令（撰写时真跑过）、环境坑（症状 + 根因 + 解法，没有则写"无"不得编造）、
    下一步具体到"打开哪个文件、改什么、跑什么命令验证"
  - §8.2 PR 自检清单同步新增 3 项（依赖四项说明、门禁削弱自检、交接文档产出）
- `docs/README.md` §2 清单与 §3 唯一真源映射同步登记 `iterations/`

**Added**
- `iterations/README.md` —— 交接文档模板与填写规范（含填完先自查的检查表）
- `iterations/I0-交接.md` —— I0 的实际交接文档
  - 环境与工具链**本机实测**，含 6 条真实踩到的环境坑与解法
  - 每条验证结论附命令与原始输出
  - 含「门禁自身是否有效」的变异验证记录（6 项）
  - I1 开工的具体第一步动作 + 4 条接手方注意事项
- `scripts/check-iteration-docs.sh` —— 交付物齐全性检查。
  从 `04` 的「I{n} 实际达成情况」小节自动识别已完成迭代，检查交接文档与
  自检报告是否齐全（顺带查空壳）。已接入 `make gate` 与 CI
- `Makefile` 新增 `gate` 目标：一次跑完 build/test/lint + Q10–Q14 + P3 + 交付物检查

### 设计阶段（2026-09-24）

**Added**
- 建立完整设计文档体系（21 份 Markdown + 1 份 JSON Schema）：
  - `01` 行业调研（39+ 开源项目 / 40+ 论文 / 8 基准 / 20 项缺陷 D1–D20 / 6 个空白 G1–G6）
  - `02` 架构设计文档（架构总纲，五层架构 + 设计原则）
  - `03` 项目命名方案（团队 AperturePrism / 项目 Aletheia）
  - `04` 开发总纲（4 阶段 / 13 迭代 / 依赖矩阵 / Q1–Q14 门禁 / 12 项里程碑）
  - `05` 接口契约与数据模型（契约冻结稿：8 个服务 + 状态机 + 熔断语义）
  - `06` 交付形态与交互载体（自托管服务 + WebUI 主界面 + CLI + MCP）
  - `07` 威胁模型（9 类威胁 + 权限分离矩阵 + 6 项明确接受的风险 + §8 事件响应流程）
  - `08` 授权与交战规则规范（Authorization Anchor + Scope 语法 + 四辖区合规细则）
  - `09` 开发交接说明（致 Claude Code：十条红线 + 15 条禁止的"好心优化"）
  - `10` 自检与偏差检查清单（10 类跑偏模式 P1–P10 + 检测命令 + CI 固化路线）
  - `README.md` 文档入口与唯一真源映射
  - `modules/M1`–`M9` 九个模块的开发规格
  - `schemas/roe.schema.json` 授权与范围定义 Schema（Draft 2020-12）

**Changed**
- 命名纠正：确认 AperturePrism 为团队名；项目名从占位名改为 **Aletheia**
- `02` 从"详细设计稿"重组为"架构总纲"，消除与 `modules/`、`04`、`M9` 的内容重复
- 修正 `02` 章节编号错误（原有两个 §1.3）
- 修正 `02` 内部失效引用
- **交接模式确定**：开发由 Claude Code **完整执行（含自检）**，取消独立评审环节；`10` 由"评审清单"改造为"自检清单"（v2）并更名为 `10-自检与偏差检查清单.md`；`09`/`04`/`README` 同步更新引用与定位

**Fixed**
- 修正 `04` 中 I11–I13 的表格格式错误

---

## 计划中

### I0 · 仓库骨架与抽象层
- 目录结构、双语言构建、接口契约空实现、CI 流水线（Q1–Q14）
- WebUI 脚手架 + Protobuf → TypeScript 类型生成 + 产物 embed 进 Go 二进制

### I1–I3 · P0 地基
- L0 光谱摄入（3 个工具适配器）
- L3 证据账本与四道闸门 + **证据链视图**
- M6 范围内核与隐私网关 + 授权管理页面

### I4–I6 · P1 认知层
- 心智地图与棱镜分解 + 地图浏览器
- **光圈控制 + 光圈上下文视图**
- 编排层 + 人机协同决策队列

### I7–I11 · P2 能力层
- 终止仲裁、三路融合（+ **冲突矩阵视图**）、后渗透、Intent Modeler、评测 Harness

### I12–I13 · P3 优化层
- 稳定性与成本治理加固（143h）、轨迹收集与小模型微调

---

## 版本记录

尚无发布版本。首个版本将在 I0 完成时打 tag `v0.1.0`。

---

## 迁移指引

尚无破坏性变更。

**契约变更规范（自首次发布起生效）：** 任何 `05-接口契约与数据模型.md` 的变更须走独立 PR（标题前缀 `contract:`）+ 双人 review，并在本文件记录迁移步骤。
