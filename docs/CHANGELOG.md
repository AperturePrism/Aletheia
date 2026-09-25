# Changelog

> 项目：**Aletheia** ｜ 团队：**AperturePrism**
> 格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。
>
> **变更类型：** `Added` 新增 ｜ `Changed` 变更 ｜ `Deprecated` 弃用 ｜ `Removed` 移除 ｜ `Fixed` 修复 ｜ `Security` 安全

---

## [Unreleased]

### I1 · M1 光谱摄入（2026-09-25）

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
