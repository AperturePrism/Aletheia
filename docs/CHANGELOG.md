# Changelog

> 项目：**Aletheia** ｜ 团队：**AperturePrism**
> 格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)；版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。
>
> **变更类型：** `Added` 新增 ｜ `Changed` 变更 ｜ `Deprecated` 弃用 ｜ `Removed` 移除 ｜ `Fixed` 修复 ｜ `Security` 安全

---

## [Unreleased]

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
- **测试**：22 个 Python 测试（契约一致性 10 + 红线扫描变异验证 10 + ROE Schema 2）+ Go 测试（config / log / checkpoint）。
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
- CI 工作流未实际执行（需 push 到 GitHub 后验证 6 个 job）—— DoD② 未达成
- Q3/Q4/Q5 三条红线无 CI 覆盖（需真实靶场，按 `04` 时间表在 I2/I3 补齐）
- Go race 检测在无 C 编译器的开发机上不可用（`GO_TEST_RACE=1` 显式启用；CI 的 ubuntu-latest 会自动启用）

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
