# Aletheia

> 团队：**AperturePrism** ｜ 项目：**Aletheia**（古希腊语 ἀλήθεια，"去蔽"）
>
> **以"可证明性"为第一原则的自主渗透测试系统。**
> 结论必须由证据显现，不可由模型声称。

---

## 一句话

把混沌的工具输出通过**棱镜**分解为结构化证据光谱，用可调**光圈**按需投喂 LLM 上下文，
并只允许落在**焦平面**上的、有可复现证据的结论成为正式发现。

命名即架构：光圈决定看多少，棱镜决定看到哪些维度，去蔽是目的。

---

## 交付形态

**自托管本地服务 + WebUI 主界面 + CLI 控制平面 + MCP 集成。**

| 载体 | 定位 |
|---|---|
| `alethd` | 核心服务，单二进制（前端资源 embed 进二进制，下载一个文件即得完整系统） |
| **WebUI** | **主界面** —— 任务编排、实时观测、证据浏览、人机协同决策 |
| `aleth` | 控制平面 —— 启动停止、脚本化、CI 集成、状态查询 |
| MCP | 集成 —— 双向（消费外部工具 / 被外部 agent 调用） |

**明确不做**：桌面 GUI（Electron/Tauri）、移动 App、浏览器扩展。

选 WebUI 为主界面的原因：本项目三个差异化能力（**证据链浏览、光圈上下文投影、冲突矩阵**）
在结构上无法用命令行有效表达。只有 CLI 的话，项目会退化成普通 CLI 渗透 agent ——
那个赛道已有 PentestGPT、Strix 等成熟产品。

---

## 三个"第一"

这是项目存在的理由。开发过程中若它们被削弱，无论功能完成多少都是跑偏。

1. 第一个把"**证据**"作为一等数据结构（而非事后补 PoC）的 AI 渗透系统
2. 第一个统一黑盒 / 白盒 / 二进制三路观测并输出**冲突矩阵**的系统
3. 第一个给出可复现的**业务逻辑**漏洞检出数字的系统

---

## 快速开始

```bash
# 1. 安装依赖（Go / Node / Python + uv + make）
make env

# 2. 构建（含 WebUI 产物嵌入 alethd 二进制）
make build

# 3. 跑全部门禁
make gate

# 4. 启动（必须提供授权凭证 —— 无凭证不启动）
cp examples/roe.example.yaml roe.yaml    # 然后按实际授权修改
./bin/alethd --authorization roe.yaml
# 打开 http://127.0.0.1:7723
```

**授权凭证是强制前置条件，不是可选项。** 依据 `docs/08` §1：缺失时进程以退出码 3 拒绝启动 ——
不是警告、不是降级、不是"仅侦察模式"。未授权扫描/渗透第三方系统是违法行为。

---

## 常用命令

| 命令 | 用途 |
|---|---|
| `make build` | 构建 WebUI + 编译 `alethd` / `aleth` |
| `make test` | Q1 单元测试（Go + Python） |
| `make lint` | Q7 静态检查（vet / gofmt / ruff / eslint / tsc / buf lint） |
| `make gate` | **全部门禁**：build + test + lint + Q10–Q14 + P3 安全扫描 + 交付物 + 治理护栏 |
| `make proto` | 从 `proto/` 重新生成 Go / TypeScript / Python 三侧代码 |
| `make env` | 安装全部依赖 |
| `make help` | 全部目标清单 |

---

## 仓库结构

```
proto/          Protobuf 契约 —— docs/05 的机器可读形式（三侧代码的唯一真源）
core/           Go：L0 光谱摄入 + 横切能力层（ScopeKernel / Gateway / Sandbox / Governor）
cmd/            入口：alethd（守护进程）、aleth（CLI 控制平面）
agents/         Python：L1–L4（心智地图 / 光圈 / 焦平面 / 编排）
web/            React + TypeScript + Vite —— WebUI 主界面
map/            心智地图 schema 与迁移
benchmarks/     评测 harness（可复现，第三方可重跑）
labs/           靶场编排
tests/          测试（契约一致性 / 红线 / 解析器边界 / 稳定性）
scripts/        门禁脚本（lint / check-* / proto 生成）
docs/           全部设计文档 —— 见 docs/README.md
```

**`docs/` 是唯一真源。** 代码与文档冲突时以文档为准；要改文档先请示，
不要按自己的理解实现（`docs/09` §9）。

---

## 当前状态

**迭代 I0 · 仓库骨架与抽象层 —— 已完成**（`make gate` 全绿）

契约已冻结并三侧生成、Go 侧安全地基（配置 / 日志 / OTel / 检查点）就位、
CI + Release 工作流可用、22+ 项测试与 6 个门禁脚本。

**本迭代不交付渗透能力** —— `05` 定义的 10 个服务当前全部显式返回 `UNIMPLEMENTED`，
真实能力按 `docs/04` §4 的迭代顺序逐个替换。

下一步：I1 · M1 光谱摄入（nmap / httpx / nuclei 三个参数化适配器 + 确定性解析器）。

---

## 文档

**从 [`docs/README.md`](docs/README.md) 开始** —— 它是文档体系唯一入口。

动代码前必读：

| 文档 | 你会获得什么 |
|---|---|
| `docs/09-开发交接说明-致ClaudeCode.md` | **十条红线 + 15 条禁止的"好心优化"** |
| `docs/05-接口契约与数据模型.md` | 你要实现的每一个接口与数据结构 |
| `docs/04-开发总纲` | 迭代顺序、DoD、CI 门禁 |
| `docs/10-自检与偏差检查清单.md` | 10 类跑偏模式与检测命令 |

协作约定见 `docs/iterations/README.md`（交接文档模板）。

---

## 许可证与免责

本项目是安全研究工具。**仅限授权测试使用**；未授权扫描/渗透第三方系统在多国辖区属违法行为。

项目方不承担使用者滥用行为的法律责任，但设置了最低技术门槛：
Authorization Anchor（无凭证不启动）+ Scope Kernel（三重校验 + fail-closed）+
速率上限 + 不可篡改审计日志。

具体许可证待定（首次发布时确定）。
