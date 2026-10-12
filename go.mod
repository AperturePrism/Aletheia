// Aletheia 仓库骨架 —— docs/02 §8 项目结构
//
// 本文件只承载"为什么这样组织"的说明；目录树本身见 docs/02 §8，
// 不在此重复维护（维护铁律：任何事实只写在一个地方 —— docs/README §3）。
//
// ============================================================================
// 技术选型与目录的对应关系（docs/02 §7）
// ============================================================================
//
// 双语言分层：
//   · L0 + 横切 + CLI + daemon → Go（core/、cmd/）
//   · L1–L4 + Agent             → Python（agents/）
//   · WebUI                     → React + TS（web/）
//
// Go 模块边界（重要，影响所有 `go` 命令）：
//   · 本模块覆盖 cmd/ 与 core/（含 proto 生成物 core/api）。
//   · web/node_modules/ 下有一个第三方 Go 包（flatted）没有自己的 go.mod，
//     因此 Go 会把它算作本模块的一部分。`go test ./...` 会输出一行
//         github.com/AperturePrism/aleth/web/node_modules/flatted/...
//     它与我们无关，且 npm install/remove 会随时改变它的存在。
//   · 因此本仓库的所有 go 命令都**显式限定 ./cmd/... ./core/...**
//     （见 Makefile 的 GO_PKGS 与 scripts/），不用 `./...`。
//     这比过滤输出可靠 —— 过滤会在新增命令时被忘记。
module github.com/AperturePrism/aleth

go 1.24

// ============================================================================
// 依赖引入策略
//
// 依据 docs/09 §5 #3：新增第三方依赖须说明用途、许可证、维护活跃度、替代方案。
// 当前处于 I0（仓库骨架与抽象层），只引入"骨架必需"的最小集合，
// 每个直接依赖在下方逐条注明四项。功能依赖（SQLite、Docker SDK）
// 在对应迭代引入，引入时在同一注释块中补录。
//
// 拒绝引入的：任何"全家桶"式 AI 框架（langchain 类）。
// docs/02 §2.2 对 GCAI 的结论是"极简优于堆砌"，架构不假设任何 AI 框架。
//
// 维护须知：`go mod tidy` 会重写 require 块并丢掉注释。
// 新增依赖后请重新补回对应注释（含 docs/09 §5 #3 的四项）。
// ============================================================================

require (
	// CLI 框架。github.com/spf13/cobra，Apache-2.0，Kubernetes 生态标准。
	// 用途：aleth 控制平面（docs/06 §3.2 的 daemon start / status / run / export）。
	// 替代方案：标准库 flag —— 不支持子命令树，不采纳。
	github.com/spf13/cobra v1.9.1

	// 配置系统。github.com/spf13/viper，MIT，spf13 维护（cobra 作者）。
	// 用途：docs/06 §5 的部署模式切换（单机/团队）、docs/08 §1 的 authorization 路径。
	// 替代方案：标准库 encoding/json + 手工校验。
	//   选 viper 因其原生支持 YAML/环境变量/文件监听三源合并，与 docs/08 的
	//   roe.yaml（YAML）直接对齐，无需自建解析层。
	github.com/spf13/viper v1.20.1

	// OpenTelemetry。go.opentelemetry.io/otel + /otel/trace，Apache-2.0，CNCF 项目。
	// 用途：modules/M6 §8 全链路追踪与决策溯源（docs/02 §7.5 可观测性栈）。
	// 替代方案：自研 trace 上下文（不采纳 —— 生态互通是 D14 的核心诉求：
	//   WebUI 内置轻量查看器与 Grafana/Loki 都要能消费同一份数据）。
	go.opentelemetry.io/otel v1.29.0
	go.opentelemetry.io/otel/trace v1.29.0

	// 结构化日志。go.uber.org/zap，MIT，Uber 维护，Go 日志事实标准。
	// 用途：daemon 与 CLI 的结构化日志。
	// 替代方案：标准库 log/slog（Go 1.21+ 内置）。
	//   暂仍选 zap：其字段化 API 与可覆写 WriteSync 是 I3 Privacy Gateway
	//   「日志中只有 token，不落普通日志」（modules/M6 §4.1）的基础设施。
	go.uber.org/zap v1.27.0

	// gRPC + Protobuf。docs/04 §I0 关键决策①：Go/Python 通信用 gRPC
	// （Protobuf 强类型，契约定死），保留 HTTP+JSON 作为调试通道。
	// protobuf 版本须与 proto/buf.gen.yaml 的 protocolbuffers/go 插件兼容。
	google.golang.org/grpc v1.67.3
	google.golang.org/protobuf v1.36.1
)

require (
	// —— 间接依赖（go mod tidy 生成，禁止手工增删）——
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.2.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/sagikazarmark/locafero v0.7.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.12.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.opentelemetry.io/otel/metric v1.29.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.29.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241223144023-3abc09e42ca8 // indirect
	gopkg.in/yaml.v3 v3.0.1
)

// ============================================================================
// 功能依赖（按 docs/09 §5 #3 的四项说明：用途 / 许可证 / 维护活跃度 / 替代方案）
// ============================================================================
//
// 说明：`go mod tidy` 会把下面这些移到上面的 require 块并丢掉注释。
// 新增依赖后请重新补回四项说明，并更新本注释块。
//
// github.com/improbable-eng/grpc-web v0.15.0
//   用途：浏览器 gRPC-Web 桥接（I4 修复 —— WebUI 主界面的 RPC 通道）。
//         web/src/lib/api.ts 的 GRPC_ENDPOINT 经此桥接访问后端。
//   许可证：Apache-2.0。
//   维护活跃度：中等（原 improbable-eng 项目已归档，但 API 稳定、
//         广泛使用；本项目只用到 WrapServer 这一稳定入口）。
//   替代方案：connect-go（能力等价但需重写前端 transport，且引入第二套
//         RPC 风格，与"契约同源"目标无益，不采纳）。
//
// github.com/modelcontextprotocol/go-sdk v1.0.0
//   用途：MCP server（06 §3.4 的"作为提供者"）—— 把 Aletheia 的能力
//         暴露给 Claude Desktop / Cursor 等外部 agent。
//   许可证：MIT（Model Context Protocol 官方 Go SDK，Google 与
//         Anthropic 共同推动，Linux 基金会旗下）。
//   维护活跃度：高（官方 SDK，随 MCP 规范演进；v1.x 已稳定）。
//   替代方案：手写 JSON-RPC over stdio（不采纳 —— MCP 的握手、
//         能力协商与工具 Schema 生成都是规范细节，手写等于重实现
//         一个协议栈，且必然与客户端实现漂移）。
//   ★ 版本约束：v1.0.0 是最后一个 `go 1.23` 的版本；v1.1+ 要求
//     go >= 1.25，会顶掉本项目 CI 的 GO_VERSION=1.24。
//     升级该依赖时务必检查 `go` 指令是否仍为 1.24。
//
// modernc.org/sqlite v1.34.5
//   用途：M2 心智地图的单一属性图存储（I4）。
//   许可证：BSD-3-Clause。
//   维护活跃度：高（modernc.org 系列的纯 Go SQLite 移植，持续跟随
//         上游 SQLite 版本）。
//   替代方案：mattn/go-sqlite3（需 cgo，与"无 C 工具链也能全量构建"
//         这一既有事实冲突，不采纳）。
//   ★ 版本约束：与上面同源 —— v1.35+ 会把 `go` 指令顶到 1.26。
//     升级时同样需要检查。
require (
	github.com/improbable-eng/grpc-web v0.15.0
	github.com/modelcontextprotocol/go-sdk v1.0.0
	modernc.org/sqlite v1.34.5
)

require (
	github.com/cenkalti/backoff/v4 v4.1.1 // indirect
	github.com/desertbit/timer v0.0.0-20180107155436-c41aec40b27f // indirect
	github.com/google/jsonschema-go v0.3.0 // indirect
	github.com/klauspost/compress v1.11.7 // indirect
	github.com/rs/cors v1.7.0 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	nhooyr.io/websocket v1.8.6 // indirect
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/exp v0.0.0-20230315142452-642cacee5cc0 // indirect
	golang.org/x/mod v0.22.0 // indirect
	modernc.org/libc v1.61.13 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.8.2 // indirect
)
