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
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require github.com/inconshreveable/mousetrap v1.1.0 // indirect
