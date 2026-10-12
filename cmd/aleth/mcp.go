package main

// `aleth mcp` —— 以 MCP server 形态暴露 Aletheia 的能力（06 §3.4）。
//
// # 为什么放在 CLI 而不是 daemon
//
// MCP 客户端（Claude Desktop / Cursor）的标准接入方式是**在配置里写一条
// 命令**，由客户端启动该进程并通过 stdin/stdout 通信（stdio transport）。
//
// 这与 daemon 的生命周期模型冲突：daemon 是常驻服务、拥有自己的
// stdout 与端口；而 stdio MCP server 必须独占父进程的 stdin/stdout。
// 因此它属于 CLI 的一个子命令 —— 客户端配置里写 `aleth mcp` 即可。
//
// # 连接 daemon
//
// MCP server 本身不持有业务逻辑（06 §3.4 的"不得有绕过路径"）：
// 它把调用转发到**已在运行的 daemon** 的 gRPC 端口，因此
// 范围校验 / 脱敏 / 预算预扣全部走与 WebUI 相同的服务实例。
//
// daemon 未运行时，MCP server 启动即失败并明确提示 ——
// 不给一个"能启动但每个调用都失败"的空壳（docs/09 §6 #4）。

import (
	"context"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"github.com/AperturePrism/aleth/core/mcp"
)

// mcpCmd 构造 `aleth mcp` 子命令。
func mcpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "以 MCP server 形态运行（供 Claude Desktop / Cursor 等外部 agent 调用）",
		Long: `把 Aletheia 的能力暴露为 MCP server（stdio transport）。

用法（写进 MCP 客户端配置）：
  {
    "mcpServers": {
      "aletheia": { "command": "aleth", "args": ["mcp"] }
    }
  }

前提：alethd 必须已在运行 —— MCP 只是集成入口，
不持有业务逻辑，也不提供绕过闸门的路径（docs/06 §3.4）。

暴露的能力：
  · trace_finding    追溯证据链（只读）
  · project_mind_map 投影心智地图（只读）
  · assemble_context 装配光圈上下文（只读）
  · list_adapters    列出工具适配器白名单（只读）
  · execute_tool     执行工具（**经完整闸门链**：范围 / 脱敏 / 预算）

明确不做：不把 UI 外包给 MCP 客户端（docs/06 §3.4 的 HexStrike 教训）。`,
		SilenceUsage: true,
		RunE:         runMCP,
	}
	cmd.Flags().String("daemon", "", "daemon 的 gRPC 地址（默认 127.0.0.1:7724）")
	return cmd
}

func runMCP(cmd *cobra.Command, _ []string) error {
	addr, _ := cmd.Flags().GetString("daemon")
	if addr == "" {
		addr = "127.0.0.1:7724"
	}

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	// ---- 可达性探针：daemon 不可达时**启动即失败** ----
	//
	// 为什么不在首次调用时才报错：MCP 客户端会显示 server "已连接"，
	// 而每个工具调用都失败 —— 使用者会以为是工具的问题，
	// 而不是"daemon 没跑"。启动即失败把这个诊断提前到接入时刻。
	//
	// 用 ScopeService.Check 做探针（实现最轻且必然已装配）；
	// 目标取一个不可能越界的地址 —— 我们只看"服务是否回应"，
	// 不看裁决结果（拒绝也是回应）。
	ctx := context.Background()
	if _, err := alethv1.NewScopeServiceClient(conn).Check(ctx, &alethv1.ScopeCheckRequest{
		SessionId: "mcp-probe",
		Target:    "127.0.0.1",
		Layer:     alethv1.ScopeLayer_NETWORK,
	}); err != nil {
		return &daemonUnreachableError{addr: addr, cause: err}
	}

	deps := mcp.Deps{
		Ledger:   alethv1.NewLedgerServiceClient(conn),
		Prism:    alethv1.NewPrismServiceClient(conn),
		Aperture: alethv1.NewApertureServiceClient(conn),
		Scope:    alethv1.NewScopeServiceClient(conn),
		Ingest:   alethv1.NewIngestServiceClient(conn),
	}

	// 闸门复用**同一个** daemon 的服务实例 —— 这就是"无绕过路径"的
	// 实现方式：不是重新判断，而是调用与 WebUI 相同的服务。
	gate, err := mcp.NewServiceGate(addr)
	if err != nil {
		return err
	}
	defer func() { _ = gate.Close() }()

	srv := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    "aletheia",
		Title:   "Aletheia — provable autonomous pentest",
		Version: version,
	}, &mcpsdk.ServerOptions{
		Instructions: "Aletheia is an evidence-first pentest system. " +
			"Every capability here goes through the same scope check, privacy " +
			"tokenization and budget reservation as the WebUI — there is no MCP " +
			"bypass path. Targets must be inside the authorized scope or calls " +
			"are refused. This is an integration interface, not a UI: use the " +
			"WebUI for evidence-chain browsing, aperture projection and the " +
			"conflict matrix.",
	})
	mcp.NewServer(gate, deps).Register(srv)

	// stdio transport：由客户端（Claude Desktop / Cursor）启动本进程。
	return srv.Run(ctx, &mcpsdk.StdioTransport{})
}

// daemonUnreachableError 把"daemon 未运行"变成一条可操作的错误。
type daemonUnreachableError struct {
	addr  string
	cause error
}

func (e *daemonUnreachableError) Error() string {
	return "cannot reach alethd at " + e.addr + ": " + e.cause.Error() +
		"\n  MCP is an integration entry point, not a standalone service." +
		"\n  Start the daemon first:  aleth daemon start --authorization roe.yaml"
}

func (e *daemonUnreachableError) Unwrap() error { return e.cause }
