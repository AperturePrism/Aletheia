// Command alethd 是 Aletheia 的核心服务进程。
//
// 对应 06 §3.1：
//
//	alethd 守护进程 —— 核心服务，承载全部业务逻辑与 API。
//	必须做：会话生命周期管理、状态持久化、任务执行、全部模块调度。
//	不做：不做任何 UI 渲染。
//	关键约束：默认仅监听 127.0.0.1（对 D19 的回应：安全默认）。
//
// 本文件在 I0 实现的是**启动顺序的骨架**。启动顺序不是实现细节，
// 而是安全边界（08 §1.1 硬约束 2）：
//
//	校验发生在最早时机 —— 在绑定端口、加载模型、初始化沙箱之前。
//	不留"先跑起来再校验"的窗口。
//
// 因此 main() 里的步骤顺序受 08 §1.1 保护，不得为了"先看到服务起来"
// 而调整。
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/AperturePrism/aleth/core/api/server"
	"github.com/AperturePrism/aleth/core/checkpoint"
	"github.com/AperturePrism/aleth/core/config"
	"github.com/AperturePrism/aleth/core/focalplane"
	"github.com/AperturePrism/aleth/core/gateway"
	"github.com/AperturePrism/aleth/core/ingest"
	"github.com/AperturePrism/aleth/core/ingest/httpx"
	"github.com/AperturePrism/aleth/core/ingest/nmap"
	"github.com/AperturePrism/aleth/core/ingest/nuclei"
	"github.com/AperturePrism/aleth/core/log"
	"github.com/AperturePrism/aleth/core/scopekernel"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// 退出码约定（08 §1.3）。
//
// 3 = 授权校验失败，4 = 范围越界熔断。这两个码是给 CI 与监控识别的，
// 不能和普通错误混在一起。
const (
	exitOK             = 0
	exitRuntimeError   = 1
	exitConfigError    = 2
	exitAuthFailed     = 3
	exitScopeViolation = 4
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		// cobra 已打印错误。这里只负责把退出码映射到 08 §1.3 的约定。
		os.Exit(exitCodeFor(err))
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alethd",
		Short: "Aletheia 守护进程 —— 核心服务，承载全部业务逻辑与 API",
		Long: `alethd 是 Aletheia 的核心服务进程。

它以自托管方式运行，对外暴露 gRPC API（Protobuf over gRPC）与 WebUI 静态资源，
不渲染任何界面（见 docs/06 §3.1）。

启动前置条件（不可协商，见 docs/08 §1.1）：
  --authorization <roe.yaml>   必须提供授权凭证。
                               缺失 → 拒绝启动（退出码 3），不是警告。

安全默认（见 docs/02 §11.3 / docs/06 §5.1）：
  · 默认仅监听 127.0.0.1
  · Privacy Gateway 默认强制开启（不得通过 UI 关闭）
  · 零遥测默认

载体职责边界（docs/06 §3）：
  交互式渗透会话的主界面是 WebUI，不是 CLI。
  CLI（aleth）是控制平面：启动停止、脚本化、CI 集成、状态查询。`,
		SilenceUsage:  true, // 运行期错误不打印 usage（噪音且误导）
		SilenceErrors: false,
		RunE:          runDaemon,
	}

	// 全局 flag：配置文件路径。
	cmd.PersistentFlags().StringP("config", "c", "", "配置文件路径（YAML）。为空则只用默认值 + 环境变量。")

	// 授权凭证。这是 08 §1 的 Authorization Anchor。
	//
	// 为什么是必填而非默认值：无授权凭证不启动（08 §1.1 硬约束 1）。
	// 给默认值会让"忘了提供凭证"变成"启动成功但用了空 scope"。
	cmd.Flags().String("authorization", "",
		"授权凭证文件路径（roe.yaml，schema 见 docs/schemas/roe.schema.json）。必填。")

	return cmd
}

func runDaemon(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")
	authPath, _ := cmd.Flags().GetString("authorization")

	// ---- 第 1 步：加载配置 ------------------------------------------------
	cfg, err := config.Load(cfgPath)
	if err != nil {
		// 配置错误：退出码 2（08 §1.3）。此时还不能用 log 包（logger 尚未构造），
		// 所以写 stderr。
		fmt.Fprintf(os.Stderr, "alethd: config error: %v\n", err)
		return errConfig{err: err}
	}

	// ---- 第 2 步：Authorization Anchor ------------------------------------
	//
	// 08 §1.1：校验发生在最早时机，在绑定端口、加载模型、初始化沙箱之前。
	// 校验内容是：凭证存在、结构合法、在有效期内、完整（必填字段齐全
	// + 至少一个 include 目标）。
	//
	// I0 只做"存在性与可读性"检查，完整校验在 I3 落地（见 04 §I3 交付物
	// 「Authorization Anchor（授权凭证校验）」）。
	// 但"无凭证不启动"这条在 I0 就必须成立 —— 它是 08 的硬约束，不是 I3 的可选项。
	if authPath == "" {
		msg := "Authorization Anchor: 拒绝启动 —— 未提供授权凭证。\n" +
			"  依据 docs/08 §1.1：无凭证不启动，不是警告、不是降级、不是「仅侦察模式」。\n" +
			"  用法：alethd --authorization roe.yaml\n" +
			"  凭证格式见 docs/08 §2，JSON Schema 见 docs/schemas/roe.schema.json。\n" +
			"  未授权扫描/渗透第三方系统是违法行为（docs/08 §8.2）。"
		fmt.Fprintf(os.Stderr, "alethd: %s\n", msg)
		return errAuth{err: errors.New("authorization credential is required")}
	}

	if err := requireReadableFile(authPath); err != nil {
		fmt.Fprintf(os.Stderr, "alethd: Authorization Anchor: 拒绝启动 —— %v\n", err)
		return errAuth{err: err}
	}
	cfg.Authorization.RoePath = authPath

	// ---- 第 3 步：存储路径与目录 ------------------------------------------
	cfg.DefaultFilePaths()
	if err := cfg.ResolvePaths(); err != nil {
		fmt.Fprintf(os.Stderr, "alethd: config error: %v\n", err)
		return errConfig{err: err}
	}

	// ---- 第 4 步：日志 -----------------------------------------------------
	//
	// 日志必须在 Auth 校验之后才构造（否则校验失败的输出会先落一份日志文件，
	// 而 08 §6.2 要求日志内容可审计、无敏感值 —— 越晚构造日志越好）。
	logger, err := log.New(log.Options{
		Level:  cfg.Logging.Level,
		Format: cfg.Logging.Format,
		File:   cfg.Logging.File,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "alethd: cannot init logger: %v\n", err)
		return errRuntime{err: err}
	}
	defer func() { _ = logger.Sync() }()
	log.SetGlobal(logger)

	// ---- 第 5 步：确认配置自洽 --------------------------------------------
	if err := cfg.Validate(); err != nil {
		// P-4：失败即熔断，不降级。配置不自洽就拒绝启动，不"警告后继续"。
		logger.Error("config validation failed; refusing to start",
			zapErr(err))
		return errConfig{err: err}
	}

	// R7：Privacy Gateway 被显式关闭时的告警。
	//
	// 只能通过配置文件显式禁用；禁用时启动日志必须高亮告警（modules/M6 §4.2）。
	// 本项目不提供 UI 开关（09 §R7），因此除了改配置文件没有别的关闭路径。
	gatewayEnabled := cfg.PrivacyGatewayEnabled()
	if !gatewayEnabled {
		logger.Warn("⚠ Privacy Gateway DISABLED via config file: " +
			"real sensitive values may reach the model provider. " +
			"Default is ENABLED (docs/09 R7). This event is written to the audit log.")
	}

	logger.Info("alethd starting",
		zap.String("deploy_mode", string(cfg.Deploy)),
		zap.String("listen", cfg.ListenAddr()),
		zap.Bool("loopback_only", cfg.IsLoopback()),
		zap.Bool("privacy_gateway", gatewayEnabled),
		zap.Bool("telemetry", cfg.Telemetry.Enabled),
		zap.String("data_dir", cfg.Storage.DataDir),
		zap.String("authorization_path", filepath.Base(cfg.Authorization.RoePath)),
	)

	// ---- 第 6 步：基础设施 -------------------------------------------------
	// checkpoint 存储在 I0 只验证"可创建"（T6.3：检查点存储基础设施）。
	// 真实使用方（M5 的 rewind/fork）在 I6 接线。
	if _, err := checkpoint.NewStore(filepath.Join(cfg.Storage.DataDir, "checkpoints")); err != nil {
		logger.Error("cannot init checkpoint store", zapErr(err))
		return errRuntime{err: err}
	}

	// 原始工具输出的内容寻址存储（05 §2.1 RawOutputRef）。
	// 失败即拒绝启动（fail-closed）：证据存不进去的摄入层不能上线。
	rawStore, err := ingest.NewRawStore(cfg.Storage.EvidenceDir)
	if err != nil {
		logger.Error("cannot init evidence store", zapErr(err))
		return errRuntime{err: err}
	}

	// ---- 第 7 步：gRPC 服务 ------------------------------------------------
	//
	// I0 只装配"空实现"（05 的服务接口全部存在，能力均为 UNIMPLEMENTED）。
	// 真实能力在后续迭代逐个替换（见 04 §4）。
	registry := server.NewRegistry()

	// I1（04 §4）：IngestService 的 unimplementedIngest 在此替换为真实实现。
	// Scope / Gateway / Sandbox 三个执行前置依赖在 I3 交付 —— 未装配期间
	// Execute 显式返回 UPSTREAM_UNAVAILABLE（fail-closed，绝不绕过校验执行），
	// ListAdapters / ValidateTool 已可用。
	ingestCatalog, err := ingest.NewCatalog(
		nmap.NewAdapter(), httpx.NewAdapter(), nuclei.NewAdapter())
	if err != nil {
		logger.Error("cannot assemble tool adapters", zapErr(err))
		return errRuntime{err: err}
	}
	// I3（04 §4）：授权凭证有效时，Scope Kernel 与 Privacy Gateway 真实接入
	// Ingest 的执行前置依赖；ScopeService 同步注册（registry.Scope）。
	// Sandbox 依赖仍缺位（I3 清单未含容器编排）—— Execute 在该场景显式
	// UPSTREAM_UNAVAILABLE（I1 语义），不存在绕过校验的执行路径。
	if cfg.Authorization.RoePath != "" {
		scope, err := scopekernel.ParseScopeFile(cfg.Authorization.RoePath)
		if err != nil {
			logger.Error("cannot parse roe scope", zapErr(err))
			return errConfig{err: err}
		}
		kernel := scopekernel.NewKernel(scope, netResolverAdapter{net.DefaultResolver}, scopekernel.RateLimit{PerMinute: 120})
		gw := gateway.NewGateway()
		registry.Ingest = ingest.NewService(ingestCatalog, ingest.Deps{
			Scope:   scopeCheckerAdapter{kernel: kernel},
			Gateway: gatewayAdapter{gateway: gw},
		}, rawStore)
		registry.Scope = scopekernel.NewServer(kernel)
		logger.Info("scope kernel + privacy gateway wired",
			zap.Int("include_rules", len(scope.Include)),
			zap.Int("exclude_rules", len(scope.Exclude)))
	} else {
		// 08 §1.1：无凭证拒绝启动发生在更早的 Authorization Anchor 步骤；
		// 能到这里说明凭证已校验，RoePath 为空只可能出现在测试装配形态。
		registry.Ingest = ingest.NewService(ingestCatalog, ingest.Deps{}, rawStore)
		logger.Info("ingest service wired",
			zap.Strings("adapters", ingestCatalog.Names()),
			zap.Strings("pending_deps", []string{"gateway", "sandbox"}))
	}

	// I2（04 §4）：LedgerService 经 focalplane 代理转发到 Python 侧实现。
	// focalplane server 未配置/未运行时保持 UNIMPLEMENTED 或显式
	// UPSTREAM_UNAVAILABLE（fail-closed）—— 账本不可用时绝不假装校验通过。
	if cfg.Focalplane.Addr != "" {
		proxy, err := focalplane.NewProxy(cfg.Focalplane.Addr)
		if err != nil {
			logger.Error("cannot wire focalplane proxy", zapErr(err))
			return errRuntime{err: err}
		}
		registry.Ledger = proxy
		logger.Info("ledger proxy wired", zap.String("focalplane_addr", cfg.Focalplane.Addr))
	} else {
		logger.Info("focalplane not configured; LedgerService stays UNIMPLEMENTED (I2)")
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			// 观测拦截器：把 request 关联到 trace（modules/M6 §8.1）。
			unaryObservabilityInterceptor(logger),
			// 脱敏拦截器（I0 版）：确保出站日志不含真实敏感值。
			// I3 换成真正的 Privacy Gateway 校验（modules/M6 §4.2）。
			unaryRedactionInterceptor(logger),
		),
	)
	registry.RegisterAll(grpcServer)

	// reflection：供 grpcurl / buf curl 调试。
	// HTTP/JSON 调试通道（I0 关键决策①的"保留"部分）由它承载。
	reflection.Register(grpcServer)

	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("aleth.v1", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthSrv)

	// ---- 第 8 步：监听 -----------------------------------------------------
	//
	// Q13 门禁：daemon 默认仅监听 127.0.0.1。
	// 对外监听必须在 config.Validate() 阶段就因缺 TLS 而失败，
	// 因此这里能绑到非回环地址，说明调用方已显式声明且有证书。
	lis, err := net.Listen("tcp", cfg.ListenAddr())
	if err != nil {
		logger.Error("cannot listen", zap.String("addr", cfg.ListenAddr()), zapErr(err))
		return errRuntime{err: err}
	}

	// WebUI 静态资源。I0 先返回一个说明页面，真实资源由 make embed 注入。
	webHandler := newWebUIHandler()

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// HTTP mux：/grpc. 给 WebSocket/HTTP+JSON 调试通道留着。
	mux := http.NewServeMux()
	mux.Handle("/", webHandler)

	httpServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 2)

	go func() {
		logger.Info("http server listening", zap.String("addr", lis.Addr().String()))
		if err := httpServer.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	go func() {
		<-rootCtx.Done()
		logger.Info("shutdown signal received")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
		grpcServer.GracefulStop()
		logger.Info("alethd stopped")
	}()

	select {
	case err := <-errCh:
		logger.Error("server error", zapErr(err))
		return errRuntime{err: err}
	case <-rootCtx.Done():
		// 等待 GracefulStop 完成。gRPC 的 GracefulStop 在另一个 goroutine 里，
		// 这里给它一点时间。
		time.Sleep(100 * time.Millisecond)
		return nil
	}
}

func requireReadableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("credential file %q: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("credential path %q is a directory, want a file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("credential file %q not readable: %w", path, err)
	}
	_ = f.Close()
	return nil
}

// ---- 退出码映射 ----

// errAuth / errConfig / errRuntime / errScope 是把退出码从错误类型里带出来的载体。
//
// 08 §1.3 的退出码是接口的一部分（CI 与监控按码判断），必须可靠映射。
type (
	errAuth    struct{ err error }
	errConfig  struct{ err error }
	errRuntime struct{ err error }
	errScope   struct{ err error }
)

func (e errAuth) Error() string    { return e.err.Error() }
func (e errConfig) Error() string  { return e.err.Error() }
func (e errRuntime) Error() string { return e.err.Error() }
func (e errScope) Error() string   { return e.err.Error() }

func exitCodeFor(err error) int {
	var (
		a errAuth
		c errConfig
		s errScope
	)
	switch {
	case errors.As(err, &a):
		return exitAuthFailed
	case errors.As(err, &s):
		return exitScopeViolation
	case errors.As(err, &c):
		return exitConfigError
	default:
		return exitRuntimeError
	}
}
