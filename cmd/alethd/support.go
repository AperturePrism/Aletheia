// alethd 的辅助装配：拦截器、WebUI 静态资源、服务注册。
//
// 这些是从 main.go 拆出来的，理由是 main() 应只表达"启动顺序"这一安全边界
// （08 §1.1 的顺序不可变），实现细节放这里便于单独测试。
package main

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AperturePrism/aleth/core/config"
	"github.com/AperturePrism/aleth/core/log"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ---- 服务注册 ----

// sessionIDFor 派生本进程的会话标识（图分区键，M2 §8）。
//
// 为什么需要：M2 的风险缓解之一是"按会话分区"——同一台机器上连续跑多个
// 会话时，图数据不应互相干扰。I4 的单机形态下每个 daemon 进程即一个会话，
// 因此用进程启动时刻派生一个稳定 ID。
//
// 为什么不用随机数：会话 ID 会写进日志与审计，随机值无法在两次启动间
// 复现排查线索；用启动时刻既唯一又可从日志时间对回。
func sessionIDFor(cfg *config.Config) string {
	return fmt.Sprintf("sess_%s_%d", cfg.Deploy, time.Now().Unix())
}

// ---- 日志字段辅助 ----

// zapErr 把 error 转成 zap.Field。
//
// 不叫 zap() —— 会和包名冲突。
func zapErr(err error) zap.Field {
	if err == nil {
		return zap.Skip()
	}
	return zap.Error(err)
}

// zapKV 构造一个字符串字段。
func zapKV(key, val string) zap.Field {
	return zap.String(key, val)
}

// ---- gRPC 拦截器 ----

// unaryObservabilityInterceptor 把每个请求关联到 trace。
//
// modules/M6 §8.1 要求每个 span 关联：
// session_id / task_id / agent_id / exec_id / 地图实体 ID / evidence_id。
//
// I0 只做最基础的：给每个请求一个 span 并记录方法名与耗时。
// 具体的 ID 关联依赖请求体里的字段，在 I1/I2 各模块落地时补。
func unaryObservabilityInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		dur := time.Since(start)

		code := status.Code(err)
		fields := []zap.Field{
			zap.String("rpc", info.FullMethod),
			zap.Duration("duration", dur),
			zap.String("grpc.code", code.String()),
		}
		switch {
		case err != nil && code == codes.Unimplemented:
			// UNIMPLEMENTED 是 I0 的正常状态（契约已定、能力未交付）。
			// 用 debug 级，避免把"还没做的能力"刷成 error。
			logger.Debug("rpc unimplemented", fields...)
		case err != nil:
			logger.Warn("rpc failed", fields...)
		default:
			logger.Debug("rpc ok", fields...)
		}
		return resp, err
	}
}

// unaryRedactionInterceptor 是 I0 版的出站脱敏。
//
// 注意它的定位：这是**日志层面**的兜底，不是 Privacy Gateway。
// I3 会把它替换为真正的 GatewayService.ScanOutbound 校验
// （modules/M6 §4.2：命中 → PRIVACY_LEAK_DETECTED → 阻断该次出站，不降级）。
//
// I0 先做日志脱敏的理由：T5.3（前端凭据泄漏）的排查依赖日志，
// 而 I0 就要交付 WebUI 骨架（04 §I0 前端交付物）。
func unaryRedactionInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		resp, err := handler(ctx, req)
		if _, cats := log.Redact(fmt.Sprintf("%+v", req)); len(cats) > 0 {
			// 请求体里出现了疑似敏感值 —— 记录但不阻断（I0），I3 起阻断。
			logger.Warn("outbound request contains suspicious values (I0: log only; I3 will block)",
				zap.String("rpc", info.FullMethod),
				zap.Strings("categories", cats))
		}
		return resp, err
	}
}

// ---- WebUI 静态资源 ----

// webAssets 是嵌入的 WebUI 构建产物。
//
// 06 §8「打包：静态资源嵌入 Go 二进制（embed）」——
// 这是关键交付优势：前端构建产物嵌入 Go 二进制后，用户下载一个文件
// 即可运行完整系统（含 UI），无需 Node 环境。
//
// 目录内容由 make go-build 维护：
//
//	· 正常路径：scripts/embed-web.sh 把 web/dist 复制进来
//	· 占位路径：cmd/alethd/webplaceholder/index.html（已入库）
//	  —— 在还没执行 make web-build 时保证 go:embed 有文件可嵌，
//	  且占位页会明确告知"WebUI 未构建"，而不是给一个空白页。
//
//go:embed all:webdist
var webAssets embed.FS

// newWebUIHandler 返回 WebUI 静态资源 handler。
func newWebUIHandler() http.Handler {
	sub, err := fs.Sub(webAssets, "webdist")
	if err != nil {
		// embed.FS 的子目录切片失败只可能是 embed 配置错误，属编译期问题。
		// 运行时返回一个明确的错误页，不静默给空白页。
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "WebUI assets unavailable: "+err.Error(), http.StatusInternalServerError)
		})
	}
	return &spaHandler{fs: sub}
}

// newGRPCWebHandler 把 gRPC server 包装为 HTTP handler。
//
// 为什么需要它：WebUI 主界面通过 nice-grpc-web 调用后端（web/src/lib/api.ts
// 的 GRPC_ENDPOINT）。浏览器不能直接说 HTTP/2 gRPC，必须由服务端提供
// gRPC-Web 桥接。docs/06 §8 的「API 契约：从 05 的 Protobuf 生成
// TypeScript 类型 —— 前端类型与后端契约同源」正是靠这条通道落地的。
//
// 先前 I0–I3 的缺口：HTTP mux 只挂了静态资源，/grpc 前缀从未有 handler，
// 因此所有前端 RPC 都表现为 "Transport error: Failed to fetch"。
// 后端能力（I2 证据链、I4 心智地图）因此不可达。本次补齐。
//
// 路径剥离是必需的：grpcweb.WrapServer 在根路径上解析
// "/<service>/<method>"。若把 handler 挂在 "/grpc/" 前缀下而不剥离，
// Go 的 mux 传入的仍是完整路径，wrapper 会把服务名解析成
// "grpc/aleth.v1.PrismService" 并返回
//
//	grpc-status: 12 (UNIMPLEMENTED) "unknown service grpc/aleth.v1..."
//
// 这会把「路径配置错误」伪装成「服务未实现」—— 前端据此误报
// "PrismService 尚未交付"，而真实原因是路由前缀没剥。
func newGRPCWebHandler(grpcServer *grpc.Server) http.Handler {
	wrapped := grpcweb.WrapServer(
		grpcServer,
		grpcweb.WithWebsockets(true),
		grpcweb.WithWebsocketOriginFunc(func(req *http.Request) bool {
			return loopbackOrigin(req)
		}),
		// 跨域：本地工具场景下允许同源 + localhost 开发端口（vite dev 7724）。
		grpcweb.WithOriginFunc(func(origin string) bool {
			return isLoopbackOrigin(origin)
		}),
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wrapped.ServeHTTP(w, stripPrefix(r, grpcWebPathPrefix))
	})
}

// stripPrefix 克隆请求并去掉挂载前缀，使 wrapper 看到 "/<service>/<method>"。
//
// 用克隆而不是原地改 r.URL.Path：请求对象可能被上游中间件或日志复用，
// 原地修改会让日志里的路径与实际不符（排查 gRPC-Web 问题时最不需要的
// 就是日志说谎）。
func stripPrefix(r *http.Request, prefix string) *http.Request {
	// 同时接受 "/grpc" 与 "/grpc/" 两种前缀写法。
	trimmed := r.URL.Path
	for _, p := range []string{strings.TrimSuffix(prefix, "/"), prefix} {
		if p != "" && strings.HasPrefix(trimmed, p) {
			trimmed = strings.TrimPrefix(trimmed, p)
			break
		}
	}
	if trimmed == "" {
		trimmed = "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	clone := r.Clone(r.Context())
	clone.URL.Path = trimmed
	clone.URL.RawPath = ""
	return clone
}

// loopbackOrigin 判定请求来源是否为回环/本地开发源。
func loopbackOrigin(req *http.Request) bool {
	origin := req.Header.Get("Origin")
	if origin == "" {
		// 非浏览器客户端（grpcurl 等）不带 Origin —— 放行。
		// 它们本来就是本机进程，与 08 §1.1 的信任前提一致。
		return true
	}
	return isLoopbackOrigin(origin)
}

// isLoopbackOrigin 判定 Origin 是否指向本机。
//
// 接受：空串、http(s)://localhost[:port]、http(s)://127.0.0.1[:port]、
// http(s)://[::1][:port]。其余（含任意外域）一律拒绝。
func isLoopbackOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	// 127.0.0.0/8 全段都视为回环。
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// spaHandler 处理 SPA 路由：未命中静态文件时回落到 index.html。
//
// WebUI 是 React SPA（06 §8：React + TypeScript + Vite，不做 SSR），
// 因此所有前端路由（/evidence、/aperture、/conflicts…）都要落到 index.html。
type spaHandler struct {
	fs fs.FS
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p == "" {
		p = "index.html"
	}

	f, err := h.fs.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// SPA fallback：前端路由未命中静态文件时给 index.html。
			p = "index.html"
			f, err = h.fs.Open(p)
		}
		if err != nil {
			http.Error(w, "WebUI not built; run `make build` (see 04 §I0 DoD)", http.StatusNotFound)
			return
		}
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if stat.IsDir() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// fs.File 没有 Seek，而 http.ServeContent 需要 io.ReadSeeker。
	// embed 出来的资源都是启动时就确定的静态文件，直接整体读入再写出即可 ——
	// 不引入 Seek 适配层。
	data, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.ServeContent(w, r, stat.Name(), stat.ModTime(), bytes.NewReader(data))
}
