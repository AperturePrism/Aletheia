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
	"net/http"
	"strings"
	"time"

	"github.com/AperturePrism/aleth/core/log"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ---- 服务注册 ----

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
