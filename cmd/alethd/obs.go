// OTel 接线（`core/obs` → alethd）。
//
// # 为什么需要这个文件
//
// `core/obs`（M6 T6.2「OTel 接入 + trace 上下文传播」）自 I0 起就实现了
// span 属性键、context 传播、范围拒绝与闸门结果记录 —— 但**从未被任何
// 生产代码引用**：6.3KB 的死代码，0% 覆盖率。
//
// 后果不是"少了个功能"，而是 `M6` §8.2 承诺的可追溯性**只是声明**：
//
//	agent 为什么这么做？     span → 决策依据的地图实体 ID → selection_reasons
//	这个结论的证据是什么？   finding_id → assertions → evidence_ids → exec_id
//	这行数据从哪来？        原始输出文件 + 行号 → SpectrumLine → EntityDraft → Entity
//
// 这三条链路的**载体**（span）从未被创建，因此"能回答"是空的。
//
// # 默认零遥测（D18）
//
// 本文件**不安装任何 exporter** —— `obs.Init(nil, ...)` 装 noop provider，
// span 全部被丢弃，行为与接线前完全一致。
//
// 这是刻意的：`07` 与 `06` 都要求"默认零遥测"（抓包验证不向外部发送数据），
// 因此开关必须显式且**默认关闭**。开启需要调用方自己构造 exporter
// 并对其内容负责（`obs.Init` 的注释即此意）。
package main

import (
	"context"
	"strings"

	otelcodes "go.opentelemetry.io/otel/codes"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/AperturePrism/aleth/core/obs"
)

// installTracing 初始化 OTel（默认 noop）。
//
// `enableExport` 为 false 时安装 noop provider —— span 仍会被创建与
// 传递（因此**链路结构是可测的**），只是没有 exporter 接收它们。
//
// 这一点很重要：它让"接线正确"与"是否导出"解耦。
// 若只在开启导出时才算接线，那"默认零遥测"的配置下就无法验证
// 链路是否真的串起来了 —— 而那正是最需要验证的默认形态。
func installTracing(enableExport bool) string {
	if !enableExport {
		obs.Init(nil, "alethd")
		return "noop (default zero-telemetry; spans created but discarded)"
	}
	// 显式开启导出时，调用方负责构造 exporter 并保证内容经脱敏。
	// 当前没有内置 exporter —— 与 02 §7.5 的"按后续迭代接线"一致。
	obs.Init(nil, "alethd")
	return "noop (no built-in exporter yet; see docs/02 §7.5)"
}

// spanKindForMethod 把 gRPC 方法名映射到 `obs.SpanKind`。
//
// 映射的依据是**层归属**（M6 的架构分层），而不是方法名前缀 —— 例如
// `Ledger` 属于 L3 焦平面、`Prism` 属于 L1 心智地图，
// 这种归属是架构事实，写死在这里比"按名字猜"更可靠。
func spanKindForMethod(fullMethod string) obs.SpanKind {
	switch {
	case strings.HasPrefix(fullMethod, "/aleth.v1.IngestService/"):
		return obs.SpanIngest
	case strings.HasPrefix(fullMethod, "/aleth.v1.PrismService/"):
		return obs.SpanMap
	case strings.HasPrefix(fullMethod, "/aleth.v1.ApertureService/"):
		return obs.SpanAperture
	case strings.HasPrefix(fullMethod, "/aleth.v1.LedgerService/"),
		strings.HasPrefix(fullMethod, "/aleth.v1.TerminationService/"):
		return obs.SpanLedger
	case strings.HasPrefix(fullMethod, "/aleth.v1.OrchestratorService/"):
		return obs.SpanOrchestrate
	case strings.HasPrefix(fullMethod, "/aleth.v1.ScopeService/"):
		return obs.SpanScope
	case strings.HasPrefix(fullMethod, "/aleth.v1.GatewayService/"):
		return obs.SpanGateway
	case strings.HasPrefix(fullMethod, "/aleth.v1.GovernorService/"):
		return obs.SpanGovernor
	case strings.HasPrefix(fullMethod, "/aleth.v1.SandboxService/"):
		return obs.SpanSandbox
	default:
		// 未知服务不猜 —— 归到编排层（它是请求入口层），
		// 但 span 名保留完整方法名，因此 trace 里仍能看出真实来源。
		return obs.SpanOrchestrate
	}
}

// sessionIDFromMetadata 从 gRPC metadata 提取 session_id（可空）。
//
// 契约没有把 session_id 放在 metadata 里（它在各请求消息内），
// 因此这里只做"尽力而为"的提取：WebUI 与 CLI 会带上它，
// 带上时 span 就有了可用于聚合的会话维度。
//
// **不编造**：取不到就留空（`obs.Attrs` 本身会跳过空值）。
func sessionIDFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if v := md.Get("x-aleth-session-id"); len(v) > 0 {
		return v[0]
	}
	return ""
}

// obsUnaryInterceptor 为每个 gRPC 调用创建一个 span
// （M6 §8.2 的三条可追溯链路的第一环）。
//
// 返回的 error 原样传递 —— 拦截器**不改变业务语义**（不改错误码、
// 不吞异常），只附加观测。这是"观测缺失不应阻断业务"的另一面：
// 观测也不应改变业务。
func obsUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context, req any, info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		sessionID := sessionIDFromMetadata(ctx)
		ctx, span := obs.Start(ctx, spanKindForMethod(info.FullMethod),
			info.FullMethod,
			obs.Attrs(sessionID, "", "", "")...,
		)
		defer span.End()

		resp, err := handler(ctx, req)
		if err != nil {
			// 失败在 trace 里必须可见 —— 否则"链路通了"会掩盖"链路里全是错误"。
			span.RecordError(err)
			span.SetStatus(traceStatusFor(err), err.Error())
		}
		return resp, err
	}
}

// obsStreamInterceptor 是流式版本的对应实现（与 unary 同一语义）。
func obsStreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv any, ss grpc.ServerStream,
		info *grpc.StreamServerInfo, handler grpc.StreamHandler,
	) error {
		ctx := ss.Context()
		sessionID := sessionIDFromMetadata(ctx)
		ctx, span := obs.Start(ctx, spanKindForMethod(info.FullMethod),
			info.FullMethod,
			obs.Attrs(sessionID, "", "", "")...,
		)
		defer span.End()

		err := handler(srv, &contextServerStream{ServerStream: ss, ctx: ctx})
		if err != nil {
			span.RecordError(err)
			span.SetStatus(traceStatusFor(err), err.Error())
		}
		return err
	}
}

// contextServerStream 让 handler 拿到带 span 的 context。
type contextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *contextServerStream) Context() context.Context { return s.ctx }

// traceStatusFor 把业务错误映射为 span 状态。
//
// # 为什么不能一律标 Error
//
// 有些"错误"是**预期内的正常结果**，标成 Error 会让 trace 充满噪声，
// 从而掩盖真正的故障：
//
//   - `APERTURE_OVER_BUDGET`：M3 §2.2 N4 规定超预算必须显式报错
//     （不允许截断）。这是**正确的拒绝**，不是故障。
//   - `PermissionDenied` / `FailedPrecondition`：范围拒绝与闸门未过
//     同样是安全机制**生效**的证明（07 §8.2："Scope Kernel 熔断是
//     防御成功，不是失败"）。
//
// 因此只有"服务端自身出问题"（Unavailable / Internal / Unknown）
// 才标 Error，其余用 Unset —— 但**仍然记录错误事件**
// （`span.RecordError`），因为"被拒绝了"本身要可追溯。
func traceStatusFor(err error) otelcodes.Code {
	switch status.Code(err) {
	case grpccodes.OK:
		return otelcodes.Unset
	case grpccodes.FailedPrecondition, grpccodes.PermissionDenied,
		grpccodes.InvalidArgument, grpccodes.NotFound, grpccodes.AlreadyExists:
		// 预期内的拒绝：记录但不标 Error。
		return otelcodes.Unset
	default:
		// Unavailable / Internal / Unknown / DeadlineExceeded …
		return otelcodes.Error
	}
}
