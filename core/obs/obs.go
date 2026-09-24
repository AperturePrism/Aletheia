// Package obs 提供全链路追踪（OpenTelemetry）与决策溯源。
//
// 对应 modules/M6 横切能力层 I0 任务 T6.2：
//
//	OTel 接入 + trace 上下文传播
//
// 设计依据（modules/M6 §8.2，对 D14「可观测性与证据链缺失」的回应）：
// 必须能回答三个问题：
//
//	agent 为什么这么做？     span → 决策依据的地图实体 ID → selection_reasons
//	这个结论的证据是什么？   finding_id → assertions → evidence_ids → exec_id → 原始输出行号
//	这行数据从哪来？        原始输出文件 + 行号 → SpectrumLine → EntityDraft → Entity
//
// 本包只负责"把 ID 串起来"这件事：定义 span 属性键，并提供
// context 传播。实际的 exporter（OTLP / Grafana / WebUI 内置轻量查看器）
// 按 02 §7.5 在后续迭代接线。
//
// 零遥测默认（D18）：本包不创建任何向外部发送数据的 exporter。
// 若要开启，必须显式配置 exporter 且发送内容经 Privacy Gateway 脱敏。
package obs

import (
	"context"
	"errors"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Span 属性键。命名与 05 的 ID 约定（§1.1）一致。
//
// 这些键是全链路追溯的"关节"：modules/M6 §8.1 要求每个 span 关联
// session_id / task_id / agent_id / exec_id / 地图实体 ID / evidence_id。
const (
	AttrSessionID    = "aleth.session_id"
	AttrTaskID       = "aleth.task_id"
	AttrAgentID      = "aleth.agent_id"
	AttrExecID       = "aleth.exec_id"     // Sandbox 签发，不可伪造
	AttrEntityID     = "aleth.entity_id"   // 地图实体 ID
	AttrEvidenceID   = "aleth.evidence_id" // 证据 ID
	AttrFindingID    = "aleth.finding_id"
	AttrToolName     = "aleth.tool_name"
	AttrToolVersion  = "aleth.tool_version"
	AttrDecisionID   = "aleth.scope_decision_id"
	AttrSourceKind   = "aleth.source_kind"   // 05 §3.1 Provenance.source_kind
	AttrApertureStop = "aleth.aperture_stop" // 05 §4.1 F_1_4 / F_4 / F_16
	AttrSpanKind     = "aleth.span_kind"
)

// SpanKind 描述 span 在架构中的位置。用于把"决策 → 证据"链结构化。
type SpanKind string

const (
	// SpanOrchestrate L4 编排。
	SpanOrchestrate SpanKind = "orchestrate"
	// SpanAperture L2 光圈装配。
	SpanAperture SpanKind = "aperture"
	// SpanLedger L3 证据账本操作。
	SpanLedger SpanKind = "ledger"
	// SpanMap L1 心智地图操作。
	SpanMap SpanKind = "map"
	// SpanIngest L0 光谱摄入。
	SpanIngest SpanKind = "ingest"
	// SpanScope 横切层：Scope Kernel 校验。
	SpanScope SpanKind = "scope"
	// SpanGateway 横切层：Privacy Gateway。
	SpanGateway SpanKind = "gateway"
	// SpanSandbox 横切层：沙箱执行。
	SpanSandbox SpanKind = "sandbox"
	// SpanGovernor 横切层：成本治理。
	SpanGovernor SpanKind = "governor"
)

// ErrNoTracerProvider 表示未初始化。
//
// 本包使用 noop 作为默认（而非返回错误），原因：观测缺失不应阻断业务。
// 但 D14 要求"必须能追溯"，因此未初始化时 Init 会把状态记录下来，
// 供自检时抓到（见 Initialized）。
var ErrNoTracerProvider = errors.New("obs: tracer provider not initialized")

var (
	mu          sync.RWMutex
	initialized bool
	serviceName string
)

// Init 初始化全局 tracer provider。
//
// tp 可为 nil → 安装 noop provider（观测关闭）。
//
// 注意（R7/D18）：本函数不接受任何"自动上报"参数；开启上报必须由调用方
// 显式构造 exporter 并对其内容负责。
func Init(tp trace.TracerProvider, svc string) {
	mu.Lock()
	defer mu.Unlock()
	if tp == nil {
		otel.SetTracerProvider(noop.NewTracerProvider())
		initialized = false
	} else {
		otel.SetTracerProvider(tp)
		initialized = true
	}
	serviceName = svc
}

// Initialized 返回是否已安装真实的 tracer provider。
//
// 自检用途：CI 可断言"生产配置下 initialized == true"，
// 防止有人无意中用 noop 跑完整流程而误以为有链路追踪。
func Initialized() bool {
	mu.RLock()
	defer mu.RUnlock()
	return initialized
}

// Tracer 返回本包的 tracer。
func Tracer() trace.Tracer {
	return otel.Tracer("github.com/AperturePrism/aleth/core/obs")
}

// Start 开始一个 span。kind 记录 span 在架构中的位置。
func Start(ctx context.Context, kind SpanKind, spanName string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	base := []attribute.KeyValue{attribute.String(AttrSpanKind, string(kind))}
	base = append(base, attrs...)
	return Tracer().Start(ctx, spanName, trace.WithAttributes(base...))
}

// Attrs 便捷构造属性。
func Attrs(sessionID, taskID, agentID, execID string) []attribute.KeyValue {
	var out []attribute.KeyValue
	add := func(k, v string) {
		if v != "" {
			out = append(out, attribute.String(k, v))
		}
	}
	add(AttrSessionID, sessionID)
	add(AttrTaskID, taskID)
	add(AttrAgentID, agentID)
	add(AttrExecID, execID)
	return out
}

// RecordScopeDeny 记录一次范围拒绝。
//
// 越界是安全机制生效的证明（07 §8.2：Scope Kernel 熔断是防御成功，不是失败），
// 但**同时**构成事件 —— 因此必须以 Error 状态记录，而非忽略。
func RecordScopeDeny(ctx context.Context, span trace.Span, decisionID, reason, failedLayer string) {
	if span == nil {
		return
	}
	span.SetAttributes(
		attribute.String(AttrDecisionID, decisionID),
		attribute.String("aleth.scope.failed_layer", failedLayer),
	)
	span.SetStatus(codes.Error, "scope_denied: "+reason)
}

// RecordLedgerGate 记录一道闸门的结果。
//
// gate ∈ {G-1, G-2, G-3, G-4}，passed 为闸门结果。
// 这样"这个结论过没过哪道闸门"在 trace 里一目了然。
func RecordLedgerGate(ctx context.Context, span trace.Span, gate string, passed bool, reason string) {
	if span == nil {
		return
	}
	span.AddEvent("ledger.gate", trace.WithAttributes(
		attribute.String("aleth.ledger.gate", gate),
		attribute.Bool("aleth.ledger.passed", passed),
		attribute.String("aleth.ledger.reason", reason),
	))
}

// SpanFromContext 取出当前 span（无 span 时返回 nil）。
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}
