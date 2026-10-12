package obs

// `core/obs` 的测试（M6 T6.2：OTel 接入 + trace 上下文传播）。
//
// # 为什么需要这组测试
//
// 本包自 I0 起就实现了 span 属性键、context 传播、范围拒绝与闸门结果
// 记录，但**从未被任何生产代码引用** —— 6.3KB 死代码、0% 覆盖率。
//
// 死代码的危险不在于"浪费"，而在于 **`M6` §8.2 承诺的三条可追溯链路
// 只是声明**：span 从未被创建，因此"能回答 agent 为什么这么做 /
// 这个结论的证据是什么 / 这行数据从哪来"是空的。
//
// 本组测试要证明的不只是"函数返回了值"，而是：
//   · 属性键的**取值是稳定的**（改动会破坏既有 trace 的兼容性）；
//   · span **真的被创建**且能通过 context 传下去；
//   · 未初始化时是 noop 而**不报错**（观测缺失不应阻断业务）。

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// withRecorder 安装一个内存 exporter，用于断言 span 真的产生了。
//
// 用 SDK 的 tracetest 而不是自写替身：它是 OTel 官方测试工具，
// 因此断言的是"符合 OTel 规范的 span"，而不是"符合我实现的 span"。
func withRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		// 恢复 noop，避免跨用例污染（本包用全局 provider）。
		Init(nil, "")
	})
	Init(tp, "test-svc")
	return rec
}

func TestInitNilInstallsNoopAndIsNotInitialized(t *testing.T) {
	// 未配置 exporter 时必须装 noop，且 Initialized 如实返回 false ——
	// 后者是自检依据（CI 可断言"生产配置下 initialized == true"，
	// 防止有人用 noop 跑完整流程而误以为有链路追踪）。
	Init(nil, "svc")
	if Initialized() {
		t.Fatal("Init(nil) must leave the package uninitialized (noop provider)")
	}
}

func TestInitWithProviderMarksInitialized(t *testing.T) {
	withRecorder(t)
	if !Initialized() {
		t.Fatal("Init(non-nil) must mark the package initialized")
	}
}

func TestStartCreatesASpanWithKindAttribute(t *testing.T) {
	// ★ 核心：span 真的被创建，且带 aleth.span.kind 属性 ——
	// 后者是 M6 架构分层的载体（"这个 span 属于哪一层"）。
	rec := withRecorder(t)
	ctx, span := Start(context.Background(), SpanAperture, "assemble")
	span.End()
	_ = ctx

	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected exactly one span, got %d", len(ended))
	}
	if ended[0].Name() != "assemble" {
		t.Fatalf("span name = %q, want assemble", ended[0].Name())
	}
	if !hasAttr(ended[0].Attributes(), AttrSpanKind, string(SpanAperture)) {
		t.Fatalf("span must carry %s=%s, got %v",
			AttrSpanKind, SpanAperture, ended[0].Attributes())
	}
}

func TestSpanPropagatesThroughContext(t *testing.T) {
	// context 传播是 M6 §8.2 三条链路的基础：
	// 没有传播，"这个结论的证据是什么"就无法在同一 trace 里串起来。
	withRecorder(t)
	ctx, parent := Start(context.Background(), SpanOrchestrate, "plan")
	childCtx, child := Start(ctx, SpanLedger, "append")
	child.End()
	parent.End()

	got := SpanFromContext(childCtx)
	if got == nil {
		t.Fatal("span must be retrievable from the derived context")
	}
	if !got.SpanContext().IsValid() {
		t.Fatal("retrieved span context must be valid")
	}
	// 注意：child 已 End，因此不再 recording —— 断言的是
	// "span 能被从 context 取回"，那才是传播的含义。
	if got.SpanContext().SpanID() != child.SpanContext().SpanID() {
		t.Fatalf("retrieved span differs from the created one: %s vs %s",
			got.SpanContext().SpanID(), child.SpanContext().SpanID())
	}
	if got.SpanContext().TraceID() != parent.SpanContext().TraceID() {
		t.Fatal("child span must share the parent trace id (that IS propagation)")
	}
}

func TestAttrsSkipsEmptyValues(t *testing.T) {
	// 空值跳过而不是写空串 —— 否则 trace 里会有大量
	// "session_id=''" 这类无信息量的属性，淹没真实维度。
	attrs := Attrs("sess_1", "", "agent_x", "")
	if len(attrs) != 2 {
		t.Fatalf("expected 2 attrs (empty skipped), got %d: %v", len(attrs), attrs)
	}
	if !hasAttr(attrs, AttrSessionID, "sess_1") {
		t.Fatalf("session id missing: %v", attrs)
	}
	if !hasAttr(attrs, AttrAgentID, "agent_x") {
		t.Fatalf("agent id missing: %v", attrs)
	}
}

func TestAttrsAllEmptyYieldsNothing(t *testing.T) {
	if got := Attrs("", "", "", ""); len(got) != 0 {
		t.Fatalf("all-empty attrs must yield nothing, got %v", got)
	}
}

func TestRecordScopeDenySetsErrorStatus(t *testing.T) {
	// ★ 范围拒绝必须以 **Error 状态** 记录。
	//
	// 看似矛盾（越界是防御成功），但 07 §8.2 的要求是双向的：
	// 它既是安全机制生效的证明，**也构成事件** —— 因此不能被忽略。
	rec := withRecorder(t)
	ctx, span := Start(context.Background(), SpanScope, "check")
	RecordScopeDeny(ctx, span, "dec_abc123", "target not in include list", "NETWORK")
	span.End()

	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected 1 span, got %d", len(ended))
	}
	if ended[0].Status().Code.String() != "Error" {
		t.Fatalf("scope deny must set Error status, got %v", ended[0].Status())
	}
	attrs := ended[0].Attributes()
	if !hasAttr(attrs, AttrDecisionID, "dec_abc123") {
		t.Fatalf("decision id missing — a denial must be traceable to its decision: %v", attrs)
	}
	if !hasAttr(attrs, "aleth.scope.failed_layer", "NETWORK") {
		t.Fatalf("failed layer missing — it tells WHERE the denial happened: %v", attrs)
	}
	if len(ended[0].Events()) == 0 {
		// SetStatus 的 message 在 Status 里；但"被拒绝"这件事也应有事件记录。
		t.Log("note: scope deny recorded via status only")
	}
}

func TestRecordScopeDenyToleratesNilSpan(t *testing.T) {
	// nil span 必须安全（无 span 时不应 panic ——
	// 观测缺失不应阻断业务，见 ErrNoTracerProvider 的说明）。
	RecordScopeDeny(context.Background(), nil, "d", "r", "NETWORK")
	RecordLedgerGate(context.Background(), nil, "G-1", true, "")
}

func TestRecordLedgerGateAddsAnEvent(t *testing.T) {
	// 闸门结果用 **event** 而非 status：一个 finding 会过四道闸门，
	// 它们是同一 span 内的多个里程碑，不是"这个 span 失败了"。
	rec := withRecorder(t)
	ctx, span := Start(context.Background(), SpanLedger, "append")
	RecordLedgerGate(ctx, span, "G-3", false, "evidence strength insufficient")
	span.End()

	ended := rec.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected 1 span, got %d", len(ended))
	}
	events := ended[0].Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Name != "ledger.gate" {
		t.Fatalf("event name = %q, want ledger.gate", events[0].Name)
	}
	if !hasAttr(events[0].Attributes, "aleth.ledger.gate", "G-3") {
		t.Fatalf("gate id missing from event: %v", events[0].Attributes)
	}
	if !hasAttr(events[0].Attributes, "aleth.ledger.passed", false) {
		t.Fatalf("pass/fail missing from event: %v", events[0].Attributes)
	}
}

func TestSpanFromContextWithoutSpanIsNonNil(t *testing.T) {
	// OTel 的约定：无 span 时返回 **noop span**（非 nil），
	// 这样 `span.End()` 之类的调用不必到处判空。
	Init(nil, "")
	span := SpanFromContext(context.Background())
	if span == nil {
		t.Fatal("SpanFromContext must return a noop span, not nil")
	}
	if span.SpanContext().IsValid() {
		t.Fatal("a noop span must not have a valid span context")
	}
}

func TestAttributeKeysAreStable(t *testing.T) {
	// ★ 属性键是**对外契约**：已导出的 trace 用它们做查询与聚合，
	// 改名会让历史 trace 与看板失联。因此取值必须被测试锁死。
	for _, tc := range []struct{ got, want string }{
		{AttrSpanKind, "aleth.span_kind"},
		{AttrSessionID, "aleth.session_id"},
		{AttrTaskID, "aleth.task_id"},
		{AttrAgentID, "aleth.agent_id"},
		{AttrExecID, "aleth.exec_id"},
		{AttrDecisionID, "aleth.scope_decision_id"},
	} {
		if tc.got != tc.want {
			t.Errorf("attribute key changed: got %q want %q "+
				"(changing it breaks queries against already-exported traces)", tc.got, tc.want)
		}
	}
}

func TestAllSpanKindsHaveDistinctNonEmptyValues(t *testing.T) {
	// 分层标识必须唯一 —— 否则 trace 里无法按层过滤。
	kinds := []SpanKind{
		SpanOrchestrate, SpanAperture, SpanLedger, SpanMap, SpanIngest,
		SpanScope, SpanGateway, SpanSandbox, SpanGovernor,
	}
	seen := map[SpanKind]bool{}
	for _, k := range kinds {
		if k == "" {
			t.Error("span kind must not be empty")
		}
		if seen[k] {
			t.Errorf("duplicate span kind %q", k)
		}
		seen[k] = true
	}
	if len(seen) != 9 {
		t.Errorf("expected 9 span kinds (one per architectural layer), got %d", len(seen))
	}
}

func TestTracerDoesNotPanicBeforeInit(t *testing.T) {
	// 未 Init 就调 Tracer/Start 必须安全 —— 包级 var 的默认值是
	// otel 的全局 noop provider。
	Init(nil, "")
	_, span := Start(context.Background(), SpanIngest, "probe")
	if span == nil {
		t.Fatal("Start must return a usable (noop) span even when uninitialized")
	}
	span.End()
}

// hasAttr 报告属性集合里是否存在 (key, value)。
//
// value 用 any 比较：OTel 的 attribute.Value 有自己的等价语义，
// 直接 `==` 不可靠，因此统一经 AsInterface() 取原始值再比。
func hasAttr(attrs []attribute.KeyValue, key string, value any) bool {
	for _, a := range attrs {
		if string(a.Key) == key && a.Value.AsInterface() == value {
			return true
		}
	}
	return false
}

var _ trace.Span = trace.SpanFromContext(context.Background())
var _ = otel.Tracer
