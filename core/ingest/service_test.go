package ingest

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"github.com/AperturePrism/aleth/core/gateway"
	"github.com/AperturePrism/aleth/core/scopekernel"
)

// ---- 测试桩：只 mock 外部边界（Scope/Gateway/Sandbox），被验证对象
//（适配器、解析器、折叠、Service 编排）全部走真实代码（09 §6 #4）。----

type fakeScope struct {
	deny       bool
	lastTarget string
	lastTool   string
}

func (f *fakeScope) CheckToolParam(_ context.Context, toolName, target string) (string, error) {
	f.lastTool, f.lastTarget = toolName, target
	if f.deny {
		return "", ErrScopeViolation
	}
	return "decision_1", nil
}

type fakeGateway struct {
	failTokenize bool
	leakOutput   bool
	tokenized    map[string]string
}

func (f *fakeGateway) TokenizeParams(_ context.Context, _ string, params map[string]string) (map[string]string, error) {
	if f.failTokenize {
		return nil, errors.New("tokenize backend down")
	}
	f.tokenized = params
	return params, nil
}

func (f *fakeGateway) ScanOutbound(_ context.Context, _ string, raw []byte) error {
	if f.leakOutput {
		return ErrPrivacyLeak
	}
	return nil
}

type fakeSandbox struct {
	fail    bool
	gotArgv []string
}

func (f *fakeSandbox) Execute(_ context.Context, _ string, argv []string) (string, []byte, error) {
	if f.fail {
		return "", nil, errors.New("sandbox down")
	}
	f.gotArgv = argv
	return "exec_fixed_0001", []byte("output"), nil
}

func probeOK(_ context.Context, toolName string) (string, error) {
	return "Nmap version 7.94 run at " + time.Now().Format(time.RFC3339), nil
}

func newTestService(t *testing.T, deps Deps) (*Service, *fakeSandbox, *fakeScope, *fakeGateway) {
	t.Helper()
	c, err := NewCatalog(nmapAdapterForTest())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewRawStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sandbox := &fakeSandbox{}
	scope := &fakeScope{}
	gw := &fakeGateway{}
	if deps.Sandbox == nil {
		deps.Sandbox = sandbox
	}
	if deps.Scope == nil {
		deps.Scope = scope
	}
	if deps.Gateway == nil {
		deps.Gateway = gw
	}
	if deps.VersionProbe == nil {
		deps.VersionProbe = probeOK
	}
	if deps.Now == nil {
		deps.Now = func() time.Time { return time.Unix(1769328000, 0) }
	}
	return NewService(c, deps, store), sandbox, scope, gw
}

func httpxAdapterForTest() Adapter {
	return &BaseAdapter{
		ToolName: "httpx",
		Versions: VersionRange{Min: "1.3.0", Max: "1.6.99"},
		SchemaDef: &ParamSchema{Params: []ParamDef{
			{Name: "target", Type: ParamTarget, Required: true, ScopeChecked: true},
		}},
	}
}

func testParams() map[string]string {
	return map[string]string{"target": "192.0.2.10", "ports": "80", "timing": "T3"}
}

// nmapAdapterForTest 与 httpxAdapterForTest：service_test.go 属于内部测试包
// （package ingest），import core/ingest/{nmap,...} 会产生 import cycle
// （子包 import 本包），因此在测试内构造等价适配器。适配器本身的正确性
// 由各自包的测试保证 —— 本文件只验证 Service 的编排与 fail-closed 语义。
func nmapAdapterForTest() Adapter {
	return &BaseAdapter{
		ToolName: "nmap",
		Versions: VersionRange{Min: "7.40", Max: "7.99"},
		SchemaDef: &ParamSchema{Params: []ParamDef{
			{Name: "target", Type: ParamTarget, Required: true, ScopeChecked: true},
			{Name: "ports", Type: ParamPortRange, ArgFlag: "-p"},
			{Name: "timing", Type: ParamEnum, Choices: []string{"T2", "T3", "T4"}, ArgFlag: "-T"},
		}},
		StaticArgs: []string{"-oX", "-"},
		ParseFn: func(raw []byte, execID string) (*alethv1.EvidenceSpectrum, error) {
			return &alethv1.EvidenceSpectrum{
				ExecId:  execID,
				Quality: &alethv1.ParseQuality{Coverage: 1.0},
			}, nil
		},
	}
}

func TestExecuteHappyPath(t *testing.T) {
	svc, sandbox, scope, gw := newTestService(t, Deps{})
	sp, err := svc.Execute(context.Background(), &alethv1.ToolRequest{
		ToolName: "nmap", Params: testParams(), SessionId: "sess_1", TaskId: "task_1",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// 范围校验先于一切执行动作，且拿到裁决 ID（05 §7.1 步骤 3）。
	if scope.lastTool != "nmap" || scope.lastTarget != "192.0.2.10" {
		t.Fatalf("scope check got tool=%q target=%q", scope.lastTool, scope.lastTarget)
	}
	// 参数脱敏发生在执行之前（05 §7.1 步骤 4）。
	if _, ok := gw.tokenized["target"]; !ok {
		t.Fatal("tokenize must run before sandbox execute")
	}
	// exec_id 来自 Sandbox（M1 N6：L0 不自造）。
	if sp.ExecId != "exec_fixed_0001" {
		t.Fatalf("exec_id = %q", sp.ExecId)
	}
	// ToolInvocation 完整且可复现（05 §2.1）。
	if sp.Tool == nil || len(sp.Tool.Argv) == 0 || sp.Tool.ArgvHash == "" {
		t.Fatalf("tool invocation incomplete: %#v", sp.Tool)
	}
	if sp.Tool.ScopeDecisionId != "decision_1" {
		t.Fatalf("scope_decision_id = %q", sp.Tool.ScopeDecisionId)
	}
	if !strings.HasPrefix(sp.Tool.ArgvHash, "") {
		t.Fatal("argv hash format")
	}
	// raw 引用与存储一致。
	if sp.Raw == nil || sp.Raw.ContentHash == "" || sp.Raw.StorageUri == "" || sp.Raw.SizeBytes != 6 {
		t.Fatalf("raw ref = %#v", sp.Raw)
	}
	if sp.SpectrumId == "" || !strings.HasPrefix(sp.SpectrumId, "sp_") {
		t.Fatalf("spectrum_id = %q", sp.SpectrumId)
	}
	if sp.ObservedAt == nil || sp.ObservedAt.AsTime().Unix() != 1769328000 {
		t.Fatalf("observed_at = %v", sp.ObservedAt)
	}
	// argv 确定性渲染（map 迭代顺序无关）。
	want := []string{"nmap", "-oX", "-", "192.0.2.10", "-p", "80", "-T", "T3"}
	for i, v := range want {
		if i >= len(sandbox.gotArgv) || sandbox.gotArgv[i] != v {
			t.Fatalf("argv = %v, want prefix %v", sandbox.gotArgv, want)
		}
	}
}

func TestExecuteScopeDenyFailsClosed(t *testing.T) {
	svc, sandbox, _, _ := newTestService(t, Deps{})
	// 显式 deny；Scope 返回 ErrScopeViolation → SCOPE_VIOLATION。
	svc.deps.Scope.(*fakeScope).deny = true
	_, err := svc.Execute(context.Background(), &alethv1.ToolRequest{ToolName: "nmap", Params: testParams()})
	assertGRPC(t, err, codes.PermissionDenied, alethv1.ErrorCode_SCOPE_VIOLATION)
	if sandbox.gotArgv != nil {
		t.Fatal("denied request must never reach the sandbox (fail-closed)")
	}
}

func TestExecuteDepsMissingFailsClosed(t *testing.T) {
	// 任何依赖缺失都必须显式失败 —— 绝不允许绕过范围校验直接执行工具。
	for name, tc := range map[string]struct {
		mutate func(d *Deps)
	}{
		"no scope":   {func(d *Deps) { d.Scope = nil }},
		"no gateway": {func(d *Deps) { d.Gateway = nil }},
		"no sandbox": {func(d *Deps) { d.Sandbox = nil }},
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := NewCatalog(nmapAdapterForTest())
			store, _ := NewRawStore(t.TempDir())
			deps := Deps{VersionProbe: probeOK}
			tc.mutate(&deps)
			svc := NewService(c, deps, store)
			_, err := svc.Execute(context.Background(), &alethv1.ToolRequest{ToolName: "nmap", Params: testParams()})
			assertGRPC(t, err, codes.Unavailable, alethv1.ErrorCode_UPSTREAM_UNAVAILABLE)
		})
	}
}

func TestExecuteGatewayFailureRefusesExecution(t *testing.T) {
	svc, sandbox, _, _ := newTestService(t, Deps{})
	svc.deps.Gateway.(*fakeGateway).failTokenize = true
	_, err := svc.Execute(context.Background(), &alethv1.ToolRequest{ToolName: "nmap", Params: testParams()})
	assertGRPC(t, err, codes.Unavailable, alethv1.ErrorCode_UPSTREAM_UNAVAILABLE)
	if sandbox.gotArgv != nil {
		t.Fatal("tokenize failure must refuse execution, not degrade (M1 §3)")
	}
}

func TestExecuteLeakBlocked(t *testing.T) {
	svc, _, _, _ := newTestService(t, Deps{})
	svc.deps.Gateway.(*fakeGateway).leakOutput = true
	_, err := svc.Execute(context.Background(), &alethv1.ToolRequest{ToolName: "nmap", Params: testParams()})
	assertGRPC(t, err, codes.FailedPrecondition, alethv1.ErrorCode_PRIVACY_LEAK_DETECTED)
}

func TestExecuteVersionMismatch(t *testing.T) {
	svc, _, _, _ := newTestService(t, Deps{})
	svc.deps.VersionProbe = func(_ context.Context, _ string) (string, error) {
		return "Nmap version 9.01", nil // 高于适配器声明区间 [7.40, 7.99]
	}
	_, err := svc.Execute(context.Background(), &alethv1.ToolRequest{ToolName: "nmap", Params: testParams()})
	assertGRPC(t, err, codes.FailedPrecondition, alethv1.ErrorCode_TOOL_VERSION_MISMATCH)
}

func TestExecuteSandboxEmptyExecID(t *testing.T) {
	// Sandbox 返回空 exec_id → 证据不可溯源 → EVIDENCE_INVALID。
	svc, _, _, _ := newTestService(t, Deps{})
	svc.deps.Sandbox = stubSandbox{execID: ""}
	_, err := svc.Execute(context.Background(), &alethv1.ToolRequest{ToolName: "nmap", Params: testParams()})
	assertGRPC(t, err, codes.Internal, alethv1.ErrorCode_EVIDENCE_INVALID)
}

type stubSandbox struct{ execID string }

func (s stubSandbox) Execute(context.Context, string, []string) (string, []byte, error) {
	return s.execID, []byte("out"), nil
}

func TestExecuteUnknownTool(t *testing.T) {
	svc, _, _, _ := newTestService(t, Deps{})
	_, err := svc.Execute(context.Background(), &alethv1.ToolRequest{
		ToolName: "masscan", Params: testParams(),
	})
	assertGRPC(t, err, codes.InvalidArgument, alethv1.ErrorCode_INVALID_ARGUMENT)
}

func TestExecuteBadParams(t *testing.T) {
	// M1 §4.3 翻车点 3：参数名不匹配必须显式 INVALID_ARGUMENT，禁止静默。
	svc, _, _, _ := newTestService(t, Deps{})
	_, err := svc.Execute(context.Background(), &alethv1.ToolRequest{
		ToolName: "nmap", Params: map[string]string{"query": "192.0.2.1"},
	})
	assertGRPC(t, err, codes.InvalidArgument, alethv1.ErrorCode_INVALID_ARGUMENT)
}

func TestValidateTool(t *testing.T) {
	t.Run("available", func(t *testing.T) {
		svc, _, _, _ := newTestService(t, Deps{})
		resp, err := svc.ValidateTool(context.Background(), &alethv1.ValidateToolRequest{ToolName: "nmap"})
		if err != nil {
			t.Fatal(err)
		}
		if !resp.Available || resp.VersionMismatch || resp.DetectedVersion != "7.94.0" {
			t.Fatalf("resp = %#v", resp)
		}
	})
	t.Run("version mismatch fail-closed", func(t *testing.T) {
		svc, _, _, _ := newTestService(t, Deps{})
		svc.deps.VersionProbe = func(context.Context, string) (string, error) { return "8.5.0", nil }
		resp, err := svc.ValidateTool(context.Background(), &alethv1.ValidateToolRequest{ToolName: "nmap"})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Available || !resp.VersionMismatch || resp.Error.GetCode() != alethv1.ErrorCode_TOOL_VERSION_MISMATCH {
			t.Fatalf("resp = %#v", resp)
		}
	})
	t.Run("probe failure", func(t *testing.T) {
		svc, _, _, _ := newTestService(t, Deps{})
		svc.deps.VersionProbe = func(context.Context, string) (string, error) { return "", errors.New("not found") }
		resp, _ := svc.ValidateTool(context.Background(), &alethv1.ValidateToolRequest{ToolName: "nmap"})
		if resp.Available || resp.Error.GetCode() != alethv1.ErrorCode_UPSTREAM_UNAVAILABLE {
			t.Fatalf("resp = %#v", resp)
		}
	})
	t.Run("unknown tool", func(t *testing.T) {
		svc, _, _, _ := newTestService(t, Deps{})
		resp, _ := svc.ValidateTool(context.Background(), &alethv1.ValidateToolRequest{ToolName: "masscan"})
		if resp.Available || resp.Error.GetCode() != alethv1.ErrorCode_INVALID_ARGUMENT {
			t.Fatalf("resp = %#v", resp)
		}
	})
}

func TestListAdapters(t *testing.T) {
	c, _ := NewCatalog(nmapAdapterForTest(), httpxAdapterForTest())
	store, _ := NewRawStore(t.TempDir())
	svc := NewService(c, Deps{VersionProbe: probeOK}, store)
	resp, err := svc.ListAdapters(context.Background(), &alethv1.ListAdaptersRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Total != 2 || len(resp.Adapters) != 2 {
		t.Fatalf("resp = %#v", resp)
	}
	if resp.Adapters[0].ToolName != "httpx" || resp.Adapters[1].ToolName != "nmap" {
		t.Fatalf("adapters not in dictionary order: %#v", resp.Adapters)
	}
	if got := resp.Adapters[1].ParamNames; len(got) != 3 || got[0] != "target" {
		t.Fatalf("param names = %v", got)
	}
	if got := resp.Adapters[1].RequiredParams; len(got) != 1 || got[0] != "target" {
		t.Fatalf("required params = %v", got)
	}
	// 分页。
	page, _ := svc.ListAdapters(context.Background(), &alethv1.ListAdaptersRequest{Offset: 1, Limit: 1})
	if len(page.Adapters) != 1 || page.Adapters[0].ToolName != "nmap" {
		t.Fatalf("paged resp = %#v", page)
	}
}

func TestFoldOffDebugSwitch(t *testing.T) {
	// fold=off 调试开关（M1 §8）：展开后每条 SpectrumLine 的 fold_count 恒为 1。
	svc, _, _, _ := newTestService(t, Deps{})
	svc.SetFoldOff(true)
	sp, err := svc.Execute(context.Background(), &alethv1.ToolRequest{ToolName: "nmap", Params: testParams()})
	if err != nil {
		t.Fatal(err)
	}
	for _, ln := range sp.Lines {
		if ln.FoldCount > 1 {
			t.Fatalf("fold=off but fold_count = %d", ln.FoldCount)
		}
	}
}

func TestGRPCWire(t *testing.T) {
	// 接线验证：Service 作为 IngestServiceServer 注册到 gRPC 后可被客户端调用
	//（即 registry.go 替换 unimplementedIngest 后的运行形态）。
	svc, _, _, _ := newTestService(t, Deps{})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	alethv1.RegisterIngestServiceServer(gs, svc)
	go gs.Serve(lis)
	defer gs.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := alethv1.NewIngestServiceClient(conn)
	resp, err := client.Execute(context.Background(), &alethv1.ToolRequest{ToolName: "nmap", Params: testParams()})
	if err != nil {
		t.Fatalf("gRPC Execute: %v", err)
	}
	if resp.Tool == nil || resp.Tool.ToolName != "nmap" {
		t.Fatalf("resp = %#v", resp)
	}
	list, err := client.ListAdapters(context.Background(), &alethv1.ListAdaptersRequest{})
	if err != nil || list.Total != 1 {
		t.Fatalf("gRPC ListAdapters: %v %#v", err, list)
	}
	// 三侧契约仍在：Unimplemented 兜底不再命中。
	if _, err := client.ValidateTool(context.Background(), &alethv1.ValidateToolRequest{ToolName: "nmap"}); err != nil {
		t.Fatalf("gRPC ValidateTool: %v", err)
	}
}

// ---- 断言辅助 ----

func assertGRPC(t *testing.T, err error, want codes.Code, wantEC alethv1.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("want gRPC error %v/%v, got nil", want, wantEC)
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != want {
		t.Fatalf("gRPC code = %v (%v), want %v", st.Code(), err, want)
	}
	details := st.Details()
	for _, d := range details {
		if e, ok := d.(*alethv1.Error); ok {
			if e.Code == wantEC {
				return
			}
			t.Fatalf("error detail code = %v, want %v", e.Code, wantEC)
		}
	}
	t.Fatalf("no alethv1.Error detail in %v (details: %d)", err, len(details))
}

// TestExecuteWithRealScopeKernel 把 I3 的真实 Scope Kernel（而非测试桩）
// 注入 Deps：越界 target 在 Execute 入口被拒（Q4 语义在 Ingest 层的验证）。
// scopekernel 不依赖 ingest —— 无 import cycle。
func TestExecuteWithRealScopeKernel(t *testing.T) {
	scope, err := scopekernel.ParseScope([]byte(`
targets:
  include:
    - cidr: "10.40.23.0/24"
  exclude:
    - cidr: "10.40.23.128/25"
`))
	if err != nil {
		t.Fatal(err)
	}
	kernel := scopekernel.NewKernel(scope, nil, scopekernel.RateLimit{PerMinute: 1000})
	gw := gateway.NewGateway()
	c, _ := NewCatalog(nmapAdapterForTest())
	store, _ := NewRawStore(t.TempDir())
	svc := NewService(c, Deps{
		Scope:        realScopeChecker{kernel},
		Gateway:      realGateway{gw},
		VersionProbe: probeOK,
	}, store)

	// 界内 → 通过 scope 校验，走到 Sandbox 依赖（I3 未交付）→ 显式
	// UPSTREAM_UNAVAILABLE（不是 SCOPE_VIOLATION）—— 范围校验与执行
	// 依赖的失败必须可区分。
	_, err = svc.Execute(context.Background(), &alethv1.ToolRequest{
		ToolName: "nmap", Params: map[string]string{"target": "10.40.23.5"},
	})
	assertGRPC(t, err, codes.Unavailable, alethv1.ErrorCode_UPSTREAM_UNAVAILABLE)

	// 越界（exclude 段）→ SCOPE_VIOLATION。
	_, err = svc.Execute(context.Background(), &alethv1.ToolRequest{
		ToolName: "nmap", Params: map[string]string{"target": "10.40.23.200"},
	})
	assertGRPC(t, err, codes.PermissionDenied, alethv1.ErrorCode_SCOPE_VIOLATION)

	// 默认拒绝（不在任何规则里）。
	_, err = svc.Execute(context.Background(), &alethv1.ToolRequest{
		ToolName: "nmap", Params: map[string]string{"target": "192.0.2.1"},
	})
	assertGRPC(t, err, codes.PermissionDenied, alethv1.ErrorCode_SCOPE_VIOLATION)
}

// realScopeChecker/realGateway 是 core/ingest.ScopeChecker/PrivacyGateway
// 的真实组件适配（与 cmd/alethd/adapters.go 同构；此处内联以保持测试自足）。
type realScopeChecker struct{ kernel *scopekernel.Kernel }

func (a realScopeChecker) CheckToolParam(_ context.Context, _, target string) (string, error) {
	v := a.kernel.Check("test-session", target)
	if !v.Allowed {
		return "", ErrScopeViolation
	}
	return v.DecisionID, nil
}

type realGateway struct{ gw *gateway.Gateway }

func (a realGateway) TokenizeParams(_ context.Context, _ string, params map[string]string) (map[string]string, error) {
	return params, nil
}

func (a realGateway) ScanOutbound(_ context.Context, _ string, raw []byte) error {
	if len(a.gw.ScanOutbound(string(raw))) > 0 {
		return ErrPrivacyLeak
	}
	return nil
}
