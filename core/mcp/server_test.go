package mcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"google.golang.org/grpc"
)

// 本文件是 MCP server 的测试（06 §3.4）。
//
// 最关键的一组断言：**MCP 不得有绕过闸门的路径**。
// 06 §3.4 原文："通过 MCP 暴露的能力必须与 WebUI/CLI 遵循完全相同的
// 闸门与范围校验，不得有绕过路径。"
//
// 因此测试的重点不是"每个工具能返回数据"，而是
// "**未经闸门放行的执行一律不发生**"。

// ---- 测试替身 ----

// recordingGate 记录被授权的调用，并可编程拒绝。
type recordingGate struct {
	allow  bool
	reason string
	calls  []ToolCall
}

func (g *recordingGate) Authorize(_ context.Context, req ToolCall) error {
	g.calls = append(g.calls, req)
	if !g.allow {
		return &ErrUnauthorized{Reason: g.reason}
	}
	return nil
}

// fakeIngest 是 IngestServiceClient 的最小替身。
//
// 只实现 MCP 用到的两三个方法；其余方法由内嵌的
// UnimplementedIngestServiceClient 兜底（`alethv1` 生成物提供）。
type fakeIngest struct {
	alethv1.IngestServiceClient
	executed   int
	lastReq    *alethv1.ToolRequest
	execErr    error
	adapters   []*alethv1.ListAdaptersResponse_AdapterInfo
	listCalled int
}

func (f *fakeIngest) Execute(_ context.Context, req *alethv1.ToolRequest, _ ...grpc.CallOption) (*alethv1.EvidenceSpectrum, error) {
	f.executed++
	f.lastReq = req
	if f.execErr != nil {
		return nil, f.execErr
	}
	return &alethv1.EvidenceSpectrum{
		SpectrumId: "sp_1",
		ExecId:     "ex_1",
		Entities:   []*alethv1.EntityDraft{{Kind: alethv1.EntityKind_ASSET}},
		Quality:    &alethv1.ParseQuality{Coverage: 0.99},
	}, nil
}

func (f *fakeIngest) ListAdapters(_ context.Context, _ *alethv1.ListAdaptersRequest, _ ...grpc.CallOption) (*alethv1.ListAdaptersResponse, error) {
	f.listCalled++
	return &alethv1.ListAdaptersResponse{Adapters: f.adapters}, nil
}

// ---- ★ 无绕过路径（06 §3.4 的核心约束）----

func TestDefaultGateRefusesEverything(t *testing.T) {
	// ★ 未配置闸门时**拒绝一切**（不是放行）。
	//
	// MCP 的调用方是外部 agent（Claude Desktop / Cursor），
	// 它们不受本项目的红线约束。因此"未配置"必须是拒绝 ——
	// 与 08 §1.1「无凭证不启动」同一思路。
	s := NewServer(nil, Deps{Ingest: &fakeIngest{}})
	_, err := s.ExecuteTool(context.Background(), ExecuteToolInput{
		ToolName: "nmap", Target: "10.0.0.1", CallerID: "external-agent",
	})
	if err == nil {
		t.Fatal("a nil gate must refuse everything, not allow")
	}
	var un *ErrUnauthorized
	if !errors.As(err, &un) {
		t.Fatalf("want ErrUnauthorized, got %T: %v", err, err)
	}
	if !strings.Contains(un.Reason, "no gate configured") {
		t.Fatalf("refusal must explain the cause: %q", un.Reason)
	}
}

func TestRefusedCallNeverReachesIngest(t *testing.T) {
	// ★ 最关键的一条：闸门拒绝时，**工具绝不能被执行**。
	//
	// 若这条失败，说明闸门是"事后告警"而不是"事前阻断" ——
	// 那正是 06 §3.4 要防的绕过路径。
	ing := &fakeIngest{}
	g := &recordingGate{allow: false, reason: "target outside authorized scope"}
	s := NewServer(g, Deps{Ingest: ing})

	_, err := s.ExecuteTool(context.Background(), ExecuteToolInput{
		ToolName: "nmap", Target: "8.8.8.8", CallerID: "external-agent",
	})
	if err == nil {
		t.Fatal("a refused call must return an error")
	}
	if ing.executed != 0 {
		t.Fatalf("REFUSED CALL STILL REACHED THE TOOL: executed=%d "+
			"(06 §3.4 forbids any MCP bypass path)", ing.executed)
	}
	if !strings.Contains(err.Error(), "outside authorized scope") {
		t.Fatalf("the refusal reason must propagate: %v", err)
	}
}

func TestGateSeesOriginalIntentBeforeExecution(t *testing.T) {
	// 闸门必须看到**原始意图**（工具名 / 目标 / 参数），
	// 而不是参数拼装后的结果 —— 否则"闸门能看到什么"取决于拼装逻辑。
	ing := &fakeIngest{}
	g := &recordingGate{allow: true}
	s := NewServer(g, Deps{Ingest: ing})

	_, err := s.ExecuteTool(context.Background(), ExecuteToolInput{
		SessionID: "s1", CallerID: "agent-x", ToolName: "nuclei",
		Target: "192.0.2.10", TaskID: "t1",
		Params: map[string]string{"target": "192.0.2.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.calls) != 1 {
		t.Fatalf("gate must be called exactly once, got %d", len(g.calls))
	}
	c := g.calls[0]
	if c.ToolName != "nuclei" || c.Target != "192.0.2.10" {
		t.Fatalf("gate must see the original intent, got %+v", c)
	}
	if c.CallerID != "agent-x" {
		// 调用方标识用于审计 —— 事后要能区分"WebUI 点的"与"外部 agent 调用的"。
		t.Fatalf("gate must see the caller id for audit, got %q", c.CallerID)
	}
	if ing.executed != 1 {
		t.Fatalf("an allowed call must reach the tool exactly once, got %d", ing.executed)
	}
}

func TestGateRunsBeforeExecution(t *testing.T) {
	// 闸门在工具执行**之前** —— 顺序反了就等于没有闸门。
	ing := &fakeIngest{}
	g := &recordingGate{allow: true}
	s := NewServer(g, Deps{Ingest: ing})
	if _, err := s.ExecuteTool(context.Background(), ExecuteToolInput{
		ToolName: "nmap", Target: "192.0.2.1", CallerID: "a",
	}); err != nil {
		t.Fatal(err)
	}
	if len(g.calls) == 0 {
		t.Fatal("gate was never consulted")
	}
}

// ---- 只读工具不需闸门（它们不产生副作用）----

func TestReadOnlyToolsDoNotRequireGate(t *testing.T) {
	// 只读工具（project / assemble / trace）不改状态，
	// 因此不经闸门 —— 但它们在 Deps 缺失时**显式失败**，不返回空数据。
	s := NewServer(nil, Deps{})
	if _, err := s.ProjectMindMap(context.Background(), ProjectInput{}); err == nil {
		t.Fatal("project without PrismService must fail explicitly")
	}
	if _, err := s.AssembleContext(context.Background(), AssembleInput{}); err == nil {
		t.Fatal("assemble without ApertureService must fail explicitly")
	}
	if _, err := s.TraceFinding(context.Background(), TraceFindingInput{FindingID: "f1"}); err == nil {
		t.Fatal("trace without LedgerService must fail explicitly")
	}
	if _, err := s.ListAdapters(context.Background(), struct{}{}); err == nil {
		t.Fatal("list_adapters without IngestService must fail explicitly")
	}
}

func TestTraceFindingRequiresFindingID(t *testing.T) {
	s := NewServer(nil, Deps{})
	if _, err := s.TraceFinding(context.Background(), TraceFindingInput{FindingID: "  "}); err == nil {
		t.Fatal("empty finding_id must be refused")
	}
}

// ---- 工具行为 ----

func TestExecuteToolPassesParamsThrough(t *testing.T) {
	ing := &fakeIngest{}
	s := NewServer(&recordingGate{allow: true}, Deps{Ingest: ing})
	res, err := s.ExecuteTool(context.Background(), ExecuteToolInput{
		SessionID: "s1", ToolName: "nmap", Target: "192.0.2.1", TaskID: "t1",
		Params: map[string]string{"target": "192.0.2.1", "ports": "80"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ing.lastReq.GetToolName() != "nmap" || ing.lastReq.GetTaskId() != "t1" {
		t.Fatalf("request not passed through: %+v", ing.lastReq)
	}
	if ing.lastReq.GetParams()["ports"] != "80" {
		t.Fatalf("params not passed through: %+v", ing.lastReq.GetParams())
	}
	if !strings.Contains(res.Text, "nmap") {
		t.Fatalf("result text should summarise the run: %q", res.Text)
	}
}

func TestExecuteToolPropagatesToolErrors(t *testing.T) {
	// 工具执行失败必须原样上抛（P-4：不吞、不降级）。
	ing := &fakeIngest{execErr: errors.New("TOOL_VERSION_MISMATCH: nmap 7.20 outside 7.40-7.99")}
	s := NewServer(&recordingGate{allow: true}, Deps{Ingest: ing})
	_, err := s.ExecuteTool(context.Background(), ExecuteToolInput{
		ToolName: "nmap", Target: "192.0.2.1",
	})
	if err == nil {
		t.Fatal("tool error must propagate")
	}
	if !strings.Contains(err.Error(), "TOOL_VERSION_MISMATCH") {
		t.Fatalf("the contract error code must survive: %v", err)
	}
}

func TestListAdaptersIsSorted(t *testing.T) {
	// 确定性顺序（P-5）—— 外部 agent 会缓存这个列表。
	ing := &fakeIngest{adapters: []*alethv1.ListAdaptersResponse_AdapterInfo{
		{ToolName: "nuclei"}, {ToolName: "httpx"}, {ToolName: "nmap"},
	}}
	s := NewServer(nil, Deps{Ingest: ing})
	res, err := s.ListAdapters(context.Background(), struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Text != "adapters: httpx, nmap, nuclei" {
		t.Fatalf("adapters must be sorted deterministically: %q", res.Text)
	}
}

// ---- 归因不一致必须显著（P0）----

func TestRenderChainFlagsAttributionMismatch(t *testing.T) {
	chain := &alethv1.TracedEvidenceChain{
		FindingId:             "f1",
		AttributionConsistent: false,
		AttributionErrors: []*alethv1.Error{
			{Message: "evidence target does not match assertion target"},
		},
	}
	text := renderChain(chain)
	if !strings.Contains(text, "MISMATCH") {
		t.Fatalf("attribution mismatch must be flagged prominently: %q", text)
	}
	if !strings.Contains(text, "P0") {
		t.Fatalf("the mismatch must be marked P0 (AIxCC penalises wrong attribution): %q", text)
	}
}

func TestRenderChainReportsConsistent(t *testing.T) {
	chain := &alethv1.TracedEvidenceChain{
		FindingId: "f1", AttributionConsistent: true,
		Assertions: []*alethv1.Assertion{{AssertionId: "a1"}},
	}
	text := renderChain(chain)
	if !strings.Contains(text, "consistent") {
		t.Fatalf("expected a consistent attribution line: %q", text)
	}
	if strings.Contains(text, "MISMATCH") {
		t.Fatalf("consistent chain must not be flagged: %q", text)
	}
}

// ---- 闸门实现的接口约束 ----

func TestDenyAllGateSatisfiesInterface(t *testing.T) {
	var _ Gate = NewDenyAllGate()
	var _ Gate = (*recordingGate)(nil)
}
