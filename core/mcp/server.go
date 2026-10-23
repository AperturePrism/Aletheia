package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// Server 把 Aletheia 的能力暴露为 MCP server（06 §3.4 的"作为提供者"）。
//
// # 暴露什么、不暴露什么
//
// **暴露**（只读 + 受闸门约束的执行）：
//   - 证据链查询（finding → assertions → evidence）
//   - 心智地图投影（实体与关系）
//   - 冲突矩阵（三路融合结果）
//   - 范围摘要（授权状态）
//   - 工具执行（经闸门 → IngestService，与 WebUI 完全同一条路径）
//
// **不暴露**：
//   - 任何"替代界面"的东西（06 §3.4：不把 UI 外包给 MCP 客户端）
//   - 任何绕过闸门的执行入口
//   - 终止会话（09 §R6：终止唯一入口是 TerminationService，
//     且它是**内部**仲裁通道；外部 agent 不应能直接触发）
type Server struct {
	gate Gate
	deps Deps
}

// Deps 是 MCP server 依赖的既有服务（**不新建能力**，只复用）。
type Deps struct {
	Ledger   alethv1.LedgerServiceClient
	Prism    alethv1.PrismServiceClient
	Aperture alethv1.ApertureServiceClient
	Scope    alethv1.ScopeServiceClient
	Ingest   alethv1.IngestServiceClient
}

// NewServer 装配 MCP server。
//
// `gate` 为 nil 时使用**拒绝一切**的默认闸门 —— 见 NewDenyAllGate
// 的说明：MCP 的调用方是外部 agent，不受本项目约束，
// 因此"未配置"必须是拒绝。
func NewServer(gate Gate, deps Deps) *Server {
	if gate == nil {
		gate = NewDenyAllGate()
	}
	return &Server{gate: gate, deps: deps}
}

// ---- 工具输入/输出结构（MCP 的 Schema 由结构体标签生成）----

// TraceFindingInput 是 trace_finding 工具的参数。
type TraceFindingInput struct {
	SessionID string `json:"session_id" jsonschema:"the Aletheia session id,omitempty"`
	FindingID string `json:"finding_id" jsonschema:"the finding to trace back to raw evidence"`
}

// ProjectInput 是 project_mind_map 工具的参数。
type ProjectInput struct {
	SessionID   string `json:"session_id,omitempty" jsonschema:"the Aletheia session id"`
	Focus       string `json:"focus,omitempty" jsonschema:"focus entity id; empty = whole graph"`
	MaxHops     uint32 `json:"max_hops,omitempty" jsonschema:"graph traversal radius"`
	MaxEntities uint32 `json:"max_entities,omitempty" jsonschema:"entity cap"`
}

// AssembleInput 是 assemble_context 工具的参数。
type AssembleInput struct {
	SessionID      string `json:"session_id,omitempty" jsonschema:"the Aletheia session id"`
	TaskID         string `json:"task_id" jsonschema:"the task this context is for"`
	FocusHint      string `json:"focus_hint,omitempty" jsonschema:"task objective / hypothesis text"`
	BudgetTokens   uint32 `json:"budget_tokens" jsonschema:"hard token budget"`
	AllowDowngrade bool   `json:"allow_downgrade,omitempty" jsonschema:"allow automatic aperture narrowing"`
}

// ExecuteToolInput 是 execute_tool 工具的参数（**受闸门约束**）。
type ExecuteToolInput struct {
	SessionID string            `json:"session_id,omitempty" jsonschema:"the Aletheia session id"`
	CallerID  string            `json:"caller_id" jsonschema:"identifier of the external agent making this call (for audit)"`
	ToolName  string            `json:"tool_name" jsonschema:"registered tool adapter name; see list_adapters"`
	Target    string            `json:"target" jsonschema:"the target the tool will run against"`
	TaskID    string            `json:"task_id,omitempty" jsonschema:"optional task id for audit"`
	Params    map[string]string `json:"params,omitempty" jsonschema:"tool parameters; must match the adapter schema"`
}

// ToolResult 是统一的工具返回（文本 + 结构化 JSON）。
//
// MCP 的 content 是给客户端渲染的，因此这里同时给可读文本与结构化数据 ——
// 但**结构化数据不是界面替代品**（06 §3.4），只是让客户端能程序化消费。
type ToolResult struct {
	Text string `json:"text"`
	JSON string `json:"json,omitempty"`
}

// ---- 工具实现 ----

// TraceFinding 追溯证据链（只读）。
func (s *Server) TraceFinding(ctx context.Context, in TraceFindingInput) (*ToolResult, error) {
	if s.deps.Ledger == nil {
		return nil, fmt.Errorf("mcp: LedgerService is not wired; " +
			"evidence tracing requires the focalplane process (see docs/iterations/I2-交接.md)")
	}
	if strings.TrimSpace(in.FindingID) == "" {
		return nil, fmt.Errorf("mcp: finding_id is required")
	}
	chain, err := s.deps.Ledger.TraceFinding(ctx, &alethv1.TraceFindingRequest{
		FindingId: in.FindingID,
	})
	if err != nil {
		return nil, fmt.Errorf("mcp: trace finding: %w", err)
	}
	blob, _ := json.Marshal(chain)
	return &ToolResult{
		Text: renderChain(chain),
		JSON: string(blob),
	}, nil
}

// ProjectMindMap 投影心智地图（只读）。
func (s *Server) ProjectMindMap(ctx context.Context, in ProjectInput) (*ToolResult, error) {
	if s.deps.Prism == nil {
		return nil, fmt.Errorf("mcp: PrismService is not wired")
	}
	sub, err := s.deps.Prism.Project(ctx, &alethv1.ProjectRequest{
		BranchId:    "",
		Focus:       in.Focus,
		MaxHops:     in.MaxHops,
		MaxEntities: in.MaxEntities,
	})
	if err != nil {
		return nil, fmt.Errorf("mcp: project: %w", err)
	}
	blob, _ := json.Marshal(sub)
	return &ToolResult{
		Text: fmt.Sprintf("entities=%d relations=%d snapshot=%s",
			len(sub.GetEntities()), len(sub.GetRelations()), sub.GetSnapshotId()),
		JSON: string(blob),
	}, nil
}

// AssembleContext 按光圈装配上下文（只读）。
func (s *Server) AssembleContext(ctx context.Context, in AssembleInput) (*ToolResult, error) {
	if s.deps.Aperture == nil {
		return nil, fmt.Errorf("mcp: ApertureService is not wired")
	}
	b, err := s.deps.Aperture.Assemble(ctx, &alethv1.AssembleRequest{
		TaskId:         in.TaskID,
		SessionId:      in.SessionID,
		FocusHint:      in.FocusHint,
		BudgetTokens:   in.BudgetTokens,
		AllowDowngrade: in.AllowDowngrade,
	})
	if err != nil {
		// 超预算是**预期内的显式拒绝**（M3 §2.2 N4 不允许截断）——
		// 原样上抛，让 MCP 客户端看到真实原因而不是"内部错误"。
		return nil, fmt.Errorf("mcp: assemble: %w", err)
	}
	blob, _ := json.Marshal(b)
	return &ToolResult{
		Text: fmt.Sprintf("aperture=%s entities=%d tokens=%d/%d omitted=%d",
			b.GetAperture().GetStop(), len(b.GetEntities()),
			b.GetEstimatedTokens(), b.GetBudgetTokens(),
			len(b.GetTruncatedDimensions())),
		JSON: string(blob),
	}, nil
}

// ExecuteTool 执行工具（★ **受闸门约束** —— 06 §3.4 的无绕过约束）。
//
// 这是唯一有副作用的 MCP 工具。它的路径与 WebUI/CLI **完全相同**：
//
//	Gate.Authorize（复用 ScopeService / PrivacyGateway / Governor）
//	  → IngestService.Execute（内部再走 scope → tokenize → sandbox → 解析）
//
// 因此不存在"MCP 特有的宽松路径"。
func (s *Server) ExecuteTool(ctx context.Context, in ExecuteToolInput) (*ToolResult, error) {
	if s.deps.Ingest == nil {
		return nil, fmt.Errorf("mcp: IngestService is not wired")
	}
	call := ToolCall{
		SessionID: in.SessionID,
		ToolName:  in.ToolName,
		Target:    in.Target,
		Params:    in.Params,
		CallerID:  in.CallerID,
	}
	// ★ 闸门在**最前面**：参数校验、范围裁决、脱敏、预算预扣
	// 都在这里发生（由注入的实现复用既有服务）。
	//
	// 位置是刻意的 —— 放在参数拼装之后会让"闸门能看到什么"
	// 取决于拼装逻辑，而闸门必须看到**原始意图**。
	if err := s.gate.Authorize(ctx, call); err != nil {
		return nil, err
	}

	spec, err := s.deps.Ingest.Execute(ctx, &alethv1.ToolRequest{
		ToolName:  in.ToolName,
		Params:    in.Params,
		SessionId: in.SessionID,
		TaskId:    in.TaskID,
	})
	if err != nil {
		return nil, fmt.Errorf("mcp: execute %s: %w", in.ToolName, err)
	}
	blob, _ := json.Marshal(spec)
	return &ToolResult{
		Text: fmt.Sprintf("tool=%s spectrum=%s entities=%d coverage=%.2f",
			in.ToolName, spec.GetSpectrumId(), len(spec.GetEntities()),
			spec.GetQuality().GetCoverage()),
		JSON: string(blob),
	}, nil
}

// ListAdapters 列出可用工具适配器（只读，供外部 agent 发现能力）。
func (s *Server) ListAdapters(ctx context.Context, _ struct{}) (*ToolResult, error) {
	if s.deps.Ingest == nil {
		return nil, fmt.Errorf("mcp: IngestService is not wired")
	}
	res, err := s.deps.Ingest.ListAdapters(ctx, &alethv1.ListAdaptersRequest{})
	if err != nil {
		return nil, fmt.Errorf("mcp: list adapters: %w", err)
	}
	names := make([]string, 0, len(res.GetAdapters()))
	for _, a := range res.GetAdapters() {
		names = append(names, a.GetToolName())
	}
	sort.Strings(names) // 确定性顺序（P-5）
	blob, _ := json.Marshal(res)
	return &ToolResult{
		Text: "adapters: " + strings.Join(names, ", "),
		JSON: string(blob),
	}, nil
}

// ---- 渲染辅助 ----

func renderChain(chain *alethv1.TracedEvidenceChain) string {
	var b strings.Builder
	fmt.Fprintf(&b, "finding %s\n", chain.GetFindingId())
	fmt.Fprintf(&b, "  assertions: %d, evidence: %d, side-effects: %d\n",
		len(chain.GetAssertions()), len(chain.GetEvidence()), len(chain.GetSideEffects()))
	if chain.GetAttributionConsistent() {
		b.WriteString("  attribution: consistent\n")
	} else {
		// 归因不一致是 P0 级（AIxCC 错误关联重罚）—— 必须显著。
		b.WriteString("  attribution: *** MISMATCH (P0) ***\n")
		for _, e := range chain.GetAttributionErrors() {
			fmt.Fprintf(&b, "    - %s\n", e.GetMessage())
		}
	}
	return b.String()
}

// Register 把全部工具注册到 MCP server。
//
// 工具清单刻意**短**：MCP 是集成接口，不是界面（06 §3.4）。
// 每个工具都对应一个既有服务能力，没有"为了方便客户端"而新增的聚合接口。
func (s *Server) Register(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name: "trace_finding",
		Description: "Trace a finding back to its raw evidence (finding -> assertions -> evidence -> exec_id). " +
			"Read-only. Requires the focalplane process.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in TraceFindingInput) (*mcp.CallToolResult, any, error) {
		res, err := s.TraceFinding(ctx, in)
		return toCallResult(res, err)
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "project_mind_map",
		Description: "Project the mind map (the single source of truth) into a subgraph. " +
			"Returns entities and relations with their provenance and versions. Read-only.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProjectInput) (*mcp.CallToolResult, any, error) {
		res, err := s.ProjectMindMap(ctx, in)
		return toCallResult(res, err)
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "assemble_context",
		Description: "Assemble a token-budgeted context bundle for a task (the aperture projection). " +
			"Returns what was selected AND what was omitted. Never truncates: over-budget is an explicit error.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in AssembleInput) (*mcp.CallToolResult, any, error) {
		res, err := s.AssembleContext(ctx, in)
		return toCallResult(res, err)
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "list_adapters",
		Description: "List the registered tool adapters (the tool allowlist). " +
			"Only adapters returned here can be executed via execute_tool.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		res, err := s.ListAdapters(ctx, in)
		return toCallResult(res, err)
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "execute_tool",
		Description: "Execute a registered tool adapter against a target. " +
			"*** This goes through the same gates as the WebUI/CLI: scope check, " +
			"privacy tokenization and budget reservation. There is no MCP bypass path. *** " +
			"The target must be inside the authorized scope or the call is refused.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ExecuteToolInput) (*mcp.CallToolResult, any, error) {
		res, err := s.ExecuteTool(ctx, in)
		return toCallResult(res, err)
	})
}

func toCallResult(res *ToolResult, err error) (*mcp.CallToolResult, any, error) {
	if err != nil {
		// 错误作为 tool 结果返回（isError），而不是协议错误 ——
		// 这样客户端能看到"为什么被拒"，而不是一个笼统的传输失败。
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
		}, nil, nil
	}
	content := []mcp.Content{&mcp.TextContent{Text: res.Text}}
	if res.JSON != "" {
		content = append(content, &mcp.TextContent{Text: res.JSON})
	}
	return &mcp.CallToolResult{Content: content}, nil, nil
}
