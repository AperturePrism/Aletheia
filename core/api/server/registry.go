// Package server 提供 alethd 的 API 装配层。
//
// 对应 04 §I0 交付物「接口契约的空实现」与 I0 关键决策：
//
//	① Go/Python 通信用 gRPC 还是 HTTP+JSON —— 推荐 gRPC（Protobuf 强类型，
//	   契约定死），但保留 HTTP+JSON 作为调试通道
//	② 接口版本化策略：Protobuf 包名带 v1
//
// 本包是 05 定义的全部服务的**空实现**登记处。每个服务的实现在对应迭代
// 落地（见 04 §3.2 的迭代顺序），此处先定义骨架，使得：
//
//   - 契约与实现的偏差在编译期就能发现（服务接口由生成物给出）
//   - I0 就能验证"全部契约可被实现、可被编译、可被客户端调用"
//
// 空实现必须是**显式的 UNIMPLEMENTED**，不能是"看起来成功其实什么都没做"：
// 一个返回空响应的方法会让调用方以为能力已存在、只是没有结果。
package server

import (
	"context"

	"github.com/AperturePrism/aleth/core/api/aleth/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Registry 登记全部服务的实现。
//
// 字段名对应 05 的 service 名，字段顺序对齐 05 的章节顺序
// （Ingest → Prism → Aperture → Ledger → Termination → Orchestrator →
// Scope → Governor → Sandbox → Gateway），便于逐章核对。
type Registry struct {
	Ingest       alethv1.IngestServiceServer
	Prism        alethv1.PrismServiceServer
	Aperture     alethv1.ApertureServiceServer
	Ledger       alethv1.LedgerServiceServer
	Termination  alethv1.TerminationServiceServer
	Orchestrator alethv1.OrchestratorServiceServer
	Scope        alethv1.ScopeServiceServer
	Governor     alethv1.GovernorServiceServer
	Sandbox      alethv1.SandboxServiceServer
	Gateway      alethv1.GatewayServiceServer
}

// NewRegistry 返回全部服务均未实现的 Registry。
//
// I0 之后各迭代逐个把 unimplemented* 换成真实实现，并在此登记。
// 这个替换过程就是 04 §4 的迭代推进。
func NewRegistry() *Registry {
	return &Registry{
		Ingest:       unimplementedIngest{},
		Prism:        unimplementedPrism{},
		Aperture:     unimplementedAperture{},
		Ledger:       unimplementedLedger{},
		Termination:  unimplementedTermination{},
		Orchestrator: unimplementedOrchestrator{},
		Scope:        unimplementedScope{},
		Governor:     unimplementedGovernor{},
		Sandbox:      unimplementedSandbox{},
		Gateway:      unimplementedGateway{},
	}
}

// RegisterAll 把 Registry 中的全部服务注册到 gRPC server。
//
// 对应 05 定义的全部服务。nil 字段被跳过 —— 允许逐步装配
// （例如 I2 只替换 Ledger，其余仍是空实现）。
func (r *Registry) RegisterAll(s *grpc.Server) {
	if r.Ingest != nil {
		alethv1.RegisterIngestServiceServer(s, r.Ingest)
	}
	if r.Prism != nil {
		alethv1.RegisterPrismServiceServer(s, r.Prism)
	}
	if r.Aperture != nil {
		alethv1.RegisterApertureServiceServer(s, r.Aperture)
	}
	if r.Ledger != nil {
		alethv1.RegisterLedgerServiceServer(s, r.Ledger)
	}
	if r.Termination != nil {
		alethv1.RegisterTerminationServiceServer(s, r.Termination)
	}
	if r.Orchestrator != nil {
		alethv1.RegisterOrchestratorServiceServer(s, r.Orchestrator)
	}
	if r.Scope != nil {
		alethv1.RegisterScopeServiceServer(s, r.Scope)
	}
	if r.Governor != nil {
		alethv1.RegisterGovernorServiceServer(s, r.Governor)
	}
	if r.Sandbox != nil {
		alethv1.RegisterSandboxServiceServer(s, r.Sandbox)
	}
	if r.Gateway != nil {
		alethv1.RegisterGatewayServiceServer(s, r.Gateway)
	}
}

// unimplementedErr 是所有未实现服务的统一返回。
//
// 为什么必须显式返回而不是把方法留空返回 nil：
//
//	gRPC 里返回 (nil, nil) 会被当成"空成功"，调用方无法区分
//	"该能力返回了空结果"与"该能力还不存在"。
//	返回 UNIMPLEMENTED 使调用方（Python 侧、CLI、WebUI）能明确识别
//	"这个服务我还没做"，对齐 05 §0 C2「失败必须显式」。
func unimplementedErr(service string) error {
	return status.Errorf(codes.Unimplemented,
		"service %s is not implemented yet; see docs/04-开发总纲 §4 for the iteration that delivers it",
		service)
}

// ---- IngestService（05 §2.2）· 交付迭代 I1 ----

type unimplementedIngest struct {
	alethv1.UnimplementedIngestServiceServer
}

func (unimplementedIngest) Execute(context.Context, *alethv1.ToolRequest) (*alethv1.EvidenceSpectrum, error) {
	return nil, unimplementedErr("IngestService")
}

func (unimplementedIngest) ListAdapters(context.Context, *alethv1.ListAdaptersRequest) (*alethv1.ListAdaptersResponse, error) {
	return nil, unimplementedErr("IngestService")
}

func (unimplementedIngest) ValidateTool(context.Context, *alethv1.ValidateToolRequest) (*alethv1.ValidateToolResponse, error) {
	return nil, unimplementedErr("IngestService")
}

// ---- PrismService（05 §3.3）· 交付迭代 I4 ----

type unimplementedPrism struct {
	alethv1.UnimplementedPrismServiceServer
}

func (unimplementedPrism) Ingest(context.Context, *alethv1.EvidenceSpectrum) (*alethv1.IngestResult, error) {
	return nil, unimplementedErr("PrismService")
}

func (unimplementedPrism) Project(context.Context, *alethv1.ProjectRequest) (*alethv1.ProjectedSubgraph, error) {
	return nil, unimplementedErr("PrismService")
}

func (unimplementedPrism) SnapshotAt(context.Context, *alethv1.SnapshotAtRequest) (*alethv1.ProjectedSubgraph, error) {
	return nil, unimplementedErr("PrismService")
}

func (unimplementedPrism) CreateBranch(context.Context, *alethv1.CreateBranchRequest) (*alethv1.BranchInfo, error) {
	return nil, unimplementedErr("PrismService")
}

func (unimplementedPrism) RollbackBranch(context.Context, *alethv1.RollbackBranchRequest) (*alethv1.RollbackResult, error) {
	return nil, unimplementedErr("PrismService")
}

func (unimplementedPrism) MergeBranch(context.Context, *alethv1.MergeBranchRequest) (*alethv1.MergeResult, error) {
	return nil, unimplementedErr("PrismService")
}

// ---- ApertureService（05 §4.2）· 交付迭代 I5 ----

type unimplementedAperture struct {
	alethv1.UnimplementedApertureServiceServer
}

func (unimplementedAperture) Assemble(context.Context, *alethv1.AssembleRequest) (*alethv1.ContextBundle, error) {
	return nil, unimplementedErr("ApertureService")
}

func (unimplementedAperture) Autofocus(context.Context, *alethv1.AutofocusRequest) (*alethv1.AutofocusResult, error) {
	return nil, unimplementedErr("ApertureService")
}

// ---- LedgerService（05 §5.3）· 交付迭代 I2 ----
//
// 四道闸门 G-1/G-2/G-3/G-4 与幻觉计数都在此服务内。
// 04 §I2 原话：「这是全项目最重要的一次迭代」。
// 09 §R4：不存在任何其他方式让一个结论变成 CONFIRMED。

type unimplementedLedger struct {
	alethv1.UnimplementedLedgerServiceServer
}

func (unimplementedLedger) Append(context.Context, *alethv1.AppendEvidenceRequest) (*alethv1.AppendEvidenceResult, error) {
	return nil, unimplementedErr("LedgerService")
}

func (unimplementedLedger) ValidateAssertion(context.Context, *alethv1.ValidateAssertionRequest) (*alethv1.ValidateAssertionResult, error) {
	return nil, unimplementedErr("LedgerService")
}

func (unimplementedLedger) RecordSideEffect(context.Context, *alethv1.RecordSideEffectRequest) (*alethv1.RecordSideEffectResult, error) {
	return nil, unimplementedErr("LedgerService")
}

func (unimplementedLedger) Reproduce(context.Context, *alethv1.ReproduceRequest) (*alethv1.ReproduceResult, error) {
	return nil, unimplementedErr("LedgerService")
}

func (unimplementedLedger) TraceFinding(context.Context, *alethv1.TraceFindingRequest) (*alethv1.TracedEvidenceChain, error) {
	return nil, unimplementedErr("LedgerService")
}

func (unimplementedLedger) ReportHallucination(context.Context, *alethv1.ReportHallucinationRequest) (*alethv1.HallucinationState, error) {
	return nil, unimplementedErr("LedgerService")
}

// ---- TerminationService（05 §5.4）· 交付迭代 I7 ----
//
// 09 §R6：RequestTermination 是全系统唯一的会话终止入口（除熔断外）。
// 任何自行终止路径都是 P0 缺陷。

type unimplementedTermination struct {
	alethv1.UnimplementedTerminationServiceServer
}

func (unimplementedTermination) RequestTermination(context.Context, *alethv1.TerminationRequest) (*alethv1.TerminationDecision, error) {
	return nil, unimplementedErr("TerminationService")
}

// ---- OrchestratorService（05 §6.2）· 交付迭代 I6 ----
//
// NextReady 不得调用 LLM —— 它是拓扑排序 + 资源约束求解（05 §6.2 原文）。

type unimplementedOrchestrator struct {
	alethv1.UnimplementedOrchestratorServiceServer
}

func (unimplementedOrchestrator) Plan(context.Context, *alethv1.PlanRequest) (*alethv1.TaskGraph, error) {
	return nil, unimplementedErr("OrchestratorService")
}

func (unimplementedOrchestrator) NextReady(context.Context, *alethv1.NextReadyRequest) (*alethv1.NextReadyResponse, error) {
	return nil, unimplementedErr("OrchestratorService")
}

func (unimplementedOrchestrator) ReportTaskResult(context.Context, *alethv1.ReportTaskResultRequest) (*alethv1.TaskUpdateResult, error) {
	return nil, unimplementedErr("OrchestratorService")
}

func (unimplementedOrchestrator) Refine(context.Context, *alethv1.RefineRequest) (*alethv1.TaskGraph, error) {
	return nil, unimplementedErr("OrchestratorService")
}

func (unimplementedOrchestrator) Checkpoint(context.Context, *alethv1.CheckpointRequest) (*alethv1.CheckpointInfo, error) {
	return nil, unimplementedErr("OrchestratorService")
}

func (unimplementedOrchestrator) Rewind(context.Context, *alethv1.RewindRequest) (*alethv1.RewindResult, error) {
	return nil, unimplementedErr("OrchestratorService")
}

func (unimplementedOrchestrator) Fork(context.Context, *alethv1.ForkRequest) (*alethv1.ForkResult, error) {
	return nil, unimplementedErr("OrchestratorService")
}

// ---- ScopeService（05 §6.3）· 交付迭代 I3 ----
//
// 09 §R8：三重校验（network / tool_param / post_dns）与"默认拒绝"语义不得修改。
// 越界必须熔断整场会话，不得改成"跳过该请求继续"。

type unimplementedScope struct {
	alethv1.UnimplementedScopeServiceServer
}

func (unimplementedScope) Check(context.Context, *alethv1.ScopeCheckRequest) (*alethv1.ScopeCheckResult, error) {
	return nil, unimplementedErr("ScopeService")
}

func (unimplementedScope) LoadScope(context.Context, *alethv1.LoadScopeRequest) (*alethv1.ScopeInfo, error) {
	return nil, unimplementedErr("ScopeService")
}

// ---- GovernorService（05 §6.3）· 交付迭代 I3 ----
//
// 预扣失败即拒绝执行（fail-closed，P-4）。不允许"best effort 继续"。

type unimplementedGovernor struct {
	alethv1.UnimplementedGovernorServiceServer
}

func (unimplementedGovernor) Reserve(context.Context, *alethv1.ReserveRequest) (*alethv1.ReserveResult, error) {
	return nil, unimplementedErr("GovernorService")
}

func (unimplementedGovernor) Consume(context.Context, *alethv1.ConsumeRequest) (*alethv1.BudgetState, error) {
	return nil, unimplementedErr("GovernorService")
}

func (unimplementedGovernor) State(context.Context, *alethv1.BudgetStateRequest) (*alethv1.BudgetState, error) {
	return nil, unimplementedErr("GovernorService")
}

func (unimplementedGovernor) CheckCircuit(context.Context, *alethv1.CircuitCheckRequest) (*alethv1.CircuitState, error) {
	return nil, unimplementedErr("GovernorService")
}

// ---- SandboxService（05 §6.3）· 交付迭代 I3 ----
//
// exec_id 的唯一合法签发者（modules/M6 §7.2）。私钥不出 Sandbox 进程。

type unimplementedSandbox struct {
	alethv1.UnimplementedSandboxServiceServer
}

func (unimplementedSandbox) Execute(context.Context, *alethv1.SandboxExecRequest) (*alethv1.SandboxExecResult, error) {
	return nil, unimplementedErr("SandboxService")
}

func (unimplementedSandbox) SignExecId(context.Context, *alethv1.SignExecIdRequest) (*alethv1.SignedExecId, error) {
	return nil, unimplementedErr("SandboxService")
}

// ---- GatewayService（05 §6.4）· 交付迭代 I3 ----
//
// 09 §R7：真实敏感值不得出现在送往模型的任何内容中。
// Gateway 默认强制开启，不得提供 UI 开关（只能通过配置文件显式禁用）。

type unimplementedGateway struct {
	alethv1.UnimplementedGatewayServiceServer
}

func (unimplementedGateway) Tokenize(context.Context, *alethv1.TokenizeRequest) (*alethv1.TokenizeResult, error) {
	return nil, unimplementedErr("GatewayService")
}

func (unimplementedGateway) Detokenize(context.Context, *alethv1.DetokenizeRequest) (*alethv1.DetokenizeResult, error) {
	return nil, unimplementedErr("GatewayService")
}

func (unimplementedGateway) ScanOutbound(context.Context, *alethv1.ScanRequest) (*alethv1.ScanResult, error) {
	return nil, unimplementedErr("GatewayService")
}
