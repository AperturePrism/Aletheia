// OrchestratorService 的 gRPC 适配层（05 §6.2）。
//
// 与 scopekernel/server.go、prism/server.go、aperture/server.go 同一分工：
// 只做 proto 消息 ↔ 领域对象的翻译与错误映射，不含规划决策逻辑。
package orchestrate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SnapshotSource 提供检查点所需的**跨模块状态快照**（05 §6.2 的
// `CheckpointInfo.graph_version` 与 `budget_snapshot_hash`）。
//
// # 为什么用接口注入而不是直接依赖 M2/M6
//
// M5 §3.2 N1/N2 明确编排层**不做**图装配（M3）与预算记账（M6）——
// 它只消费它们的结论。检查点需要把这两个结论**定格**下来，
// 因此这里声明"我需要什么"，由装配方（cmd/alethd）把真实实现接上。
//
// 这与 core/ingest 的 `Deps` 是同一做法：接口由消费者定义，
// 因此测试可以精确注入固定值，验证检查点确实记录了快照。
type SnapshotSource interface {
	// GraphVersion 返回心智地图当前的版本标识（M2 的 `SnapshotAt` 时刻）。
	//
	// 空串表示"该来源未提供"—— 此时 `CheckpointInfo.graph_version`
	// 如实为空，**不编造**一个版本号（伪造的可复现性比缺失更糟）。
	GraphVersion(ctx context.Context, sessionID string) (string, error)
	// BudgetSnapshotHash 返回预算状态的哈希（M6 Governor 的状态摘要）。
	//
	// 用哈希而非完整状态：检查点需要的是"能判定两次快照是否相同"，
	// 而不是可回滚的预算副本（预算不回滚 —— 与账本同源的设计）。
	BudgetSnapshotHash(ctx context.Context, sessionID string) (string, error)
}

// Server 实现 alethv1.OrchestratorServiceServer。
//
// 会话状态：I6 的单机形态下每进程承载一个会话（与 M2 的按会话分区同源），
// 因此这里按 session_id 保存图与检查点，支持多会话并行（团队模式的雏形）。
type Server struct {
	alethv1.UnimplementedOrchestratorServiceServer

	mu     sync.Mutex
	graphs map[string]*Graph           // session_id → 当前图
	ckpts  map[string]*CheckpointStore // session_id → 检查点
	now    func() time.Time
	seq    uint64
	// snapshots 提供检查点所需的跨模块状态（可为 nil —— 见 Checkpoint）。
	snapshots SnapshotSource
}

// NewServer 装配 OrchestratorService。
func NewServer() *Server {
	return &Server{
		graphs: map[string]*Graph{},
		ckpts:  map[string]*CheckpointStore{},
		now:    time.Now,
	}
}

// NewServerWithSnapshots 装配带跨模块状态来源的 OrchestratorService。
//
// `src` 为 nil 时等价于 `NewServer()`（检查点里的版本字段留空并带告警）。
func NewServerWithSnapshots(src SnapshotSource) *Server {
	s := NewServer()
	s.snapshots = src
	return s
}

// Plan 登记 LLM 生成的图草稿（OrchestratorService.Plan）。
//
// 契约（05 §6.2）：LLM 只生成"有哪些任务、依赖关系"，**不做逐步决策** ——
// 序列求解交给确定性规划器。因此本方法只做校验与登记，不"优化"图。
func (s *Server) Plan(ctx context.Context, req *alethv1.PlanRequest) (*alethv1.TaskGraph, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if req.GetProposedGraph() == nil {
		return nil, status.Error(codes.InvalidArgument,
			"plan requires a proposed_graph (LLM output is a task/dependency structure, not free text)")
	}
	g, err := NewGraph(req.GetProposedGraph())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if g.SessionID == "" {
		g.SessionID = req.GetSessionId()
	}
	if g.SessionID == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	if g.PlanRevision == "" {
		g.PlanRevision = "1"
	}

	s.mu.Lock()
	s.graphs[g.SessionID] = g
	if _, ok := s.ckpts[g.SessionID]; !ok {
		s.ckpts[g.SessionID] = NewCheckpointStore(DefaultMaxCheckpoints)
	}
	s.mu.Unlock()

	return g.ToProto(), nil
}

// NextReady 返回可执行任务（确定性：拓扑 + 资源约束，**零 LLM**）。
func (s *Server) NextReady(ctx context.Context, req *alethv1.NextReadyRequest) (*alethv1.NextReadyResponse, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	g, err := s.graphFor(req.GetSessionId())
	if err != nil {
		return nil, err
	}
	ready, blocked := g.NextReady(req.GetAvailableSlots())
	return &alethv1.NextReadyResponse{ReadyTaskIds: ready, BlockedReasons: blocked}, nil
}

// ReportTaskResult 写回任务结果（状态流转）。
func (s *Server) ReportTaskResult(
	ctx context.Context, req *alethv1.ReportTaskResultRequest,
) (*alethv1.TaskUpdateResult, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	g, err := s.graphFor(req.GetSessionId())
	if err != nil {
		return nil, err
	}
	if req.GetTaskId() == "" {
		return nil, status.Error(codes.InvalidArgument, "task_id is required")
	}
	if err := g.ApplyResult(req.GetTaskId(), req.GetStatus(), req.GetFailures()); err != nil {
		return &alethv1.TaskUpdateResult{
			Error: &alethv1.Error{Code: alethv1.ErrorCode_INVALID_ARGUMENT, Message: err.Error()},
		}, nil
	}
	return &alethv1.TaskUpdateResult{
		UpdatedTask:  findTaskProto(g, req.GetTaskId()),
		UpdatedGraph: g.ToProto(),
	}, nil
}

// Refine 失败驱动的计划改写（OrchestratorService.Refine）。
func (s *Server) Refine(ctx context.Context, req *alethv1.RefineRequest) (*alethv1.TaskGraph, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	g, err := s.graphFor(req.GetSessionId())
	if err != nil {
		return nil, err
	}
	if len(req.GetFailures()) == 0 {
		return nil, status.Error(codes.InvalidArgument,
			"refine requires at least one FailureRecord (structured failure type drives the rewrite)")
	}
	// 校验每个失败类型可识别 —— 未知类型不得静默进入计划。
	for _, f := range req.GetFailures() {
		if _, ok := ParseFailureType(f.GetFailureType()); !ok {
			return nil, status.Error(codes.InvalidArgument, fmt.Sprintf(
				"unknown failure_type %q; refusing to guess a remediation", f.GetFailureType()))
		}
	}
	// 记录改写依据并递增计划版本（M5 §4.2：plan_revision += 1）。
	if g.Rationale == "" {
		g.Rationale = "refined due to: "
	} else {
		g.Rationale += " | refined due to: "
	}
	for i, f := range req.GetFailures() {
		if i > 0 {
			g.Rationale += ", "
		}
		g.Rationale += f.GetFailureType()
	}
	if req.GetRefinerGuidance() != "" {
		g.Rationale += " | " + req.GetRefinerGuidance()
	}
	g.PlanRevision = bumpRevision(g.PlanRevision)
	return g.ToProto(), nil
}

// Checkpoint 创建检查点。
func (s *Server) Checkpoint(ctx context.Context, req *alethv1.CheckpointRequest) (*alethv1.CheckpointInfo, error) {
	cp, err := s.snapshotCheckpoint(ctx, req.GetSessionId(), req.GetLabel())
	if err != nil {
		return nil, err
	}
	store, err := s.ckptFor(req.GetSessionId())
	if err != nil {
		return nil, err
	}
	if err := store.Save(cp, false); err != nil {
		return nil, toStatus(err)
	}
	return &alethv1.CheckpointInfo{
		CheckpointId:       cp.ID,
		SessionId:          cp.SessionID,
		Label:              cp.Label,
		PlanRevision:       cp.PlanRevision,
		GraphVersion:       cp.GraphVersion,
		BudgetSnapshotHash: cp.BudgetHash,
		CreatedAt:          timestamppb.New(cp.createdAt),
	}, nil
}

// snapshotCheckpoint 构造（但不保存）一个检查点。
//
// 拆出来是为了让"快照不完整时的 Warnings"可被单独测试 ——
// 那些告警**不进 proto**（契约的 `CheckpointInfo` 没有告警字段），
// 因此只能从内部结构观察。
func (s *Server) snapshotCheckpoint(ctx context.Context, sessionID, label string) (*Checkpoint, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	g, err := s.graphFor(sessionID)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.seq++
	n := s.seq
	s.mu.Unlock()

	now := s.now()
	// 跨模块状态快照（05 §6.2 的 `graph_version` 与 `budget_snapshot_hash`）。
	//
	// ★ 取不到时**留空并记 warning**，不编造值。
	// 一个伪造的版本号会让"rewind 后证据一致"看起来有据可依，而实际没有 ——
	// 那比缺失更糟（`docs/10` §0：不能让"没查"伪装成"没问题"）。
	graphVersion, budgetHash, snapWarnings := s.snapshotFor(ctx, sessionID)

	return &Checkpoint{
		ID:           fmt.Sprintf("cp_%s_%d", sessionID, n),
		SessionID:    sessionID,
		Label:        label,
		PlanRevision: g.PlanRevision,
		GraphVersion: graphVersion,
		BudgetHash:   budgetHash,
		Graph:        g.ToProto(),
		Warnings:     snapWarnings,
		createdAt:    now,
	}, nil
}

// snapshotFor 取跨模块状态快照。
//
// 未注入 `SnapshotSource` 时返回空值与说明性告警 ——
// **不返回错误**：检查点本身仍有价值（图快照 + 计划版本），
// 缺的只是"能与其他模块的版本对齐"这一层。把整次 Checkpoint 变成
// 失败会让调用方失去图快照，代价更大。
func (s *Server) snapshotFor(ctx context.Context, sessionID string) (graphVersion, budgetHash string, warnings []string) {
	if s.snapshots == nil {
		return "", "", []string{
			"no SnapshotSource wired: graph_version and budget_snapshot_hash are empty; " +
				"this checkpoint cannot be aligned with M2/M6 state",
		}
	}
	// 两个来源各自独立：一个失败不影响另一个。
	if v, err := s.snapshots.GraphVersion(ctx, sessionID); err != nil {
		warnings = append(warnings, "graph version unavailable: "+err.Error())
	} else {
		graphVersion = v
	}
	if h, err := s.snapshots.BudgetSnapshotHash(ctx, sessionID); err != nil {
		warnings = append(warnings, "budget snapshot unavailable: "+err.Error())
	} else {
		budgetHash = h
	}
	return graphVersion, budgetHash, warnings
}

// Rewind 回到检查点。
func (s *Server) Rewind(ctx context.Context, req *alethv1.RewindRequest) (*alethv1.RewindResult, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	store, err := s.ckptFor(req.GetSessionId())
	if err != nil {
		return nil, err
	}
	out, err := store.Rewind(req.GetCheckpointId())
	if err != nil {
		return nil, toStatus(err)
	}
	s.mu.Lock()
	s.graphs[req.GetSessionId()] = out.Graph
	s.mu.Unlock()

	// 证据一致性：账本不回滚（M5 §4.3），因此已 CONFIRMED 的证据必然一致。
	// 该字段如实反映这条设计事实，而不是无条件宣称 true ——
	// LedgerNotRolledBack 是 rewind 的实现保证，若它为 false 则不一致。
	return &alethv1.RewindResult{
		SessionId:            req.GetSessionId(),
		RestoredCheckpointId: out.CheckpointID,
		EvidenceConsistent:   out.LedgerNotRolledBack,
	}, nil
}

// Fork 从检查点派生平行分支。
func (s *Server) Fork(ctx context.Context, req *alethv1.ForkRequest) (*alethv1.ForkResult, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	store, err := s.ckptFor(req.GetSessionId())
	if err != nil {
		return nil, err
	}
	out, err := store.Fork(req.GetCheckpointId(), req.GetForkName())
	if err != nil {
		return nil, toStatus(err)
	}
	// 新分支作为独立会话登记（分支隔离：假设不污染主分支）。
	s.mu.Lock()
	s.graphs[out.NewSessionID] = out.Graph
	s.ckpts[out.NewSessionID] = NewCheckpointStore(DefaultMaxCheckpoints)
	s.mu.Unlock()

	return &alethv1.ForkResult{
		NewSessionId:     out.NewSessionID,
		ParentSessionId:  out.ParentSessionID,
		RootCheckpointId: out.RootCheckpointID,
	}, nil
}

// ---- 内部 ----

func (s *Server) graphFor(sessionID string) (*Graph, error) {
	if sessionID == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.graphs[sessionID]
	if !ok {
		return nil, status.Errorf(codes.NotFound,
			"no task graph for session %q; call Plan first", sessionID)
	}
	return g, nil
}

func (s *Server) ckptFor(sessionID string) (*CheckpointStore, error) {
	if sessionID == "" {
		return nil, status.Error(codes.InvalidArgument, "session_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.ckpts[sessionID]
	if !ok {
		return nil, status.Errorf(codes.NotFound,
			"no checkpoint store for session %q; call Plan first", sessionID)
	}
	return st, nil
}

func findTaskProto(g *Graph, taskID string) *alethv1.Task {
	for _, t := range g.ToProto().GetTasks() {
		if t.GetTaskId() == taskID {
			return t
		}
	}
	return nil
}

// bumpRevision 把 "1" → "2"；非数字时追加后缀（不猜测格式）。
func bumpRevision(rev string) string {
	var n int
	if _, err := fmt.Sscanf(rev, "%d", &n); err == nil && n > 0 {
		return fmt.Sprintf("%d", n+1)
	}
	if rev == "" {
		return "1"
	}
	return rev + "+1"
}

func ctxErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return status.Error(codes.Canceled, ctx.Err().Error())
	default:
		return nil
	}
}

// toStatus 把领域错误映射为契约错误码。
func toStatus(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.Canceled, err.Error())
	default:
		return status.Error(codes.NotFound, err.Error())
	}
}
