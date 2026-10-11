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
}

// NewServer 装配 OrchestratorService。
func NewServer() *Server {
	return &Server{
		graphs: map[string]*Graph{},
		ckpts:  map[string]*CheckpointStore{},
		now:    time.Now,
	}
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
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	g, err := s.graphFor(req.GetSessionId())
	if err != nil {
		return nil, err
	}
	store, err := s.ckptFor(req.GetSessionId())
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.seq++
	n := s.seq
	s.mu.Unlock()

	now := s.now()
	cp := &Checkpoint{
		ID:           fmt.Sprintf("cp_%s_%d", req.GetSessionId(), n),
		SessionID:    req.GetSessionId(),
		Label:        req.GetLabel(),
		PlanRevision: g.PlanRevision,
		BudgetHash:   "", // 预算快照由 M6 Governor 提供（I6 接线预留）
		Graph:        g.ToProto(),
	}
	if err := store.Save(cp, false); err != nil {
		return nil, toStatus(err)
	}
	return &alethv1.CheckpointInfo{
		CheckpointId: cp.ID,
		SessionId:    cp.SessionID,
		Label:        cp.Label,
		PlanRevision: cp.PlanRevision,
		GraphVersion: cp.GraphVersion,
		CreatedAt:    timestamppb.New(now.UTC()),
	}, nil
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
