// PrismService 的 gRPC 适配层（05 §3.3）。
//
// 职责边界：本文件只做 proto 消息 ↔ Store 的翻译与错误映射，
// **不含任何图语义决策** —— 版本推进、冲突判定、分支隔离全部在
// Store/Temporal 层（与 scopekernel/server.go 同一分工原则）。
package prism

import (
	"context"
	"errors"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server 实现 alethv1.PrismServiceServer。
type Server struct {
	alethv1.UnimplementedPrismServiceServer

	store *Store
}

// NewServer 装配 PrismService。
func NewServer(store *Store) *Server { return &Server{store: store} }

// Ingest 写入光谱（幂等）。
func (s *Server) Ingest(ctx context.Context, sp *alethv1.EvidenceSpectrum) (*alethv1.IngestResult, error) {
	res, err := s.store.Ingest(ctx, sp)
	if err != nil {
		return nil, toStatus(err)
	}
	return res, nil
}

// Project 按焦点与孔径投影子图。
func (s *Server) Project(ctx context.Context, req *alethv1.ProjectRequest) (*alethv1.ProjectedSubgraph, error) {
	sub, err := s.store.Project(ctx, req.GetBranchId(), req.GetFocus(),
		req.GetMaxHops(), req.GetMaxEntities(), req.GetKinds())
	if err != nil {
		return nil, toStatus(err)
	}
	return sub, nil
}

// SnapshotAt 时间回放：返回 T 时刻的认知状态。
func (s *Server) SnapshotAt(ctx context.Context, req *alethv1.SnapshotAtRequest) (*alethv1.ProjectedSubgraph, error) {
	if req.GetAt() == nil {
		return nil, status.Error(codes.InvalidArgument,
			"snapshot_at requires an explicit timestamp (replay target)")
	}
	sub, err := s.store.SnapshotAt(ctx, req.GetBranchId(),
		req.GetAt().AsTime(), req.GetMaxEntities())
	if err != nil {
		return nil, toStatus(err)
	}
	return sub, nil
}

// CreateBranch 建立假设分支。
func (s *Server) CreateBranch(ctx context.Context, req *alethv1.CreateBranchRequest) (*alethv1.BranchInfo, error) {
	info, err := s.store.CreateBranch(ctx, req.GetBranchName(),
		req.GetParentBranchId(), req.GetRationale())
	if err != nil {
		return nil, toStatus(err)
	}
	return info, nil
}

// RollbackBranch 回滚假设分支。
func (s *Server) RollbackBranch(ctx context.Context, req *alethv1.RollbackBranchRequest) (*alethv1.RollbackResult, error) {
	res, err := s.store.RollbackBranch(ctx, req.GetBranchId(), req.GetToVersion())
	if err != nil {
		return nil, toStatus(err)
	}
	return res, nil
}

// MergeBranch 合并假设分支（含 M4 闸门：未验证的假设实体拒绝合并）。
func (s *Server) MergeBranch(ctx context.Context, req *alethv1.MergeBranchRequest) (*alethv1.MergeResult, error) {
	res, err := s.store.MergeBranch(ctx, req.GetSourceBranchId(), req.GetTargetBranchId())
	if err != nil {
		return nil, toStatus(err)
	}
	return res, nil
}

// toStatus 把 Store 错误映射为契约错误码（05 §1.3）。
//
// 语义映射：
//
//	ErrBranchNotFound / ErrMainBranchImmutable / ErrBranchLimitExceeded
//	    → FailedPrecondition（调用方的前置状态不对，不是参数格式问题）
//	未知分支作为投影/回放目标 → NotFound 更贴切，但分支不是"资源检索"
//	    而是执行前置条件，故统一 FailedPrecondition。
func toStatus(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// 上下文取消**不伪装**成业务错误 —— 调用方需区分"我取消了"与
		// "系统拒绝了"（P-4：不吞、不降级）。
		return status.Error(codes.Canceled, err.Error())
	case errors.Is(err, ErrBranchNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ErrMainBranchImmutable),
		errors.Is(err, ErrBranchLimitExceeded),
		errors.Is(err, ErrHypothesisInMerge):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, ErrInvalidDraft):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
