// ApertureService 的 gRPC 适配层（05 §4.2）。
//
// 与 scopekernel/server.go、prism/server.go 同一分工：本文件只做
// proto 消息 ↔ Assembler 的翻译与错误映射，不含任何光圈决策逻辑。
package aperture

import (
	"context"
	"errors"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server 实现 alethv1.ApertureServiceServer。
type Server struct {
	alethv1.UnimplementedApertureServiceServer

	assembler *Assembler
}

// NewServer 装配 ApertureService。
func NewServer(assembler *Assembler) *Server { return &Server{assembler: assembler} }

// Assemble 装配上下文（核心接口）。
func (s *Server) Assemble(ctx context.Context, req *alethv1.AssembleRequest) (*alethv1.ContextBundle, error) {
	bundle, err := s.assembler.Assemble(ctx, req)
	if err != nil {
		return nil, toStatus(err)
	}
	return bundle, nil
}

// Autofocus 自动对焦。
func (s *Server) Autofocus(ctx context.Context, req *alethv1.AutofocusRequest) (*alethv1.AutofocusResult, error) {
	res, err := s.assembler.Autofocus(ctx, req)
	if err != nil {
		return nil, toStatus(err)
	}
	return res, nil
}

// toStatus 把装配错误映射为契约错误码（05 §1.3）。
//
// 关键映射：OverBudgetError → APERTURE_OVER_BUDGET（不是 Internal）。
// 契约（05 §4.1）明确要求"estimated_tokens > budget_tokens 时，
// ApertureService 必须返回 APERTURE_OVER_BUDGET 错误，禁止截断后返回" ——
// 调用方据此决定降档或提高预算，因此这个码是接口的一部分，必须准确。
func toStatus(err error) error {
	var ob *OverBudgetError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.Canceled, err.Error())
	case errors.As(err, &ob):
		st := status.New(codes.FailedPrecondition, err.Error())
		if withDetail, derr := st.WithDetails(&alethv1.Error{
			Code:    alethv1.ErrorCode_APERTURE_OVER_BUDGET,
			Message: err.Error(),
			Remediation: "narrow the aperture (allow_downgrade) or raise budget_tokens; " +
				"truncation is not an available path (modules/M3 §2.2 N4)",
		}); derr == nil {
			return withDetail.Err()
		}
		return st.Err()
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
