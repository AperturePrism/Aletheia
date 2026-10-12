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

// AssembleWithOverrides 装配并应用**连续调节**（M3 §7 DoD）。
//
// # 这是进程内 API，不经 gRPC
//
// `AssembleRequest` 在 `05 §4.2` 是 **[frozen]** 的，没有可放覆盖参数的
// 字段。按 `docs/09` R1 未自造 RPC、未改 proto。
//
// 因此连续调节只对**进程内调用方**可用 —— 主要是 M5 编排层：
// 它在下发任务时知道"这个任务需要比 f/4 再深一点但不需要 f/16 的窄"，
// 而 gRPC 调用方暂时只能走三档。
//
// 补法是同一个 `contract:` PR 给 `AssembleRequest` 加三个可选字段。
// 与 I6 的 `GetGraph`、I0 的 `ListSessions` 缺口一并处理。
//
// ★ 注意 `MCP` 的 `assemble_context` 工具也走 gRPC，因此同样只能三档 ——
// 这是**如实的能力边界**，不做"看起来支持"的假接口。
func (s *Server) AssembleWithOverrides(
	ctx context.Context, req *alethv1.AssembleRequest, ov Overrides,
) (*alethv1.ContextBundle, error) {
	bundle, err := s.assembler.AssembleWithOverrides(ctx, req, ov)
	if err != nil {
		return nil, toStatus(err)
	}
	return bundle, nil
}

// ProfileForExposed 暴露档位参数解析（供 M5 在规划时预估曝光）。
//
// 存在的理由：编排层需要在不装配的情况下知道"某档位大概会给多少实体"，
// 以便决定任务的档位。直接读 `profiles` 是包内私有，因此提供本入口。
func ProfileForExposed(stop alethv1.ApertureSetting_Stop) StopProfile {
	return ProfileFor(stop)
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
