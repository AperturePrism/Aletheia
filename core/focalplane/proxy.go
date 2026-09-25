// Package focalplane 提供 LedgerService 的 Go 侧转发代理。
//
// 架构依据（02 §8、modules/M4「建议语言 Python」）：L3 的实现在
// agents/src/aletheia/focalplane/（Python），alethd 通过本代理把
// LedgerService 调用转发到 focalplane gRPC server（仅回环监听）。
//
// 失败语义（P-4 / 与 core/ingest 的依赖缺失同构）：server 未运行或
// 调用失败 → 显式 UPSTREAM_UNAVAILABLE（带契约错误码 detail），
// 绝不返回空响应冒充成功。进程编排（自动拉起 focalplane）属 I6。
package focalplane

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// Proxy 实现 alethv1.LedgerServiceServer，把调用透传给 Python focalplane。
type Proxy struct {
	alethv1.UnimplementedLedgerServiceServer

	addr   string
	client alethv1.LedgerServiceClient
	conn   *grpc.ClientConn
}

// NewProxy 连接 focalplane server。addr 必须是回环地址（Q13 同源约束，
// 由 config.validateFocalplane 保证，这里再做一次防线纵深）。
func NewProxy(addr string) (*Proxy, error) {
	if !isLoopbackAddr(addr) {
		return nil, fmt.Errorf("focalplane addr must be loopback, got %q", addr)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial focalplane %q: %w", addr, err)
	}
	return &Proxy{
		addr:   addr,
		conn:   conn,
		client: alethv1.NewLedgerServiceClient(conn),
	}, nil
}

// Close 释放连接。
func (p *Proxy) Close() error { return p.conn.Close() }

func (p *Proxy) Append(ctx context.Context, req *alethv1.AppendEvidenceRequest) (*alethv1.AppendEvidenceResult, error) {
	return forward(ctx, p.addr, func() (*alethv1.AppendEvidenceResult, error) {
		return p.client.Append(ctx, req)
	})
}

func (p *Proxy) ValidateAssertion(ctx context.Context, req *alethv1.ValidateAssertionRequest) (*alethv1.ValidateAssertionResult, error) {
	return forward(ctx, p.addr, func() (*alethv1.ValidateAssertionResult, error) {
		return p.client.ValidateAssertion(ctx, req)
	})
}

func (p *Proxy) RecordSideEffect(ctx context.Context, req *alethv1.RecordSideEffectRequest) (*alethv1.RecordSideEffectResult, error) {
	return forward(ctx, p.addr, func() (*alethv1.RecordSideEffectResult, error) {
		return p.client.RecordSideEffect(ctx, req)
	})
}

func (p *Proxy) Reproduce(ctx context.Context, req *alethv1.ReproduceRequest) (*alethv1.ReproduceResult, error) {
	return forward(ctx, p.addr, func() (*alethv1.ReproduceResult, error) {
		return p.client.Reproduce(ctx, req)
	})
}

func (p *Proxy) TraceFinding(ctx context.Context, req *alethv1.TraceFindingRequest) (*alethv1.TracedEvidenceChain, error) {
	return forward(ctx, p.addr, func() (*alethv1.TracedEvidenceChain, error) {
		return p.client.TraceFinding(ctx, req)
	})
}

func (p *Proxy) ReportHallucination(ctx context.Context, req *alethv1.ReportHallucinationRequest) (*alethv1.HallucinationState, error) {
	return forward(ctx, p.addr, func() (*alethv1.HallucinationState, error) {
		return p.client.ReportHallucination(ctx, req)
	})
}

// forward 统一处理「上游不可达」的显式失败（P-4）。
func forward[Resp any](ctx context.Context, addr string, call func() (Resp, error)) (Resp, error) {
	resp, err := call()
	if err != nil {
		var zero Resp
		if status.Code(err) == codes.Unavailable {
			st := status.New(codes.Unavailable,
				"focalplane (ledger) unreachable at "+addr+"; start it via `uv run python -m aletheia.focalplane.server`")
			d, derr := st.WithDetails(&alethv1.Error{
				Code: alethv1.ErrorCode_UPSTREAM_UNAVAILABLE,
				Message: "LedgerService unavailable; forged evidence cannot be adjudicated without it",
			})
			if derr == nil {
				return zero, d.Err()
			}
		}
		return zero, err
	}
	return resp, nil
}

func isLoopbackAddr(addr string) bool {
	// 与 cmd/alethd 的回环判定一致的最小实现：host 部分是 127.0.0.1 或 [::1]。
	for _, prefix := range []string{"127.0.0.1", "[::1]", "localhost"} {
		if len(addr) >= len(prefix) && addr[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
