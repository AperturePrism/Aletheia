package focalplane

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:7728": true,
		"[::1]:7728":     true,
		"localhost:7728": true,
		"0.0.0.0:7728":   false,
		"10.0.0.5:7728":  false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestNewProxyRejectsNonLoopback(t *testing.T) {
	// Q13 同源：内部账本通道绝不对外。
	if _, err := NewProxy("0.0.0.0:7728"); err == nil {
		t.Fatal("non-loopback focalplane addr must be rejected")
	}
}

func TestProxyForwardUnavailableFailsClosed(t *testing.T) {
	// focalplane server 未运行 → 显式 UPSTREAM_UNAVAILABLE + 契约错误码 detail。
	// 连接一个必然无人监听的回环端口。
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	_ = lis.Close() // 关闭：保证端口无人监听

	p, err := NewProxy(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	resp, err := p.Append(context.Background(), &alethv1.AppendEvidenceRequest{})
	if err == nil {
		t.Fatal("unreachable focalplane must fail, not return empty success")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unavailable {
		t.Fatalf("gRPC code = %v, want Unavailable", st.Code())
	}
	found := false
	for _, d := range st.Details() {
		if e, ok := d.(*alethv1.Error); ok && e.Code == alethv1.ErrorCode_UPSTREAM_UNAVAILABLE {
			found = true
		}
	}
	if !found {
		t.Fatal("error detail must carry UPSTREAM_UNAVAILABLE (05 §1.3)")
	}
	// 空响应绝不能冒充成功。
	_ = resp
}

func TestProxyForwardsToRealServer(t *testing.T) {
	// 用进程内真实 gRPC server 模拟 focalplane（转发链路验证）。
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	alethv1.RegisterLedgerServiceServer(gs, &stubLedger{})
	go gs.Serve(lis)
	defer gs.Stop()

	p, err := NewProxy(lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	resp, err := p.ValidateAssertion(context.Background(), &alethv1.ValidateAssertionRequest{})
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	// stub 返回固定的 CANDIDATE 结论 —— 证明转发到达了上游。
	if resp.ResultingStatus != alethv1.FindingStatus_CANDIDATE {
		t.Fatalf("resulting_status = %v", resp.ResultingStatus)
	}
}

type stubLedger struct {
	alethv1.UnimplementedLedgerServiceServer
}

func (s *stubLedger) ValidateAssertion(
	context.Context, *alethv1.ValidateAssertionRequest,
) (*alethv1.ValidateAssertionResult, error) {
	return &alethv1.ValidateAssertionResult{
		ResultingStatus: alethv1.FindingStatus_CANDIDATE,
	}, nil
}
