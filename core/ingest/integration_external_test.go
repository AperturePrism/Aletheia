package ingest_test

// 端到端集成（外部测试包）：真实 nmap 适配器 + 真实 Privacy Gateway +
// stub Sandbox。放在外部包（ingest_test）是因为包内测试无法 import
// 依赖本包的子包（nmap → ingest 会成环）—— 编排语义的用例留在
// service_test.go（stub adapter），本文件验证真实数据流。

import (
	"context"
	"testing"

	"github.com/AperturePrism/aleth/core/api/aleth/v1"
	"github.com/AperturePrism/aleth/core/gateway"
	"github.com/AperturePrism/aleth/core/ingest"
	"github.com/AperturePrism/aleth/core/ingest/nmap"
	"github.com/AperturePrism/aleth/core/scopekernel"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// nmapXMLOutputPrivateIP 是一份最小 nmap XML 观测，目标为私网地址
// 10.40.23.5 —— 会命中 Gateway 的 IP_PRIVATE 脱敏/扫描模式（真实
// 扫描的常态形态；文档网段 192.0.2.x 不命中，测不到该路径）。
const nmapXMLOutputPrivateIP = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94" xmloutputversion="1.05">
<host><status state="up"/>
<address addr="10.40.23.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="3000"><state state="open"/></port></ports>
</host>
</nmaprun>`

// realGatewayAdapter 把 core/gateway 实例适配为 ingest.PrivacyGateway。
type realGatewayAdapter struct{ gw *gateway.Gateway }

func (a realGatewayAdapter) TokenizeParams(_ context.Context, _ string, params map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(params))
	for k, v := range params {
		t, _ := a.gw.Tokenize(v)
		out[k] = t
	}
	return out, nil
}

func (a realGatewayAdapter) TokenizeOutput(_ context.Context, _ string, raw []byte) ([]byte, error) {
	t, _ := a.gw.Tokenize(string(raw))
	return []byte(t), nil
}

func (a realGatewayAdapter) ScanOutbound(_ context.Context, _ string, raw []byte) error {
	if len(a.gw.ScanOutbound(string(raw))) > 0 {
		return ingest.ErrPrivacyLeak
	}
	return nil
}

// passthroughGateway 模拟「Tokenize 缺位」的网关（脱敏失效），
// ScanOutbound 仍为真实现 —— 验证扫描的独立防线。
type passthroughGateway struct{ gw *gateway.Gateway }

func (p passthroughGateway) TokenizeParams(_ context.Context, _ string, params map[string]string) (map[string]string, error) {
	return params, nil
}

func (p passthroughGateway) TokenizeOutput(_ context.Context, _ string, raw []byte) ([]byte, error) {
	return raw, nil
}

func (p passthroughGateway) ScanOutbound(_ context.Context, _ string, raw []byte) error {
	if len(p.gw.ScanOutbound(string(raw))) > 0 {
		return ingest.ErrPrivacyLeak
	}
	return nil
}

// stubSandbox 返回固定的工具输出（真实适配器解析该输出）。
type stubSandbox struct {
	execID string
	output []byte
}

func (s stubSandbox) Execute(context.Context, string, []string) (string, []byte, error) {
	return s.execID, s.output, nil
}

func mustKernel(t *testing.T, cidr string) *scopekernel.Kernel {
	t.Helper()
	scope, err := scopekernel.ParseScope([]byte("targets:\n  include:\n    - cidr: " + cidr + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return scopekernel.NewKernel(scope, nil, scopekernel.RateLimit{PerMinute: 1000})
}

func newIntegrationService(t *testing.T, gw ingest.PrivacyGateway, sb ingest.SandboxRunner) *ingest.Service {
	t.Helper()
	c, err := ingest.NewCatalog(nmap.NewAdapter())
	if err != nil {
		t.Fatal(err)
	}
	store, err := ingest.NewRawStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return ingest.NewService(c, ingest.Deps{
		Scope:   realScopeChecker{kernel: mustKernel(t, "10.40.23.0/24")},
		Gateway: gw,
		Sandbox: sb,
		VersionProbe: func(context.Context, string) (string, error) {
			return "Nmap version 7.94", nil
		},
	}, store)
}

type realScopeChecker struct{ kernel *scopekernel.Kernel }

func (r realScopeChecker) CheckToolParam(ctx context.Context, toolName, target string) (string, error) {
	v := r.kernel.Check("session", target)
	if !v.Allowed {
		return "", ingest.ErrScopeViolation
	}
	return v.DecisionID, nil
}

// TestExecutePrivateIPOutputPassesAfterTokenize 验证 I3 行为缺陷的修正：
// 工具输出含私网 IP（nmap 常态）时，先 TokenizeOutput 再 ScanOutbound
// → 放行，且 spectrum 保留真实值（图谱/账本消费真实值；模型侧脱敏
// 在 M3 装配与 M6 出站扫描）。修正前对原始 stdout 直接扫描 → 真实
// 扫描 100% 被 PRIVACY_LEAK_DETECTED 阻断。
func TestExecutePrivateIPOutputPassesAfterTokenize(t *testing.T) {
	svc := newIntegrationService(t,
		realGatewayAdapter{gw: gateway.NewGateway()},
		stubSandbox{execID: "exec_chain_1", output: []byte(nmapXMLOutputPrivateIP)})

	sp, err := svc.Execute(context.Background(), &alethv1.ToolRequest{
		ToolName: "nmap", Params: map[string]string{"target": "10.40.23.5"},
	})
	if err != nil {
		t.Fatalf("private-IP output must pass after tokenize (I3 fix): %v", err)
	}
	found := false
	for _, d := range sp.GetEntities() {
		if d.GetAttributes()["addr"] == "10.40.23.5" {
			found = true
		}
	}
	if !found {
		t.Fatal("spectrum must keep real values (graph consumes real identity)")
	}
}

// TestExecuteUnsanitizedOutputStillBlocked 反向防线：若 Gateway 脱敏缺位
// （TokenizeOutput 原样返回），ScanOutbound 对含私网 IP 的文本仍阻断 ——
// 顺序修正不是放松，扫描的防线语义完整保留。
func TestExecuteUnsanitizedOutputStillBlocked(t *testing.T) {
	svc := newIntegrationService(t,
		passthroughGateway{gw: gateway.NewGateway()},
		stubSandbox{execID: "exec_chain_2", output: []byte(nmapXMLOutputPrivateIP)})

	_, err := svc.Execute(context.Background(), &alethv1.ToolRequest{
		ToolName: "nmap", Params: map[string]string{"target": "10.40.23.5"},
	})
	if err == nil {
		t.Fatal("unsanitized output must be blocked")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", status.Code(err))
	}
}
