// 装配适配器：把 M6 组件（scopekernel / gateway）适配为 core/ingest
// 定义的执行前置依赖接口（ScopeChecker / PrivacyGateway）。
//
// 归属：cmd 层的装配文件 —— 接口由消费者定义（core/ingest），实现绑定
// 在这里完成，main() 只做构造与注入。适配器零决策：全部转发内核/网关。
package main

import (
	"context"
	"net"

	"github.com/AperturePrism/aleth/core/gateway"
	"github.com/AperturePrism/aleth/core/ingest"
	"github.com/AperturePrism/aleth/core/scopekernel"
)

// scopeCheckerAdapter 把 scopekernel.Kernel 适配为 ingest.ScopeChecker。
//
// 语义对齐（M1 §3）：CheckToolParam 返回 ErrScopeViolation 时，Ingest
// 必须以 SCOPE_VIOLATION 终止（调用方熔断整场会话）—— 本适配器只翻译，
// 不做"跳过该请求"的任何变体（09 §R8）。
type scopeCheckerAdapter struct {
	kernel *scopekernel.Kernel
}

func (a scopeCheckerAdapter) CheckToolParam(
	_ context.Context, _ string, target string,
) (string, error) {
	v := a.kernel.Check("session", target) // session 维度由 Kernel 限流内部处理
	if !v.Allowed {
		return "", ingest.ErrScopeViolation
	}
	return v.DecisionID, nil
}

// privacyGatewayAdapter 把 gateway.Gateway 适配为 ingest.PrivacyGateway。
type gatewayAdapter struct {
	gateway *gateway.Gateway
}

func (a gatewayAdapter) TokenizeParams(
	_ context.Context, _ string, params map[string]string,
) (map[string]string, error) {
	out := make(map[string]string, len(params))
	for k, v := range params {
		tokenized, _ := a.gateway.Tokenize(v)
		out[k] = tokenized
	}
	return out, nil
}

func (a gatewayAdapter) ScanOutbound(_ context.Context, _ string, raw []byte) error {
	if hits := a.gateway.ScanOutbound(string(raw)); len(hits) > 0 {
		return ingest.ErrPrivacyLeak
	}
	return nil
}

// netResolverAdapter 把 net.Resolver（返回 IPAddr）适配为 scopekernel.Resolver
// （返回 net.IP —— post_dns 复核只需要地址）。
type netResolverAdapter struct{ inner *net.Resolver }

func (a netResolverAdapter) LookupIPAddr(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := a.inner.LookupIPAddr(ctx, host)
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, err
}
