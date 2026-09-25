package scopekernel

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

func mustNormalize(t *testing.T, raw string) string {
	t.Helper()
	got, err := NormalizeTarget(raw)
	if err != nil {
		t.Fatalf("NormalizeTarget(%q): %v", raw, err)
	}
	return got
}

// ---- 归一化（M6 §3.3 / 08 §3 的七类输入形态）----

func TestNormalizeDecimalIP(t *testing.T) {
	// 十进制整数 3232235777 = 192.168.1.1。
	if got := mustNormalize(t, "3232235777"); got != "192.168.1.1" {
		t.Fatalf("decimal IP = %q", got)
	}
}

func TestNormalizeOctalAndHexOctets(t *testing.T) {
	if got := mustNormalize(t, "0177.0.0.1"); got != "127.0.0.1" {
		t.Fatalf("octal octets = %q", got)
	}
	if got := mustNormalize(t, "0x7f.0.0.1"); got != "127.0.0.1" {
		t.Fatalf("hex octets = %q", got)
	}
	if got := mustNormalize(t, "0xC0.0xA8.0x01.0x01"); got != "192.168.1.1" {
		t.Fatalf("mixed hex = %q", got)
	}
}

func TestNormalizeIPv6MappedIPv4(t *testing.T) {
	if got := mustNormalize(t, "::ffff:10.40.23.1"); got != "10.40.23.1" {
		t.Fatalf("ipv6-mapped = %q", got)
	}
}

func TestNormalizeURLUserinfo(t *testing.T) {
	// 必须取真实 host（evil.com），userinfo（allowed）永远不参与匹配。
	if got := mustNormalize(t, "http://allowed@evil.com"); got != "evil.com" {
		t.Fatalf("userinfo URL = %q", got)
	}
	if got := mustNormalize(t, "https://user:pass@app.example.com/v2/"); got != "app.example.com" {
		t.Fatalf("https URL = %q", got)
	}
}

func TestNormalizeTrailingDotAndCase(t *testing.T) {
	if got := mustNormalize(t, "Evil.COM."); got != "evil.com" {
		t.Fatalf("trailing dot = %q", got)
	}
}

func TestNormalizeRejectsOversizedAndGarbage(t *testing.T) {
	long := strings.Repeat("a.", 140) + "com" // > 253 字节
	if _, err := NormalizeTarget(long); err == nil {
		t.Fatal("oversized target must be rejected (truncation attack)")
	}
	if _, err := NormalizeTarget(""); err == nil {
		t.Fatal("empty target must be rejected")
	}
	if _, err := NormalizeTarget("http://"); err == nil {
		t.Fatal("URL without host must be rejected")
	}
	if _, err := NormalizeTarget("in valid"); err == nil {
		t.Fatal("whitespace inside host must be rejected")
	}
}

// ---- 匹配语义（08 §3：exclude 优先 / include / 默认拒绝）----

func testScope() Scope {
	include, _ := NewCIDRRule("10.40.23.0/24")
	excludeDB, _ := NewCIDRRule("10.40.23.128/25")
	excludeHost := TargetRule{Kind: "host", Host: "pay.example.com", Value: "pay.example.com"}
	includeHost := TargetRule{Kind: "host", Host: "app.example.com", Ports: []uint16{80, 443}}
	return Scope{
		Include: []TargetRule{include, includeHost},
		Exclude: []TargetRule{excludeDB, excludeHost},
	}
}

func TestExcludeBeatsInclude(t *testing.T) {
	k := NewKernel(testScope(), nil, RateLimit{PerMinute: 1000})
	// 10.40.23.200 同时在 include /24 与 exclude /25 → exclude 永远优先。
	if v := k.Check("sess", "10.40.23.200"); v.Allowed {
		t.Fatal("exclude rule must win over include (安全默认)")
	}
	if v := k.Check("sess", "10.40.23.200"); v.FailedBy != "exclude" {
		t.Fatalf("failed_by = %q, want exclude", v.FailedBy)
	}
	if v := k.Check("sess", "10.40.23.1"); !v.Allowed {
		t.Fatalf("in-scope target must pass: %s", v.Reason)
	}
}

func TestDefaultDeny(t *testing.T) {
	k := NewKernel(testScope(), nil, RateLimit{PerMinute: 1000})
	v := k.Check("sess", "192.0.2.99") // 不在任何规则里
	if v.Allowed || v.FailedBy != "default_deny" {
		t.Fatalf("unlisted target must be default-deny, got %+v", v)
	}
}

func TestHostPortRestriction(t *testing.T) {
	k := NewKernel(testScope(), nil, RateLimit{PerMinute: 1000})
	// app.example.com 仅允许 80/443。
	if v := k.Check("sess", "app.example.com:443"); !v.Allowed {
		t.Fatalf("443 should pass: %s", v.Reason)
	}
	if v := k.Check("sess", "app.example.com:8080"); v.Allowed {
		t.Fatal("8080 not in ports list must be denied")
	}
}

func TestExcludeHost(t *testing.T) {
	k := NewKernel(testScope(), nil, RateLimit{PerMinute: 1000})
	// 大小写/尾点混淆后仍必须命中 exclude。
	if v := k.Check("sess", "PAY.Example.COM."); v.Allowed {
		t.Fatal("exclude host must match after normalization")
	}
}

// ---- L3 post_dns（rebinding / 通配符 DNS）----

type fakeResolver map[string][]net.IP

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IP, error) {
	if ips, ok := f[host]; ok {
		return ips, nil
	}
	return nil, fmt.Errorf("no such host %q", host)
}

func TestPostDNSRebindingDetected(t *testing.T) {
	// app.example.com 首次解析返回合法 IP，第二次返回范围外 IP（rebinding）。
	res := fakeResolver{"app.example.com": {
		net.ParseIP("10.40.23.5"),
		net.ParseIP("192.0.2.99"), // 范围外
	}}
	k := NewKernel(testScope(), res, RateLimit{PerMinute: 1000})
	v := k.CheckResolved(context.Background(), "sess", "app.example.com")
	if v.Allowed {
		t.Fatal("any resolved address outside scope must deny the whole check")
	}
	if v.FailedBy != "exclude" {
		t.Fatalf("failed_by = %q", v.FailedBy)
	}
}

func TestPostDNSNilResolverFailsClosed(t *testing.T) {
	k := NewKernel(testScope(), nil, RateLimit{PerMinute: 1000})
	v := k.CheckResolved(context.Background(), "sess", "app.example.com")
	if v.Allowed || v.FailedBy != "dns_unresolvable" {
		t.Fatal("post_dns without resolver must fail closed")
	}
}

// ---- 速率限制（M6 §3.4）----

func TestRateLimitPerTargetSession(t *testing.T) {
	k := NewKernel(testScope(), nil, RateLimit{PerMinute: 3})
	for i := 0; i < 3; i++ {
		if v := k.Check("sessA", "10.40.23.10"); !v.Allowed {
			t.Fatalf("request %d within limit must pass", i)
		}
	}
	if v := k.Check("sessA", "10.40.23.10"); v.Allowed || v.FailedBy != "rate_limit" {
		t.Fatalf("4th request must hit rate limit, got %+v", v)
	}
	// 不同会话/目标各自独立计数。
	if v := k.Check("sessB", "10.40.23.10"); !v.Allowed {
		t.Fatalf("other session must have its own budget")
	}
	if v := k.Check("sessA", "10.40.23.11"); !v.Allowed {
		t.Fatalf("other target must have its own budget")
	}
}

// ---- roe.yaml 解析 ----

func TestParseScopeYAML(t *testing.T) {
	yaml := `
targets:
  include:
    - cidr: "10.40.23.0/24"
    - host: "app.example.com"
      ports: [80, 443]
  exclude:
    - cidr: "10.40.23.128/25"
    - host: "pay.example.com"
`
	scope, err := ParseScope([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(scope.Include) != 2 || len(scope.Exclude) != 2 {
		t.Fatalf("parsed scope = %+v", scope)
	}
	k := NewKernel(scope, nil, RateLimit{PerMinute: 1000})
	if v := k.Check("sess", "10.40.23.7"); !v.Allowed {
		t.Fatalf("in-scope CIDR must pass: %s", v.Reason)
	}
	if v := k.Check("sess", "pay.example.com"); v.Allowed {
		t.Fatal("exclude host must deny")
	}
}

func TestParseScopeRejectsEmptyInclude(t *testing.T) {
	_, err := ParseScope([]byte("targets:\n  exclude:\n    - cidr: \"10.0.0.0/8\"\n"))
	if err == nil {
		t.Fatal("scope without include targets must be a config error (fail-closed)")
	}
}
