// Package scopekernel 实现 M6 范围内核（modules/M6 §3，docs/08 §3 Scope 语法）。
//
// 裁决语义（08 §3 匹配优先级，不可协商 —— 09 §R8）：
//
//  1. exclude 命中 → 拒绝（排除项永远优先）
//  2. include 命中 → 允许
//  3. 均未命中     → 拒绝（默认拒绝，不是默认放行）
//
// 归一化（M6 §3.3 七类绕过手法的统一防线）：任何目标在比对前必须先
// 规范化为「真实 host 的点分十进制 / 规范域名」—— 十进制/八进制/十六进制
// IP、IPv6 映射、userinfo 混淆、尾点、超长域名都在这一层收口。
// DNS 解析后的 post_dns 复核由 Kernel.Check 的 L3 承担（本包只做纯函数
// 归一化与匹配，DNS 查询以 Resolver 接口注入，便于测试与超时控制）。
package scopekernel

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// MaxTargetLen 是目标字段长度上限（08 §3：超长域名截断防御 —— 先拒后查）。
const MaxTargetLen = 253 // DNS 域名的规范上限

// TargetRule 是一条 include/exclude 规则（08 §3 Scope 语法）。
type TargetRule struct {
	Kind  string // "cidr" | "host" | "url_prefix"
	Value string // 归一化前的原始值
	CIDR  netip.Prefix
	Host  string   // 归一化后的小写域名/IP
	Ports []uint16 // host 规则的可选端口限定
}

// Scope 是从 roe.yaml 解析出的授权范围。
type Scope struct {
	Include []TargetRule
	Exclude []TargetRule
}

// NormalizeTarget 把任意输入形式归一化为「真实 host + 可选端口」。
//
// 防御映射（08 §3 / M6 §3.3）：
//   - 十进制 IP（3232235777）、八进制（0177.0.0.1）、十六进制（0x7f.0.0.1）
//     → 统一解析为 netip.Addr 后输出规范形式；
//   - IPv6 映射 IPv4（::ffff:10.40.23.1）→ 展开为 IPv4；
//   - URL（含 userinfo `http://allowed@evil.com`）→ net/url 解析取 Host
//     （userinfo 永远不参与匹配）；
//   - 域名尾点（evil.com.）→ 去尾点；大小写 → 小写；
//   - 超长目标 → 直接拒绝（errTooLong），不做截断匹配。
func NormalizeTarget(raw string) (string, error) {
	if len(raw) > MaxTargetLen {
		return "", fmt.Errorf("target exceeds %d bytes (possible truncation attack)", MaxTargetLen)
	}
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("target is empty")
	}
	// URL 形态：解析取真实 host（userinfo / scheme / path 都剥离）。
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("unparsable URL: %w", err)
		}
		host := u.Hostname() // Hostname 已剥离 userinfo 与端口
		if host == "" {
			return "", fmt.Errorf("URL %q has no host", raw)
		}
		return normalizeHost(host)
	}
	return normalizeHost(s)
}

// normalizeHost 对裸 host/IP 归一化。
func normalizeHost(host string) (string, error) {
	host = strings.TrimSuffix(host, ".") // 尾点
	host = strings.ToLower(host)
	if host == "" {
		return "", fmt.Errorf("host is empty after normalization")
	}
	if strings.ContainsAny(host, "/@?") {
		return "", fmt.Errorf("host contains URL structure characters after stripping: %q", host)
	}
	// IP 形态（含十进制/八进制/十六进制混淆与 IPv6 映射）统一走 netip 解析。
	if addr, err := parseFlexibleIP(host); err == nil {
		return addr.String(), nil
	}
	// 其余按域名处理：只允许域名合法字符（宽度防线，格式校验交给 DNS 层）。
	for _, r := range host {
		ok := r == '-' || r == '_' || r == '.' ||
			(r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if !ok {
			return "", fmt.Errorf("host %q contains invalid character %q", host, r)
		}
	}
	return host, nil
}

// parseFlexibleIP 解析十进制/八进制/十六进制/IPv6 映射等 IP 混淆形态。
// net.ParseIP 不认八进制与十进制整数形态，这里先做数值展开再交给 netip。
func parseFlexibleIP(s string) (netip.Addr, error) {
	// 1) IPv6 映射 IPv4（::ffff:a.b.c.d 或 ::ffff:aabbccdd）→ 展开。
	if strings.HasPrefix(strings.ToLower(s), "::ffff:") {
		v4 := strings.TrimPrefix(strings.ToLower(s), "::ffff:")
		if addr, err := parseFlexibleIP(v4); err == nil && addr.Is4() {
			return addr, nil
		}
	}
	// 2) 纯十进制整数（如 3232235777）→ 点分十进制。
	if isAll(s, '0', '9') && len(s) > 0 && len(s) <= 10 {
		if n, ok := parseUint64(s); ok && n <= 0xFFFFFFFF {
			b := [4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
			return netip.AddrFrom4(b), nil
		}
	}
	// 3) 点分形态中的八进制/十六进制段（0177.0.0.1 / 0x7f.0.0.1）。
	if strings.Count(s, ".") == 3 {
		parts := strings.Split(s, ".")
		var b [4]byte
		valid := true
		for i, p := range parts {
			n, err := parseOctet(p)
			if err != nil {
				valid = false
				break
			}
			b[i] = n
		}
		if valid {
			return netip.AddrFrom4(b), nil
		}
	}
	// 4) 标准 IP（含 IPv6）。
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap(), nil
	}
	return netip.Addr{}, fmt.Errorf("not an IP: %q", s)
}

// parseOctet 解析单个 IPv4 八位组，接受十进制 / 0 前缀八进制 / 0x 十六进制。
func parseOctet(p string) (byte, error) {
	if p == "" {
		return 0, fmt.Errorf("empty octet")
	}
	base := 10
	if strings.HasPrefix(p, "0x") || strings.HasPrefix(p, "0X") {
		base = 16
		p = p[2:]
	} else if len(p) > 1 && p[0] == '0' {
		base = 8
		p = p[1:]
	}
	n := 0
	for i := 0; i < len(p); i++ {
		c := p[i]
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case base == 16 && c >= 'a' && c <= 'f':
			d = int(c-'a') + 10
		case base == 16 && c >= 'A' && c <= 'F':
			d = int(c-'A') + 10
		default:
			return 0, fmt.Errorf("bad octet digit %q", p)
		}
		if d >= base {
			return 0, fmt.Errorf("digit %q out of base %d", p, base)
		}
		n = n*base + d
		if n > 255 {
			return 0, fmt.Errorf("octet overflow %q", p)
		}
	}
	return byte(n), nil
}

func isAll(s string, lo, hi byte) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < lo || s[i] > hi {
			return false
		}
	}
	return true
}

func parseUint64(s string) (uint64, bool) {
	var n uint64
	for i := 0; i < len(s); i++ {
		n = n*10 + uint64(s[i]-'0')
		if n > 0xFFFFFFFF {
			return 0, false
		}
	}
	return n, true
}

// Matches 判定已归一化的目标是否命中本规则。
func (r TargetRule) Matches(host string, port uint16) bool {
	switch r.Kind {
	case "cidr":
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return false // 域名不与 CIDR 直接匹配（host 规则承担）
		}
		return r.CIDR.Contains(addr.Unmap())
	case "host":
		if r.Host != host {
			return false
		}
		if len(r.Ports) == 0 {
			return true
		}
		for _, p := range r.Ports {
			if p == port {
				return true
			}
		}
		return false
	case "url_prefix":
		return strings.HasPrefix(host, r.Host)
	default:
		return false
	}
}

// NewCIDRRule 构造 CIDR 规则（scope 解析时校验前缀合法性）。
func NewCIDRRule(value string) (TargetRule, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return TargetRule{}, fmt.Errorf("invalid cidr %q: %w", value, err)
	}
	return TargetRule{Kind: "cidr", Value: value, CIDR: prefix.Masked()}, nil
}
