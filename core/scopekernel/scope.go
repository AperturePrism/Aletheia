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

	// PathPrefix 仅 url_prefix 规则使用：归一化后的路径前缀（始终以 "/" 开头）。
	//
	// 为什么必须单独存：08 §3 的 url_prefix 语义是「URL 前缀」
	// （例 `https://api.example.com/v2/` 只授权该主机下的 /v2/ 子树）。
	// 若只保留 host，规则会静默退化为「整站主机匹配」—— 授权范围被放大，
	// 且 include 侧会连带放行根路径与 /admin 等未授权路径。这是授权绕过
	// （07 §T5.5 / M6 §3.3），故 path 必须参与匹配。
	PathPrefix string
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
//
// 注意 url_prefix 的 host 比较**不使用裸 strings.HasPrefix**：
// 那会让规则 `api.example.com` 命中 `api.example.com.evil.com`
// （攻击者注册的相似域名）与 `api.example.comX`。必须按域标签边界比较。
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
		// host 必须精确相等（归一化后两侧都是小写规范形式）。
		// 不做后缀/子串匹配 —— 相似域名与后缀混淆由精确相等天然排除。
		//
		// 无 path 上下文时（Matches 的旧签名）保守处理：仅当规则本身
		// 不含路径约束（PathPrefix 为空或 "/"）才在 host 相等时命中。
		// 含路径约束的规则必须走 MatchesTarget 传入 path ——
		// 这里返回 false 是 fail-closed，避免"忘了传 path 就整站放行"。
		return r.Host == host && r.pathUnconstrained()
	default:
		return false
	}
}

// MatchesTarget 是带路径上下文的完整匹配入口（url_prefix 的正确语义）。
//
// targetPath 是请求路径（如 "/v2/users"）；不适用时传 ""。
// 语义（08 §3）：
//   - cidr / host 规则忽略 path；
//   - url_prefix 规则要求 host 精确相等 **且** 路径落在 PathPrefix 子树内。
//
// 路径边界必须按 **路径段** 比较，不能用裸 HasPrefix：
// `/v2/` 不应命中 `/v2evil`，`/admin` 不应命中 `/administrator`。
func (r TargetRule) MatchesTarget(host, targetPath string, port uint16) bool {
	if r.Kind != "url_prefix" {
		return r.Matches(host, port)
	}
	if r.Host != host {
		return false
	}
	if r.pathUnconstrained() {
		return true
	}
	return pathHasPrefix(targetPath, r.PathPrefix)
}

// pathUnconstrained 报告该 url_prefix 规则是否不含路径约束。
func (r TargetRule) pathUnconstrained() bool {
	return r.PathPrefix == "" || r.PathPrefix == "/"
}

// pathHasPrefix 按路径段边界判定 prefix。
//
// 规则（等价于 HTTP 路由的子树匹配语义）：
//
//	prefix "/v2/" → 命中 "/v2/", "/v2/users"；不命中 "/v2", "/v2evil"
//	prefix "/v2"  → 命中 "/v2", "/v2/users"；不命中 "/v2evil"
//
// 空 targetPath 视为 "/"（根路径）。
func pathHasPrefix(targetPath, prefix string) bool {
	if targetPath == "" {
		targetPath = "/"
	}
	// 尾斜杠语义："/v2/" 应命中 "/v2" 本身（根）与 "/v2/..." 全部子树。
	if strings.HasSuffix(prefix, "/") {
		if targetPath == strings.TrimSuffix(prefix, "/") {
			return true
		}
	}
	if !strings.HasPrefix(targetPath, prefix) {
		return false
	}
	// 前缀已到目标串末尾 → 命中。
	if len(targetPath) == len(prefix) {
		return true
	}
	// 否则要求边界字符是 '/'（段边界）或 prefix 自身以 '/' 结尾。
	if strings.HasSuffix(prefix, "/") {
		return true
	}
	return targetPath[len(prefix)] == '/'
}

// NewCIDRRule 构造 CIDR 规则（scope 解析时校验前缀合法性）。
func NewCIDRRule(value string) (TargetRule, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return TargetRule{}, fmt.Errorf("invalid cidr %q: %w", value, err)
	}
	return TargetRule{Kind: "cidr", Value: value, CIDR: prefix.Masked()}, nil
}

// NewURLPrefixRule 构造 url_prefix 规则（08 §3）。
//
// 必须**同时**保留 host 与 path —— 只留 host 会让规则静默退化为整站匹配，
// 使 `https://api.example.com/v2/` 连带授权 `/`、`/admin` 等未授权路径
// （授权绕过）。path 归一化为始终以 "/" 开头的形式。
func NewURLPrefixRule(value string) (TargetRule, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return TargetRule{}, fmt.Errorf("url_prefix is empty")
	}
	host, path, err := SplitURLHostPath(raw)
	if err != nil {
		return TargetRule{}, err
	}
	return TargetRule{
		Kind:       "url_prefix",
		Value:      value,
		Host:       host,
		PathPrefix: path,
	}, nil
}

// SplitURLHostPath 把 URL 或裸 host(+path) 拆为归一化 host 与路径前缀。
//
// 接受的形态（08 §3 的 url_prefix 用例含完整 URL）：
//
//	"https://api.example.com/v2/"   → ("api.example.com", "/v2/")
//	"http://allowed@evil.com/x"     → ("evil.com", "/x")   userinfo 不参与匹配
//	"api.example.com/v2"            → ("api.example.com", "/v2")
//	"api.example.com"               → ("api.example.com", "")
//
// 无路径时返回 ""（表示该规则不约束路径）。
func SplitURLHostPath(raw string) (host, path string, err error) {
	if strings.Contains(raw, "://") {
		u, uerr := url.Parse(raw)
		if uerr != nil {
			return "", "", fmt.Errorf("unparsable URL: %w", uerr)
		}
		h := u.Hostname()
		if h == "" {
			return "", "", fmt.Errorf("URL %q has no host", raw)
		}
		norm, nerr := NormalizeTarget(h)
		if nerr != nil {
			return "", "", nerr
		}
		// EscapedPath 保留原始转义，避免 %2F 被还原成 "/" 改变段边界。
		p := u.EscapedPath()
		if p == "" {
			p = ""
		}
		return norm, cleanPathPrefix(p), nil
	}
	// 裸 host 可能带路径："api.example.com/v2"
	if i := strings.IndexByte(raw, '/'); i >= 0 {
		hostPart, pathPart := raw[:i], raw[i:]
		norm, nerr := NormalizeTarget(hostPart)
		if nerr != nil {
			return "", "", nerr
		}
		return norm, cleanPathPrefix(pathPart), nil
	}
	norm, nerr := NormalizeTarget(raw)
	if nerr != nil {
		return "", "", nerr
	}
	return norm, "", nil
}

// cleanPathPrefix 归一化路径前缀：确保以 "/" 开头、折叠重复斜杠。
// 不做 URL 解码（解码会让 %2F 变成段分隔符，改变边界语义）。
func cleanPathPrefix(p string) string {
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// 折叠重复斜杠（"//v2" → "/v2"），保留尾斜杠语义。
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}
