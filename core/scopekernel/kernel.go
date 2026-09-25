// Kernel 实现三重校验（M6 §3.1）与 roe.yaml Scope 段解析（08 §3）。
//
//	L1 network      —— 目标 IP/CIDR/host 是否在 scope 白名单内
//	L2 tool_param   —— 工具参数中的 target 字段（由 M1 渲染 argv 前调用）
//	L3 post_dns     —— DNS 解析后的真实 IP 再复核（防 rebinding / 重定向落点）
//
// 熔断语义（M6 §3.2 不可协商）：DENY 返回 allowed=false，调用方必须
// 触发 SCOPE_VIOLATION 终止整场会话 —— 本包只诚实裁决，不做"告警后继续"。
package scopekernel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Resolver 抽象 DNS 查询（L3 post_dns 用）。
// 生产环境注入 net.Resolver；测试注入固定解析表。
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IP, error)
}

// RateLimit 是按「目标 + 会话」维度的速率限制（M6 §3.4，对 D16 的回应）。
type RateLimit struct {
	PerMinute int
}

// Kernel 是范围裁决内核。
type Kernel struct {
	mu       sync.Mutex
	scope    Scope
	resolver Resolver
	rate     RateLimit
	hits     map[string][]time.Time // "session|host" -> 请求时间戳
}

// NewKernel 构造内核。resolver 可为 nil —— nil 时 L3 post_dns 拒绝
// （fail-closed：没有解析能力就不能宣称"解析后已复核"）。
func NewKernel(scope Scope, resolver Resolver, rate RateLimit) *Kernel {
	if rate.PerMinute <= 0 {
		rate.PerMinute = 60
	}
	return &Kernel{
		scope:    scope,
		resolver: resolver,
		rate:     rate,
		hits:     make(map[string][]time.Time),
	}
}

// Verdict 是一次裁决的结论（映射 proto ScopeCheckResult）。
type Verdict struct {
	Allowed    bool
	FailedBy   string // "" | "exclude" | "default_deny" | "rate_limit" | "dns_unresolvable"
	DecisionID string
	Reason     string
}

// Check 对已归一化目标做 scope 裁决（L1/L2 共用比对逻辑；L3 见 CheckResolved）。
func (k *Kernel) Check(sessionID, target string) Verdict {
	host, port, err := splitAndNormalize(target)
	if err != nil {
		return k.deny(sessionID, host, "default_deny", fmt.Sprintf("normalization rejected: %v", err))
	}
	return k.judge(sessionID, host, port)
}

// CheckResolved 在 DNS 解析**之后**复核（L3）：解析出的每个 IP 都必须在
// scope 内 —— 任一解析结果越界即整体拒绝（防 rebinding / 通配符 DNS）。
func (k *Kernel) CheckResolved(ctx context.Context, sessionID, target string) Verdict {
	host, port, err := splitAndNormalize(target)
	if err != nil {
		return k.deny(sessionID, host, "default_deny", fmt.Sprintf("normalization rejected: %v", err))
	}
	// 域名才需要解析复核；已归一化为 IP 的目标在 L1 已精确匹配。
	if !isIPLiteral(host) {
		if k.resolver == nil {
			return k.deny(sessionID, host, "dns_unresolvable",
				"post_dns check requires a resolver; refusing without one (fail-closed)")
		}
		addrs, err := k.resolver.LookupIPAddr(ctx, host)
		if err != nil || len(addrs) == 0 {
			return k.deny(sessionID, host, "dns_unresolvable", fmt.Sprintf("DNS lookup failed: %v", err))
		}
		for _, ip := range addrs {
			if !k.inScope(ip.String(), port) {
				return k.deny(sessionID, host, "exclude",
					fmt.Sprintf("post_dns: resolved address %s outside scope", ip.String()))
			}
		}
	}
	return k.judge(sessionID, host, port)
}

// judge 执行 08 §3 的匹配语义（exclude 优先 → include → 默认拒绝）+ 限流。
func (k *Kernel) judge(sessionID, host string, port uint16) Verdict {
	// 1. exclude 命中 → 拒绝（永远优先于包含项 —— 安全默认）。
	for _, r := range k.scope.Exclude {
		if r.Matches(host, port) {
			return k.deny(sessionID, host, "exclude",
				fmt.Sprintf("target matches exclude rule %q", r.Value))
		}
	}
	// 2. include 命中 → 允许（进入限流）。
	included := false
	for _, r := range k.scope.Include {
		if r.Matches(host, port) {
			included = true
			break
		}
	}
	if !included {
		// 3. 均未命中 → 拒绝（默认拒绝，不是默认放行）。
		return k.deny(sessionID, host, "default_deny",
			"target not in include list (default-deny policy)")
	}
	// 4. 速率限制（M6 §3.4）：目标 + 会话维度。
	if !k.allowRate(sessionID, host) {
		return k.deny(sessionID, host, "rate_limit",
			fmt.Sprintf("rate limit exceeded (%d/min per target+session)", k.rate.PerMinute))
	}
	return Verdict{
		Allowed:    true,
		DecisionID: newDecisionID(),
		Reason:     fmt.Sprintf("in scope (%s)", host),
	}
}

// allowRate 是固定窗口计数（1 分钟）。实现刻意简单：
// 限流是防御纵深的一层而非精确计量，超时窗口的计数器即够用（M6 §3.4）。
func (k *Kernel) allowRate(sessionID, host string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	key := sessionID + "|" + host
	now := time.Now()
	window := now.Add(-time.Minute)
	fresh := k.hits[key][:0]
	for _, t := range k.hits[key] {
		if t.After(window) {
			fresh = append(fresh, t)
		}
	}
	if len(fresh) >= k.rate.PerMinute {
		k.hits[key] = fresh
		return false
	}
	k.hits[key] = append(fresh, now)
	return true
}

func (k *Kernel) deny(sessionID, host, failedBy, reason string) Verdict {
	return Verdict{
		Allowed:    false,
		FailedBy:   failedBy,
		DecisionID: newDecisionID(),
		Reason:     reason,
	}
}

// inScope 仅做 include/exclude 比对（L3 内部用；已排除限流语义）。
func (k *Kernel) inScope(host string, port uint16) bool {
	for _, r := range k.scope.Exclude {
		if r.Matches(host, port) {
			return false
		}
	}
	for _, r := range k.scope.Include {
		if r.Matches(host, port) {
			return true
		}
	}
	return false // 默认拒绝
}

// splitAndNormalize 把原始目标拆为 (host, port) 并归一化。
// 无端口时 port=0（表示"不限端口"，由 host 规则的 Ports 语义裁决）。
// 拆分先于归一化 —— `:` 不在裸 host 的合法字符集内。
func splitAndNormalize(target string) (string, uint16, error) {
	var hostPart, portPart string
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return "", 0, fmt.Errorf("unparsable URL: %w", err)
		}
		hostPart, portPart = u.Hostname(), u.Port()
	} else if i := strings.LastIndex(target, ":"); i >= 0 && !strings.Contains(target[i+1:], "]") {
		// IPv6 字面量（含多个冒号）不走此分支：无 :// 且不以 [:: 开头的
		// 情况下，最后一段冒号后是数字才视为端口。
		if isAll(target[i+1:], '0', '9') {
			hostPart, portPart = target[:i], target[i+1:]
		} else {
			hostPart = target
		}
	} else {
		hostPart = target
	}
	host, err := NormalizeTarget(hostPart)
	if err != nil {
		return "", 0, err
	}
	var port uint16
	if portPart != "" {
		n, err := strconv.ParseUint(portPart, 10, 16)
		if err != nil {
			return "", 0, fmt.Errorf("bad port %q", portPart)
		}
		port = uint16(n)
	}
	return host, port, nil
}

func isIPLiteral(host string) bool {
	return strings.Contains(host, ":") || strings.Count(host, ".") == 3
}

// newDecisionID 生成裁决记录 ID（写入审计链，08 §6.1）。
func newDecisionID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand 失败是系统级异常：fail-closed（09 §6 #2）。
		panic(fmt.Sprintf("scopekernel: crypto/rand unavailable: %v", err))
	}
	sum := sha256.Sum256(b)
	return "dec_" + hex.EncodeToString(sum[:8])
}
