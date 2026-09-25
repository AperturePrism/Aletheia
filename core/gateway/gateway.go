// Package gateway 实现 M6 Privacy Gateway（modules/M6 §4，Q5 红线）。
//
// 双向映射（M6 §4.1）：真实敏感值 → 确定性 token（模型可见）；
// 工具执行前一刻本地回注（token → 真实值）。出站二次扫描（§4.2）：
// 工具输出离开 L0 前按泄漏模式全量扫描，命中即阻断（PRIVACY_LEAK_DETECTED）。
//
// 安全约束（不可协商，09 §R7）：
//   - 映射确定性：同一真实值在同一会话内必须映射到同一 token
//     （否则模型无法建立跨证据的关联）；
//   - 映射表仅存内存（本进程），不落盘、不出进程、不进日志；
//   - 默认强制开启，无 UI 开关（配置文件显式禁用 + 启动高亮告警，
//     该开关属 alethd 启动逻辑，本包不提供旁路）。
package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// TokenCategory 是 05 §6.4 LeakHit 的五类敏感值。
type TokenCategory int

const (
	CatIPPrivate TokenCategory = iota
	CatHostInternal
	CatEmail
	CatCredential
	CatPathInternal
)

func (c TokenCategory) String() string {
	switch c {
	case CatIPPrivate:
		return "IP_PRIVATE"
	case CatHostInternal:
		return "HOST_INTERNAL"
	case CatEmail:
		return "EMAIL"
	case CatCredential:
		return "CREDENTIAL"
	case CatPathInternal:
		return "PATH_INTERNAL"
	}
	return "UNKNOWN"
}

// LEAK_PATTERNS 是出站二次扫描的泄漏模式（M6 §4.2 原文形态，Q5 的执行体）。
//
// PATH_INTERNAL 的 Python 原文含 lookbehind `(?<![\w/])` —— Go RE2 不支持
// lookbehind，改为独立扫描函数（scanPathInternal）手动排除前驱字符。
var LEAK_PATTERNS = map[TokenCategory]*regexp.Regexp{
	CatIPPrivate:    regexp.MustCompile(`\b(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)\d+\.\d+\b`),
	CatHostInternal: regexp.MustCompile(`\b[\w.-]+\.(internal|corp|local|lan)\b`),
	CatEmail:        regexp.MustCompile(`\b[\w.+-]+@[\w.-]+\.\w+\b`),
	CatCredential:   regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S+`),
}

// rePathInternal 是 PATH_INTERNAL 的 Go 等价模式（不含 lookbehind；
// 前驱排除在 scanPathInternal 内做）。
var rePathInternal = regexp.MustCompile(`/(?:opt|srv|home|etc)/[\w./-]+`)

// Gateway 持有会话内的 token 映射表。并发安全。
type Gateway struct {
	mu    sync.Mutex
	table map[string]tokenEntry // 真实值 → token（确定性：同值同 token）
	seq   map[TokenCategory]int // 各类别已发出的序号（IP_PRIVATE_001 的 001）
}

type tokenEntry struct {
	token string
	kind  TokenCategory
}

// NewGateway 建立空映射表。
func NewGateway() *Gateway {
	return &Gateway{table: make(map[string]tokenEntry), seq: make(map[TokenCategory]int)}
}

// Tokenize 把文本中的真实敏感值替换为确定性 token（M6 §4.1 正向）。
// 返回脱敏后的文本与本次发生的映射（调用方可记录审计，不含真实值）。
func (g *Gateway) Tokenize(text string) (string, []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := text
	var applied []string
	// 按类别顺序扫描；同一次调用内先替换的产物不再被后续类别误判
	//（token 形如 IP_PRIVATE_001，不含泄漏模式特征）。
	for _, cat := range []TokenCategory{CatIPPrivate, CatHostInternal, CatEmail, CatCredential} {
		re := LEAK_PATTERNS[cat]
		out = re.ReplaceAllStringFunc(out, func(matched string) string {
			token := g.tokenFor(matched, cat)
			applied = append(applied, token)
			return token
		})
	}
	out = g.tokenizePaths(out, &applied)
	return out, applied
}

// scanPathInternal 找出前驱不是 [\w/] 的内部路径（等价 Python lookbehind）。
// 前驱是字母/数字/下划线/斜杠说明路径是更长 token 的一部分（如 "wordsrv/etc"），不命中。
func scanPathInternal(text string) [][2]int {
	var out [][2]int
	for _, loc := range rePathInternal.FindAllStringIndex(text, -1) {
		if loc[0] > 0 {
			prev := text[loc[0]-1]
			if prev == '_' || prev == '/' ||
				(prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') {
				continue
			}
		}
		out = append(out, [2]int{loc[0], loc[1]})
	}
	return out
}

func (g *Gateway) tokenizePaths(text string, applied *[]string) string {
	locs := scanPathInternal(text)
	// 从后往前替换，避免偏移失效。
	for i := len(locs) - 1; i >= 0; i-- {
		loc := locs[i]
		real := text[loc[0]:loc[1]]
		token := g.tokenFor(real, CatPathInternal)
		*applied = append(*applied, token)
		text = text[:loc[0]] + token + text[loc[1]:]
	}
	return text
}

// tokenFor 返回真实值的确定性 token（调用方持锁）。
func (g *Gateway) tokenFor(real string, cat TokenCategory) string {
	if e, ok := g.table[real]; ok {
		return e.token
	}
	g.seq[cat]++
	token := fmt.Sprintf("%s_%03d", cat.String(), g.seq[cat])
	g.table[real] = tokenEntry{token: token, kind: cat}
	return token
}

// Detokenize 把 token 回注为真实值（工具执行前一刻，M6 §4.1 反向）。
// 未知 token 原样返回 —— 回注是保守替换，不猜测。
func (g *Gateway) Detokenize(text string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := text
	// 按真实值长度降序回注：长值优先，避免短值是长值前缀时误替换。
	reals := make([]string, 0, len(g.table))
	for real := range g.table {
		reals = append(reals, real)
	}
	sort.Slice(reals, func(i, j int) bool { return len(reals[i]) > len(reals[j]) })
	for _, real := range reals {
		out = strings.ReplaceAll(out, g.table[real].token, real)
	}
	return out
}

// ScanOutbound 是出站二次扫描（M6 §4.2）：命中即返回泄漏列表（阻断）。
// 在 Tokenize 之后调用 —— 若脱敏不完整（如目标侧回显了真实值），这里是
// 最后一道防线。
func (g *Gateway) ScanOutbound(text string) []LeakHit {
	var hits []LeakHit
	for _, cat := range []TokenCategory{CatIPPrivate, CatHostInternal, CatEmail, CatCredential} {
		re := LEAK_PATTERNS[cat]
		for _, loc := range re.FindAllStringIndex(text, -1) {
			hits = append(hits, LeakHit{
				Category:  cat.String(),
				Offset:    loc[0],
				Excerpt:   maskExcerpt(text[loc[0]:loc[1]]),
				ValueHash: hashValue(text[loc[0]:loc[1]]),
			})
		}
	}
	for _, loc := range scanPathInternal(text) {
		hits = append(hits, LeakHit{
			Category:  CatPathInternal.String(),
			Offset:    loc[0],
			Excerpt:   maskExcerpt(text[loc[0]:loc[1]]),
			ValueHash: hashValue(text[loc[0]:loc[1]]),
		})
	}
	return hits
}

// LeakHit 是一次泄漏命中（05 §6.4：excerpt 必须掩码 —— 告警日志不含真实值）。
type LeakHit struct {
	Category  string
	Offset    int
	Excerpt   string // 掩码后的片段（首尾各保留 1 字符）
	ValueHash string // 真实值的 sha256 前 16 字节（审计可比对，不可逆）
}

func maskExcerpt(s string) string {
	if len(s) <= 2 {
		return strings.Repeat("*", len(s))
	}
	return s[:1] + strings.Repeat("*", len(s)-2) + s[len(s)-1:]
}

func hashValue(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}
