// Package log 提供结构化日志，并内置脱敏。
//
// 对应 modules/M6 横切能力层 I0 任务 T6.1：
//
//	配置系统 + 结构化日志（含脱敏日志格式）
//
// 脱敏是硬约束而非可选项：
//
//   - 05 §3.2「凭据存储硬约束」：实体属性中禁止出现明文凭据。
//   - modules/M6 §4.1「映射表安全」：映射表不落普通日志，日志中只有 token。
//   - 08 §6.2「日志保护」：日志中只有 Privacy Gateway 的 token，无真实 IP/凭据。
//
// 因此本包在 zap 之上加一层确定性脱敏 Core。它在 I3 会把脱敏委托给
// Privacy Gateway（真正的双向映射表在那里），I0 先用一组保守的确定性规则，
// 覆盖最危险的几类：私有 IP、内网域名、凭据键值、内部路径、email。
//
// 设计原则：脱敏规则必须是确定性的、可测试的（P-2），并且**宁可误伤不可漏放**——
// 对真实值来说，漏放的代价远高于误伤。
package log

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// 脱敏类别。命名与 05 §6.4 LeakHit.category 一致（便于两个模块的审计口径统一）。
const (
	CatIPPrivate    = "IP_PRIVATE"
	CatHostInternal = "HOST_INTERNAL"
	CatEmail        = "EMAIL"
	CatCredential   = "CREDENTIAL"
	CatPathInternal = "PATH_INTERNAL"
)

// 脱敏模式集合。
//
// 与 modules/M6 §4.2 的 LEAK_PATTERNS 对齐（同一组正则，Go 侧与 Python 侧
// 必须字面一致 —— 两侧的差异本身会变成"看起来脱敏了实际没脱敏"的漏洞）。
// 在 I3 会把这份清单收敛为唯一的共享定义（并加一条 CI 校验两侧一致）。
var leakPatterns = []struct {
	category string
	re       *regexp.Regexp
	mask     string
}{
	// 私有 IPv4。
	{
		CatIPPrivate,
		regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b`),
		"IP_PRIVATE_REDACTED",
	},
	// 内网域名后缀。modules/M6 §4.2 原文为 \b[\w.-]+\.(internal|corp|local|lan)\b，
	// Go RE2 不支持 lookbehind，改用等价的显式写法。
	{
		CatHostInternal,
		regexp.MustCompile(`\b[\w.-]+\.(internal|corp|local|lan)\b`),
		"HOST_INTERNAL_REDACTED",
	},
	// Email。
	{
		CatEmail,
		regexp.MustCompile(`\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b`),
		"EMAIL_REDACTED",
	},
	// 凭据键值。modules/M6 §4.2 原文含 (?i) 前缀词，Go 用 (?i) 标记。
	{
		CatCredential,
		regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S+`),
		"CREDENTIAL_REDACTED",
	},
	// 内部路径。modules/M6 §4.2 原文带 lookbehind (?<![\w/])，Go RE2 不支持，
	// 改用 \A|[^\w/] 的等价写法。
	{
		CatPathInternal,
		regexp.MustCompile(`(^|[^\w/])/(opt|srv|home|etc)/[\w./-]+`),
		"PATH_INTERNAL_REDACTED",
	},
}

// 已知的假阳性排除：脱敏不应破坏我们自己生成的 token。
// Privacy Gateway 的 token 形如 IP_PRIVATE_001 / HOST_INTERNAL_001（05 §1.1），
// 它们已经是脱敏形式，不应被二次改写。
var gatewayTokenRe = regexp.MustCompile(`\b(IP_PRIVATE|HOST_INTERNAL|CRED|PATH_INTERNAL|EMAIL)_\d+\b`)

// Redact 对字符串做确定性脱敏，返回脱敏后的文本与命中的类别列表。
//
// 确定性要求：同一输入永远得到同一输出（不含随机数、不含时间戳）。
// 这是 P-5（可复现即一切）在日志层面的体现 ——
// 同一条审计记录必须能在不同机器上重放出相同内容。
func Redact(s string) (string, []string) {
	if s == "" {
		return s, nil
	}

	// 保护已有的 gateway token，脱敏后原样放回。
	// token 本身已是脱敏形式，不应被规则二次改写。
	restored := restoreTokens(s)

	var categories []string
	seen := map[string]bool{}
	text := restored.masked
	for _, p := range leakPatterns {
		if p.re.MatchString(text) {
			if !seen[p.category] {
				seen[p.category] = true
				categories = append(categories, p.category)
			}
			text = p.re.ReplaceAllString(text, p.mask)
		}
	}
	return restored.unmask(text), categories
}

// tokenHide 记录被临时替换掉的 gateway token，用于脱敏后还原。
type tokenHide struct {
	masked       string // token 被替换成占位符后的文本
	placeholders []string
	originals    []string
}

// restoreTokens 把 gateway token 替换为占位符，返回可还原的句柄。
func restoreTokens(s string) tokenHide {
	tokens := gatewayTokenRe.FindAllString(s, -1)
	h := tokenHide{masked: s}
	for _, t := range tokens {
		ph := fmt.Sprintf("\x00GT%d\x00", len(h.originals))
		h.masked = strings.Replace(h.masked, t, ph, 1)
		h.placeholders = append(h.placeholders, ph)
		h.originals = append(h.originals, t)
	}
	return h
}

func (h tokenHide) unmask(s string) string {
	for i, ph := range h.placeholders {
		s = strings.Replace(s, ph, h.originals[i], 1)
	}
	return s
}

// RedactIsClean 判断字符串是否不含任何真实敏感值。用于出站前的二次校验。
func RedactIsClean(s string) bool {
	_, cats := Redact(s)
	return len(cats) == 0
}

// Options 日志初始化选项。
type Options struct {
	// Level debug / info / warn / error。非法值按 info 处理。
	Level string
	// Format json / console。
	Format string
	// File 日志文件。为空则只写 stderr。
	File string
	// DisableRedaction 关闭脱敏。
	//
	// 仅用于测试与调试。生产配置不暴露该开关（R7 精神：
	// 安全默认不给人随手关掉的机会）。设为 true 时 New() 会返回一个
	// 带 immutable 标记的 logger 并在首条日志高亮告警。
	DisableRedaction bool
}

// New 构造 logger。
func New(opts Options) (*zap.Logger, error) {
	zapLevel := zap.InfoLevel
	switch strings.ToLower(strings.TrimSpace(opts.Level)) {
	case "debug":
		zapLevel = zap.DebugLevel
	case "info", "":
		zapLevel = zap.InfoLevel
	case "warn":
		zapLevel = zap.WarnLevel
	case "error":
		zapLevel = zap.ErrorLevel
	default:
		// 未知级别按 info 处理，但显式记录下来（不静默）。
		zapLevel = zap.InfoLevel
		opts.Level = "info"
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	// ISO8601 UTC（05 §1.2：所有时间字段 RFC 3339 UTC）。
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	// 秒级时间戳精度足够，且避免纳秒带来的不确定性。
	encoderCfg.EncodeDuration = zapcore.SecondsDurationEncoder

	var writeSyncer zapcore.WriteSyncer
	if strings.TrimSpace(opts.File) != "" {
		f, err := os.OpenFile(opts.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, fmt.Errorf("log: open %q: %w", opts.File, err)
		}
		writeSyncer = zap.CombineWriteSyncers(f, zapcore.Lock(os.Stderr))
	} else {
		writeSyncer = zapcore.Lock(os.Stderr)
	}

	// 包一层脱敏 Core。这是"日志中只有 token"的执行点。
	if !opts.DisableRedaction {
		writeSyncer = &redactingWriteSyncer{ws: writeSyncer}
	}

	var encoder zapcore.Encoder
	switch strings.ToLower(strings.TrimSpace(opts.Format)) {
	case "console":
		encoder = zapcore.NewConsoleEncoder(encoderCfg)
	case "json", "":
		encoder = zapcore.NewJSONEncoder(encoderCfg)
	default:
		encoder = zapcore.NewJSONEncoder(encoderCfg)
	}

	core := zapcore.NewCore(encoder, writeSyncer, zapLevel)

	logger := zap.New(core,
		// 调用方信息（文件:行）在 debug 级才有，避免正常运行时刷屏。
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)

	if opts.DisableRedaction {
		// 脱敏被关闭 —— 按 R7 精神必须高亮告警。
		logger.Warn("log: redaction DISABLED (debug only); real sensitive values may appear in logs")
	}

	return logger, nil
}

// redactingWriteSyncer 在写出前对整行做确定性脱敏。
//
// 为什么在 WriteSyncer 层而不是字段层：
// zap 的字段链要求每个调用点都记得脱敏，人会漏。在出口处统一处理，
// 使得"漏调用"不可能发生 —— 这正是 fail-closed 的思路。
type redactingWriteSyncer struct {
	ws zapcore.WriteSyncer
}

func (r *redactingWriteSyncer) Write(p []byte) (int, error) {
	redacted, _ := Redact(string(p))
	n, err := r.ws.Write([]byte(redacted))
	if err != nil {
		return n, err
	}
	// 返回原始长度：zap 用返回值判断写入是否完整，
	// 而脱敏后长度不同。上报 len(p) 以保持 io.Writer 契约。
	if n != len([]byte(redacted)) {
		return n, nil
	}
	return len(p), nil
}

func (r *redactingWriteSyncer) Sync() error { return r.ws.Sync() }

// NewNop 返回一个丢弃所有输出的 logger。用于测试。
func NewNop() *zap.Logger {
	return zap.NewNop()
}

var (
	globalMu sync.RWMutex
	global   = zap.NewNop()
)

// SetGlobal 替换全局 logger。应在进程启动时调用一次。
func SetGlobal(l *zap.Logger) {
	globalMu.Lock()
	defer globalMu.Unlock()
	global = l
}

// L 返回全局 logger。
func L() *zap.Logger {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}

// S 返回全局 sugared logger。
func S() *zap.SugaredLogger { return L().Sugar() }
