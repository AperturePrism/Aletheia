// Package ingest 实现 L0 光谱摄入（docs/05 §2、modules/M1）。
//
// 本包是系统唯一允许与外部工具交互的入口，也是「不让 LLM 碰命令行」这条
// 规则（09 §R5）的执行者：argv 由参数化 Schema 确定性渲染，任何形如
// run("nmap "+llm_output) 的路径在这里从类型系统上就不存在 ——
// RenderArgv 的输入是 map[string]string（填槽值），不是字符串命令。
//
// 解析器为纯函数（M1 §4.3）：无 IO、无全局状态、无时间/随机依赖，
// 相同输入必得相同输出（P-5 / Q6）。无法解析的行进入 ParseQuality 并
// 保留为原始行记录，不得静默丢弃。
package ingest

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// Adapter 是工具适配器的统一接口（M1 §4.1）。每个工具一个实现。
type Adapter interface {
	// Name 是工具名（即 IngestService 工具白名单的键，05 §2.2 ToolRequest.tool_name）。
	Name() string

	// SupportedVersions 是适配器声明支持的工具版本区间（含端点）。
	// ValidateTool 与 Execute 都以此做版本门禁：不匹配即 TOOL_VERSION_MISMATCH，
	// fail-closed，不静默降级（04 §I1 风险缓解）。
	SupportedVersions() VersionRange

	// Schema 是参数化 Schema。参数名必须匹配它，否则 INVALID_ARGUMENT
	//（M1 §4.3 翻车点 3：禁止静默拒绝）。
	Schema() *ParamSchema

	// RenderArgv 校验参数并确定性渲染完整 argv（含 argv[0]）。
	// 参数按 Schema 定义顺序拼接，map 迭代顺序不影响结果（M1 §4.5）。
	RenderArgv(params map[string]string) ([]string, error)

	// Parse 把工具原始输出确定性地解析为光谱（不含 ToolInvocation/RawOutputRef，
	// 那些由执行上下文组装）。raw 必须是未清洗的原始字节 —— 解析器内部先归一化。
	Parse(raw []byte, execID string) (*alethv1.EvidenceSpectrum, error)

	// FoldStrategy 返回该工具的折叠策略（M1 §4.1）。当前 I1 只暴露组上限；
	// fold=off 调试开关在 Service 层（M1 §8）。
	FoldStrategy() FoldStrategy
}

// FoldStrategy 是一个工具的无损折叠策略（M1 §4.4）。
type FoldStrategy struct {
	// MaxFoldGroup 限制单个折叠组的记录条数；0 表示不限。
	MaxFoldGroup int
}

// VersionRange 是含端点的工具版本支持区间。
type VersionRange struct {
	Min string // 如 "7.80"；空串 = 无下限（不建议：门禁要显式）
	Max string // 如 "7.99"；空串 = 无上限（不建议，理由同上）
}

// Version 是解析后的语义版本号；缺失分量按 0。
type Version struct{ Major, Minor, Patch int }

// versionRe 提取字符串中第一组 MAJOR[.MINOR[.PATCH]]。
// 工具版本横幅形如 "Nmap version 7.94"、"httpx v1.6.0"、"nuclei 3.2.7"。
var versionRe = regexp.MustCompile(`(?:^|[^\d.])(\d+)(?:\.(\d+))?(?:\.(\d+))?`)

// ParseVersion 从版本横幅提取语义版本。
// 独立成函数（而非内联在各适配器）是因为版本串本身是解析陷阱：
// "2 (RPC #100000)" 之类内容混入版本位是 M1 §4.3 翻车点 1 的变体。
func ParseVersion(s string) (Version, error) {
	m := versionRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Version{}, fmt.Errorf("no version number found in %q", s)
	}
	v := Version{atoi(m[1]), atoi(m[2]), atoi(m[3])}
	return v, nil
}

// VersionInRange 判定 version 是否落在区间内（含端点）。
// 区间端点解析失败是配置错误：fail-closed（返回错误而非宽松处理）。
func VersionInRange(version string, r VersionRange) (bool, error) {
	v, err := ParseVersion(version)
	if err != nil {
		return false, fmt.Errorf("detect version: %w", err)
	}
	if r.Min != "" {
		lo, err := ParseVersion(r.Min)
		if err != nil {
			return false, fmt.Errorf("min bound: %w", err)
		}
		if compareVersion(v, lo) < 0 {
			return false, nil
		}
	}
	if r.Max != "" {
		hi, err := ParseVersion(r.Max)
		if err != nil {
			return false, fmt.Errorf("max bound: %w", err)
		}
		if compareVersion(v, hi) > 0 {
			return false, nil
		}
	}
	return true, nil
}

func compareVersion(a, b Version) int {
	if a.Major != b.Major {
		return sign(a.Major - b.Major)
	}
	if a.Minor != b.Minor {
		return sign(a.Minor - b.Minor)
	}
	return sign(a.Patch - b.Patch)
}

func sign(n int) int {
	switch {
	case n > 0:
		return 1
	case n < 0:
		return -1
	default:
		return 0
	}
}

func atoi(s string) int {
	if s == "" {
		return 0
	}
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// ---- 参数化 Schema（M1 §4.2）----

// ParamType 是参数值类型。每种类型的校验规则见 validateValue ——
// 类型集合刻意小：没有自由字符串类型，就没有「顺手把 LLM 输出当参数传」的口子。
type ParamType int

const (
	// ParamTarget 是扫描目标（IP / CIDR / 主机名 / URL）。
	// ScopeChecked 为 true 时渲染前必须经 ScopeService 校验（M1 §4.2 硬约束）。
	ParamTarget ParamType = iota
	// ParamPortRange 是端口或端口范围（如 "80" "1-1024" "80,443"）。
	ParamPortRange
	// ParamEnum 是白名单单选。
	ParamEnum
	// ParamEnumList 是白名单多选，渲染为逗号连接的单个 flag 值。
	ParamEnumList
	// ParamBoolFlag 是布尔开关：true 渲染 flag，false 不渲染。
	ParamBoolFlag
	// ParamPath 是文件系统路径（模板目录、字典文件）。禁止 .. 与元字符。
	ParamPath
)

// ParamDef 定义一个参数。Params 切片的顺序就是渲染顺序（确定性）。
type ParamDef struct {
	Name         string
	Type         ParamType
	Required     bool
	ScopeChecked bool     // true → 渲染前必须经 ScopeService 校验（M1 §4.2）
	Choices      []string // Enum / EnumList 的白名单
	Default      string   // 缺省值；空串 = 缺省不渲染
	Aliases      []string // 常见别名（M1 §4.3 翻车点 3 的缓解）
	ArgFlag      string   // "" = 位置参数（放 argv 最前）；否则 flag 形式（如 "-p"）
}

// ParamSchema 是有序参数集合。
type ParamSchema struct {
	Params []ParamDef
}

// forbiddenChars 是一切参数值都禁止的字符集：
// shell 元字符与控制字符。execve 不经 shell，但这些值可能被下游工具
// 或解析器二次解释（M1 §6 反注入测试的对象）。
const forbiddenChars = ";&|<>`$(){}[]!\\\"'\n\r\t\x1b"

// spaceChars 是禁止的空白（目标/端口/路径都不应含空白）。
const spaceChars = " \t\v\f\x00"

// ArgError 是带契约错误码的适配层错误（05 §1.3 ErrorCode）。
// Service 层据此映射 gRPC status；文案面向开发者，禁止含真实敏感值。
type ArgError struct {
	Code alethv1.ErrorCode
	Msg  string
}

func (e *ArgError) Error() string { return e.Msg }

func argErr(code alethv1.ErrorCode, format string, args ...any) *ArgError {
	return &ArgError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// Validate 校验原始参数并返回规范化的键值（别名归一、缺省补齐）。
// 未知参数显式报错 —— 静默忽略会掩盖「模型用了错误参数名」这一事实（M1 §4.3）。
func (s *ParamSchema) Validate(params map[string]string) (map[string]string, error) {
	byName := make(map[string]*ParamDef, len(s.Params))
	byAlias := make(map[string]string)
	for i := range s.Params {
		def := &s.Params[i]
		if _, dup := byName[def.Name]; dup {
			return nil, argErr(alethv1.ErrorCode_INVALID_ARGUMENT, "duplicate param name %q", def.Name)
		}
		byName[def.Name] = def
		for _, a := range def.Aliases {
			byAlias[a] = def.Name
		}
	}
	normalized := make(map[string]string, len(params))
	used := make(map[string]bool, len(params))
	for k, v := range params { // map 迭代顺序不影响结果：只做归一，渲染时按定义序
		name := k
		if canonical, ok := byAlias[k]; ok {
			name = canonical
		}
		if _, ok := byName[name]; !ok {
			return nil, argErr(alethv1.ErrorCode_INVALID_ARGUMENT,
				"unknown param %q for this tool (see ListAdapters for the schema)", k)
		}
		if _, dup := normalized[name]; dup {
			return nil, argErr(alethv1.ErrorCode_INVALID_ARGUMENT,
				"param %q provided twice (as alias)", name)
		}
		if err := validateValue(byName[name], v); err != nil {
			return nil, err
		}
		normalized[name] = v
		used[k] = true
	}
	for i := range s.Params {
		def := &s.Params[i]
		v, ok := normalized[def.Name]
		switch {
		case ok && v == "":
			return nil, argErr(alethv1.ErrorCode_INVALID_ARGUMENT, "param %q must not be empty", def.Name)
		case ok:
			// 已校验。
		case def.Default != "":
			normalized[def.Name] = def.Default
		case def.Required:
			return nil, argErr(alethv1.ErrorCode_INVALID_ARGUMENT,
				"missing required param %q", def.Name)
		}
	}
	return normalized, nil
}

// RenderArgv 按定义顺序渲染 argv：位置参数在最前，其余按 Params 顺序。
// 值一律作为独立 argv 元素传递（绝不拼接进一个字符串），
// 布尔开关渲染为单个 flag 元素。
func (s *ParamSchema) RenderArgv(params map[string]string) ([]string, error) {
	normalized, err := s.Validate(params)
	if err != nil {
		return nil, err
	}
	argv := make([]string, 0, 2*len(s.Params)+1)
	for i := range s.Params { // 位置参数在前
		def := &s.Params[i]
		if def.ArgFlag == "" {
			if v, ok := normalized[def.Name]; ok {
				argv = append(argv, v)
			}
		}
	}
	for i := range s.Params {
		def := &s.Params[i]
		if def.ArgFlag == "" {
			continue
		}
		v, ok := normalized[def.Name]
		if !ok {
			continue
		}
		if def.Type == ParamBoolFlag {
			if v == "true" {
				argv = append(argv, def.ArgFlag)
			}
			continue
		}
		argv = append(argv, def.ArgFlag, v)
	}
	return argv, nil
}

func validateValue(def *ParamDef, v string) error {
	if strings.ContainsAny(v, forbiddenChars) {
		return argErr(alethv1.ErrorCode_INVALID_ARGUMENT,
			"param %q contains forbidden characters", def.Name)
	}
	if strings.ContainsAny(v, spaceChars) {
		return argErr(alethv1.ErrorCode_INVALID_ARGUMENT, "param %q contains whitespace", def.Name)
	}
	if strings.HasPrefix(v, "-") {
		// 选项注入防线：值一律不允许以 "-" 开头，避免被工具解析为 flag
		//（如把 "-iL /etc/passwd" 塞进 target）。
		return argErr(alethv1.ErrorCode_INVALID_ARGUMENT, "param %q must not start with '-'", def.Name)
	}
	switch def.Type {
	case ParamTarget:
		if !validTarget(v) {
			return argErr(alethv1.ErrorCode_INVALID_ARGUMENT,
				"param %q is not a valid target (IP/CIDR/hostname/URL)", def.Name)
		}
	case ParamPortRange:
		if !validPortRange(v) {
			return argErr(alethv1.ErrorCode_INVALID_ARGUMENT,
				"param %q is not a valid port spec", def.Name)
		}
	case ParamEnum:
		if !contains(def.Choices, v) {
			return argErr(alethv1.ErrorCode_INVALID_ARGUMENT,
				"param %q = %q not in allowed choices", def.Name, v)
		}
	case ParamEnumList:
		for _, item := range strings.Split(v, ",") {
			if !contains(def.Choices, item) {
				return argErr(alethv1.ErrorCode_INVALID_ARGUMENT,
					"param %q item %q not in allowed choices", def.Name, item)
			}
		}
	case ParamPath:
		if strings.Contains(v, "..") || !validPathChars(v) {
			return argErr(alethv1.ErrorCode_INVALID_ARGUMENT, "param %q is not a valid path", def.Name)
		}
	case ParamBoolFlag:
		if v != "true" && v != "false" {
			return argErr(alethv1.ErrorCode_INVALID_ARGUMENT,
				"param %q must be \"true\" or \"false\"", def.Name)
		}
	}
	return nil
}

// validTarget 收紧目标字符集：字母数字与 URL/CIDR 必要标点。
// 这不是目标格式的完整校验（IP 解析交给工具自身），而是注入面控制。
func validTarget(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '-' || c == ':' || c == '/' || c == '_':
		default:
			return false
		}
	}
	return len(s) > 0
}

// validPortRange 只允许数字、逗号、范围连字符（连字符不允许在首尾）。
func validPortRange(s string) bool {
	if len(s) == 0 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c == '-' || c == ',' {
			continue
		}
		return false
	}
	return true
}

func validPathChars(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		// ':' 支持 Windows 盘符（"C:\tools"）与 mmap 风格相对路径。
		case c == '.' || c == '-' || c == '_' || c == '/' || c == '+' || c == '@' || c == ':':
		default:
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// BaseAdapter 用数据定义实现 Adapter 的机械部分；
// 各工具适配器只需提供 Schema、静态 argv 与 Parse 函数。
type BaseAdapter struct {
	ToolName   string
	Versions   VersionRange
	SchemaDef  *ParamSchema
	StaticArgs []string // 渲染在动态参数之前的固定 flag（如 "-oX","-"）
	ParseFn    func(raw []byte, execID string) (*alethv1.EvidenceSpectrum, error)
	Fold       FoldStrategy
}

func (b *BaseAdapter) Name() string                    { return b.ToolName }
func (b *BaseAdapter) SupportedVersions() VersionRange { return b.Versions }
func (b *BaseAdapter) Schema() *ParamSchema            { return b.SchemaDef }
func (b *BaseAdapter) FoldStrategy() FoldStrategy      { return b.Fold }

func (b *BaseAdapter) RenderArgv(params map[string]string) ([]string, error) {
	argv, err := b.SchemaDef.RenderArgv(params)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, 1+len(b.StaticArgs)+len(argv))
	out = append(out, b.ToolName)
	out = append(out, b.StaticArgs...)
	return append(out, argv...), nil
}

func (b *BaseAdapter) Parse(raw []byte, execID string) (*alethv1.EvidenceSpectrum, error) {
	if b.ParseFn == nil {
		return nil, fmt.Errorf("adapter %q has no parse function", b.ToolName)
	}
	return b.ParseFn(raw, execID)
}

// Catalog 是工具适配器注册表（M1 R1：工具白名单 —— 只有显式注册的
// 适配器可被调用，threat-model T2「工具投毒」的第一道防线）。
type Catalog struct {
	byName map[string]Adapter
	names  []string
}

// NewCatalog 注册适配器；重名是装配错误，fail-fast。
func NewCatalog(adapters ...Adapter) (*Catalog, error) {
	c := &Catalog{byName: make(map[string]Adapter, len(adapters))}
	for _, a := range adapters {
		if _, dup := c.byName[a.Name()]; dup {
			return nil, fmt.Errorf("duplicate adapter %q", a.Name())
		}
		c.byName[a.Name()] = a
		c.names = append(c.names, a.Name())
	}
	sort.Strings(c.names)
	return c, nil
}

func (c *Catalog) Get(name string) (Adapter, bool) {
	a, ok := c.byName[name]
	return a, ok
}

// Names 返回字典序适配器名（ListAdapters 的确定性顺序，proto 注释要求）。
func (c *Catalog) Names() []string { return append([]string(nil), c.names...) }
