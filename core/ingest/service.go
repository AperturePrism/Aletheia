package ingest

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"github.com/AperturePrism/aleth/core/spectrum"
)

// ---- 执行前置依赖（M1 §3）----
//
// M1 只消费这些能力，不实现它们（M1 §2.2 N3/N4/N6：范围决策归 ScopeKernel、
// 脱敏归 PrivacyGateway、exec_id 签发归 Sandbox，均在 I3 交付）。
// 接口由消费者定义，真实实现（I3）与测试桩都针对这里的签名编程。

// ScopeChecker 是 ScopeService 的 L0 视角：目标参数校验。
// 实现侧约束（I3）：DENY 必须触发整场会话熔断，不允许「跳过该请求继续」
// （09 §R8）—— L0 侧的义务是把 DENY 显式转为 ErrScopeViolation 向上传播。
type ScopeChecker interface {
	// CheckToolParam 校验目标是否在授权范围内，返回裁决记录 ID（写入审计）。
	CheckToolParam(ctx context.Context, toolName, target string) (decisionID string, err error)
}

// PrivacyGateway 是 GatewayService 的 L0 视角（M1 §3）。
type PrivacyGateway interface {
	// TokenizeParams 把参数中的真实敏感值替换为脱敏 token。失败必须拒绝执行。
	TokenizeParams(ctx context.Context, toolName string, params map[string]string) (map[string]string, error)
	// ScanOutbound 对工具原始输出做出站二次扫描；命中即阻断（05 §6.4）。
	ScanOutbound(ctx context.Context, toolName string, raw []byte) error
}

// SandboxRunner 是 SandboxService 的 L0 视角。
// exec_id 必须由 Sandbox 签发 —— L0 不得自行生成（M1 §2.2 N6、05 §2.1）。
type SandboxRunner interface {
	// Execute 在隔离环境执行 argv，返回签发的 exec_id 与原始 stdout。
	Execute(ctx context.Context, toolName string, argv []string) (execID string, stdout []byte, err error)
}

// sentinel 错误：依赖实现用 errors.Is 报告语义，Service 据此映射契约错误码。
var (
	// ErrScopeViolation 对应 SCOPE_VIOLATION（05 §1.3：熔断整场会话）。
	ErrScopeViolation = errors.New("scope violation: target outside authorized scope")
	// ErrPrivacyLeak 对应 PRIVACY_LEAK_DETECTED（出站含未脱敏敏感值，阻断）。
	ErrPrivacyLeak = errors.New("privacy leak detected in tool output")
)

// Deps 是 Service 的执行依赖。任一为 nil 时，Execute 显式失败
// （UPSTREAM_UNAVAILABLE）—— 绝不允许在缺依赖时「直接执行工具」，
// 那会同时绕过范围校验、脱敏与 exec_id 签发（P3 安全机制绕过）。
type Deps struct {
	Scope   ScopeChecker
	Gateway PrivacyGateway
	Sandbox SandboxRunner

	// Now 返回观测时间（RFC 3339 UTC 落到 proto Timestamp）。
	// 测试注入固定时钟；nil 时用 time.Now。
	Now func() time.Time

	// VersionProbe 检测本机工具版本横幅（如 "Nmap version 7.94"）。
	// nil 时用本文件的 defaultVersionProbe（执行 versionCommands 中的命令）。
	VersionProbe func(ctx context.Context, toolName string) (string, error)
}

// versionCommands 是各工具的版本探测命令。
// key 必须与适配器 Name() 一致 —— 未登记的工具无法做版本门禁，直接拒绝。
var versionCommands = map[string][]string{
	"nmap":   {"nmap", "--version"},
	"httpx":  {"httpx", "-version"},
	"nuclei": {"nuclei", "-version"},
}

func defaultVersionProbe(ctx context.Context, toolName string) (string, error) {
	argv, ok := versionCommands[toolName]
	if !ok {
		return "", fmt.Errorf("no version probe registered for tool %q", toolName)
	}
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
	if err != nil {
		return "", fmt.Errorf("probe %s version: %w", toolName, err)
	}
	return string(out), nil
}

// Service 实现 alethv1.IngestServiceServer（05 §2.2）。
type Service struct {
	alethv1.UnimplementedIngestServiceServer

	catalog *Catalog
	deps    Deps
	store   *RawStore

	// foldOff 是 fold=off 调试开关（M1 §8）：关闭无损折叠，SpectrumLine
	// 逐条对应原始记录。仅用于调试对比，默认关闭。
	foldOff bool
}

// NewService 装配 IngestService。store 用于原始输出的内容寻址存储。
func NewService(catalog *Catalog, deps Deps, store *RawStore) *Service {
	return &Service{catalog: catalog, deps: deps, store: store}
}

// SetFoldOff 打开 fold=off 调试开关（M1 §8）。
func (s *Service) SetFoldOff(v bool) { s.foldOff = v }

// ---- Execute（05 §2.2：范围校验 → 参数渲染 → 沙箱执行 → 解析 → 折叠）----

func (s *Service) Execute(ctx context.Context, req *alethv1.ToolRequest) (*alethv1.EvidenceSpectrum, error) {
	if req == nil {
		return nil, errCode(codes.InvalidArgument, alethv1.ErrorCode_INVALID_ARGUMENT, "empty request")
	}
	adapter, ok := s.catalog.Get(req.GetToolName())
	if !ok {
		return nil, errCode(codes.InvalidArgument, alethv1.ErrorCode_INVALID_ARGUMENT,
			"unknown tool %q; see ListAdapters for the allowlist", req.GetToolName())
	}
	// 参数校验（显式 INVALID_ARGUMENT，禁止静默拒绝 —— M1 §4.3 翻车点 3）。
	normalized, err := adapter.Schema().Validate(req.GetParams())
	if err != nil {
		return nil, toGRPC(err)
	}
	// argv 由参数化 Schema 确定性渲染（09 §R5）。不存在其他渲染路径。
	argv, err := adapter.RenderArgv(req.GetParams())
	if err != nil {
		return nil, toGRPC(err)
	}

	// 步骤 3（05 §7.1）：范围校验。DENY → SCOPE_VIOLATION → 调用方熔断整场会话。
	if s.deps.Scope == nil {
		return nil, errCode(codes.Unavailable, alethv1.ErrorCode_UPSTREAM_UNAVAILABLE,
			"scope checker not wired; refusing to execute (delivered in I3)")
	}
	target := normalized["target"]
	decisionID, err := s.deps.Scope.CheckToolParam(ctx, req.GetToolName(), target)
	if err != nil {
		if errors.Is(err, ErrScopeViolation) {
			return nil, errCode(codes.PermissionDenied, alethv1.ErrorCode_SCOPE_VIOLATION,
				"target outside authorized scope; session must be terminated")
		}
		return nil, errCode(codes.Unavailable, alethv1.ErrorCode_UPSTREAM_UNAVAILABLE,
			"scope check failed: %v", err)
	}

	// 步骤 4：参数脱敏。失败拒绝执行，不降级（M1 §3）。
	if s.deps.Gateway == nil {
		return nil, errCode(codes.Unavailable, alethv1.ErrorCode_UPSTREAM_UNAVAILABLE,
			"privacy gateway not wired; refusing to execute (delivered in I3)")
	}
	if _, err := s.deps.Gateway.TokenizeParams(ctx, req.GetToolName(), normalized); err != nil {
		return nil, errCode(codes.Unavailable, alethv1.ErrorCode_UPSTREAM_UNAVAILABLE,
			"tokenize failed; refusing to execute: %v", err)
	}

	// 版本门禁：版本不在适配器声明区间 → TOOL_VERSION_MISMATCH，fail-closed
	//（04 §I1 风险缓解：不静默降级解析）。
	probe := s.deps.VersionProbe
	if probe == nil {
		probe = defaultVersionProbe
	}
	banner, err := probe(ctx, req.GetToolName())
	if err != nil {
		return nil, errCode(codes.Unavailable, alethv1.ErrorCode_UPSTREAM_UNAVAILABLE,
			"tool version probe failed: %v", err)
	}
	inRange, err := VersionInRange(banner, adapter.SupportedVersions())
	if err != nil {
		return nil, errCode(codes.FailedPrecondition, alethv1.ErrorCode_TOOL_VERSION_MISMATCH,
			"tool version undetectable: %v", err)
	}
	if !inRange {
		return nil, errCode(codes.FailedPrecondition, alethv1.ErrorCode_TOOL_VERSION_MISMATCH,
			"tool %s version outside supported range [%s, %s]",
			req.GetToolName(), adapter.SupportedVersions().Min, adapter.SupportedVersions().Max)
	}
	toolVersion := normalizedVersion(banner)

	// 步骤 5：沙箱执行，取回 exec_id（唯一合法签发者是 Sandbox，05 §6.3）。
	if s.deps.Sandbox == nil {
		return nil, errCode(codes.Unavailable, alethv1.ErrorCode_UPSTREAM_UNAVAILABLE,
			"sandbox not wired; refusing to execute (delivered in I3)")
	}
	execID, stdout, err := s.deps.Sandbox.Execute(ctx, req.GetToolName(), argv)
	if err != nil {
		return nil, errCode(codes.Unavailable, alethv1.ErrorCode_UPSTREAM_UNAVAILABLE,
			"sandbox execute failed: %v", err)
	}
	if execID == "" {
		// Sandbox 返回空 exec_id 是违约：证据不可溯源，必须失败（05 §2.1）。
		return nil, errCode(codes.Internal, alethv1.ErrorCode_EVIDENCE_INVALID,
			"sandbox returned empty exec_id; evidence would be unattributable")
	}

	// 步骤 7：出站二次扫描。有命中 → 阻断，光谱不得离开 L0（M1 §3）。
	if err := s.deps.Gateway.ScanOutbound(ctx, req.GetToolName(), stdout); err != nil {
		if errors.Is(err, ErrPrivacyLeak) {
			return nil, errCode(codes.FailedPrecondition, alethv1.ErrorCode_PRIVACY_LEAK_DETECTED,
				"tool output contains unsanitized sensitive value; blocked")
		}
		return nil, errCode(codes.Unavailable, alethv1.ErrorCode_UPSTREAM_UNAVAILABLE,
			"outbound scan failed: %v", err)
	}

	// 步骤 6（解析）在扫描之后补上时序，但实现顺序无关 —— 解析是纯函数。
	sp, err := adapter.Parse(stdout, execID)
	if err != nil {
		return nil, errCode(codes.FailedPrecondition, alethv1.ErrorCode_EVIDENCE_INVALID,
			"parse failed (fail-closed): %v", err)
	}
	if s.foldOff {
		sp.Lines = spectrum.RecordsToLines(
			spectrum.ExpandFolded(spectrum.LinesToRecords(sp.Lines)))
	}

	// 组装执行上下文：spectrum_id / tool / raw / observed_at。
	sp.SpectrumId = newSpectrumID()
	sp.Tool = &alethv1.ToolInvocation{
		ToolName:        req.GetToolName(),
		ToolVersion:     toolVersion,
		Argv:            argv,
		ArgvHash:        argvHash(argv),
		ScopeDecisionId: decisionID,
	}
	hash, uri, err := s.store.Put(stdout)
	if err != nil {
		return nil, errCode(codes.Unavailable, alethv1.ErrorCode_UPSTREAM_UNAVAILABLE,
			"evidence storage failed: %v", err)
	}
	sp.Raw = &alethv1.RawOutputRef{
		ContentHash: hash,
		StorageUri:  uri,
		SizeBytes:   uint64(len(stdout)),
		LineCount:   uint32(len(spectrum.SplitLines(stdout))),
	}
	now := s.deps.Now
	if now == nil {
		now = time.Now
	}
	sp.ObservedAt = timestamppb.New(now().UTC())
	return sp, nil
}

// ---- ListAdapters（05 §2.2，[derived] 契约：字典序 + offset/limit）----

func (s *Service) ListAdapters(ctx context.Context, req *alethv1.ListAdaptersRequest) (*alethv1.ListAdaptersResponse, error) {
	names := s.catalog.Names()
	offset := int(req.GetOffset())
	limit := int(req.GetLimit())
	if limit == 0 {
		limit = len(names)
	}
	if offset > len(names) {
		offset = len(names)
	}
	end := offset + limit
	if end > len(names) {
		end = len(names)
	}
	resp := &alethv1.ListAdaptersResponse{Total: uint32(len(names))}
	for _, name := range names[offset:end] {
		adapter, _ := s.catalog.Get(name)
		info := &alethv1.ListAdaptersResponse_AdapterInfo{
			ToolName:   name,
			MinVersion: adapter.SupportedVersions().Min,
			MaxVersion: adapter.SupportedVersions().Max,
		}
		for _, def := range adapter.Schema().Params {
			info.ParamNames = append(info.ParamNames, def.Name)
			if def.Required {
				info.RequiredParams = append(info.RequiredParams, def.Name)
			}
		}
		resp.Adapters = append(resp.Adapters, info)
	}
	return resp, nil
}

// ---- ValidateTool（05 §2.2，[derived] 契约：fail-closed 版本门禁）----

func (s *Service) ValidateTool(ctx context.Context, req *alethv1.ValidateToolRequest) (*alethv1.ValidateToolResponse, error) {
	resp := &alethv1.ValidateToolResponse{}
	adapter, ok := s.catalog.Get(req.GetToolName())
	if !ok {
		resp.Error = &alethv1.Error{Code: alethv1.ErrorCode_INVALID_ARGUMENT,
			Message:     fmt.Sprintf("unknown tool %q", req.GetToolName()),
			Remediation: "call ListAdapters for the registered tool allowlist"}
		return resp, nil
	}
	probe := s.deps.VersionProbe
	if probe == nil {
		probe = defaultVersionProbe
	}
	banner, err := probe(ctx, req.GetToolName())
	if err != nil {
		resp.Error = &alethv1.Error{Code: alethv1.ErrorCode_UPSTREAM_UNAVAILABLE,
			Message:     fmt.Sprintf("tool %s unavailable: %v", req.GetToolName(), err),
			Remediation: "install the tool and ensure it is on PATH"}
		return resp, nil
	}
	resp.DetectedVersion = normalizedVersion(banner)
	inRange, err := VersionInRange(banner, adapter.SupportedVersions())
	if err != nil || !inRange {
		resp.VersionMismatch = true
		resp.Error = &alethv1.Error{Code: alethv1.ErrorCode_TOOL_VERSION_MISMATCH,
			Message: fmt.Sprintf("tool %s version %q outside supported range [%s, %s]",
				req.GetToolName(), resp.DetectedVersion,
				adapter.SupportedVersions().Min, adapter.SupportedVersions().Max),
			Remediation: "install a version within the adapter's declared support range"}
		return resp, nil
	}
	resp.Available = true
	return resp, nil
}

// ---- 错误映射 ----

// errCode 构造带契约错误码 detail 的 gRPC 错误（05 §1.3 Error 结构）。
// 文案面向开发者，只含工具名/参数名/错误原因，禁止携带真实目标值。
func errCode(c codes.Code, ec alethv1.ErrorCode, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	st := status.New(c, msg)
	withDetail, err := st.WithDetails(&alethv1.Error{Code: ec, Message: msg})
	if err != nil {
		return st.Err()
	}
	return withDetail.Err()
}

// toGRPC 把适配层 ArgError 映射为 gRPC 错误。
func toGRPC(err error) error {
	var ae *ArgError
	if !errors.As(err, &ae) {
		return errCode(codes.Internal, alethv1.ErrorCode_ERROR_CODE_UNSPECIFIED, "internal error: %v", err)
	}
	return errCode(codes.InvalidArgument, ae.Code, "%s", ae.Msg)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// normalizedVersion 从版本横幅提取规范化版本串（"MAJOR.MINOR.PATCH"）。
// ToolInvocation.tool_version 与 ValidateTool.detected_version 都用它，
// 消费方拿到的是可比较的版本号，而不是整行横幅。
func normalizedVersion(banner string) string {
	v, err := ParseVersion(banner)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}
