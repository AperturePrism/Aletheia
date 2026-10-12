package scopekernel

// 授权凭证的**有效期**校验（`docs/08` §1.3、`docs/schemas/roe.schema.json`）。
//
// # 为什么这里需要单独一个文件
//
// `ParseScopeFile` 只解析 `targets` 段（CIDR / host / url_prefix），
// 对应 `05` 的 `Scope` 结构 —— **它看不到 `authorization` 段**。
//
// 而 `roe.schema.json` 明确要求：
//
//	"required": ["granted_by", "granted_to", "contact", "valid_from", "valid_until"]
//	"valid_until" 的描述原文：
//	  "实现须校验 valid_until > valid_from，且跨度不超过 90 天
//	   （超长授权需在 PR 中说明理由）。跨度上限无法在 JSON Schema 内表达，
//	   由 Scope Kernel 强制。"
//
// 也就是说**这份校验被明确指派给 Scope Kernel**，但在本次修复之前
// 代码里搜不到任何 `valid_until` 的使用 —— 一条被指派却从未实现的
// 安全约束。后果：一份**已过期**的授权凭证会被正常接受。
//
// # 为什么这是安全问题
//
// 授权有效期是"这次交战被允许的时间窗"。过期的凭证意味着
// **授权已经失效**，而 `08` §1.1 的第一原则是"无凭证不启动"。
// 接受过期凭证等价于让授权无限续期 —— 那正是该字段要防的事。
//
// 90 天跨度上限同理：它是"一次性授权不应变成长期授权"的约束。

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// MaxAuthorizationSpan 是单次授权的最长跨度（`roe.schema.json` 的
// valid_until 描述原文："跨度不超过 90 天"）。
const MaxAuthorizationSpan = 90 * 24 * time.Hour

// Authorization 是 roe.yaml 的 `authorization` 段（08 §2）。
//
// 只声明**校验需要**的字段，不做完整映射 —— 完整结构由
// `roe.schema.json` 管辖（冻结），这里重复声明全部字段会让
// 两处定义漂移。注释字段（granted_by 等）由 schema 校验必填性，
// 因此不在此处重复校验。
type Authorization struct {
	// ValidFrom 授权生效时刻（RFC 3339）。
	ValidFrom time.Time `yaml:"valid_from"`
	// ValidUntil 授权失效时刻（RFC 3339）。
	ValidUntil time.Time `yaml:"valid_until"`
	// GrantedBy / GrantedTo / Contact / TicketID / DocumentHash
	// 仅用于完整性提示（必填性由 schema 保证）。
	GrantedBy    string `yaml:"granted_by"`
	GrantedTo    string `yaml:"granted_to"`
	Contact      string `yaml:"contact"`
	TicketID     string `yaml:"ticket_id"`
	DocumentHash string `yaml:"document_hash"`
}

// readROEFile 统一读文件（与 parse.go 同一错误措辞，便于排查）。
func readROEFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read roe file: %w", err)
	}
	return raw, nil
}

// authDocYAML 只取校验需要的两段。
type authDocYAML struct {
	Authorization Authorization `yaml:"authorization"`
}

// ParseAuthorizationFile 从 roe.yaml 读取 `authorization` 段。
//
// 与 `ParseScopeFile` 分开：两者关注不同段落，合并会让
// "targets 合法但 authorization 缺失"这类情况难以表达清楚。
func ParseAuthorizationFile(path string) (Authorization, error) {
	raw, err := readROEFile(path)
	if err != nil {
		return Authorization{}, err
	}
	return ParseAuthorization(raw)
}

// ParseAuthorization 从 YAML 字节解析 `authorization` 段。
func ParseAuthorization(raw []byte) (Authorization, error) {
	var d authDocYAML
	if err := yaml.Unmarshal(raw, &d); err != nil {
		return Authorization{}, fmt.Errorf("parse roe yaml: %w", err)
	}
	return d.Authorization, nil
}

// ValidateAuthorizationWindow 校验授权时间窗（08 §1.3 / roe.schema.json）。
//
// 三条判据（全部来自 schema 的 valid_until 描述）：
//
//  1. valid_from 与 valid_until 都必须存在（零值即缺失）
//  2. valid_until > valid_from
//  3. 跨度 ≤ 90 天
//
// `now` 由调用方传入（而非内部取 time.Now）：这让本函数是**纯的**，
// 因此"过期"与"未生效"两种情形都能被确定性测试覆盖，
// 不必靠 sleep 或改系统时钟。
func ValidateAuthorizationWindow(a Authorization, now time.Time) error {
	if a.ValidFrom.IsZero() {
		return fmt.Errorf("authorization.valid_from is required (08 §2；schema 的 required 列表)")
	}
	if a.ValidUntil.IsZero() {
		return fmt.Errorf("authorization.valid_until is required (08 §2；schema 的 required 列表)")
	}
	if !a.ValidUntil.After(a.ValidFrom) {
		return fmt.Errorf(
			"authorization.valid_until (%s) must be after valid_from (%s) —— "+
				"schema 的 valid_until 描述明确要求实现校验这一点",
			a.ValidUntil.Format(time.RFC3339), a.ValidFrom.Format(time.RFC3339))
	}
	if span := a.ValidUntil.Sub(a.ValidFrom); span > MaxAuthorizationSpan {
		return fmt.Errorf(
			"authorization span %s exceeds the %s limit —— "+
				"schema 原文：跨度上限无法在 JSON Schema 内表达，由 Scope Kernel 强制；"+
				"超长授权需在 PR 中说明理由",
			span.Round(time.Hour), MaxAuthorizationSpan)
	}
	if now.Before(a.ValidFrom) {
		return fmt.Errorf(
			"authorization not yet valid: valid_from=%s, now=%s (08 §1.3：拒绝启动)",
			a.ValidFrom.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if now.After(a.ValidUntil) {
		return fmt.Errorf(
			"authorization expired: valid_until=%s, now=%s (08 §1.3：拒绝启动。"+
				"授权有效期是「本次交战被允许的时间窗」—— 接受过期凭证等于让授权无限续期)",
			a.ValidUntil.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return nil
}

// ValidateROEFile 是 daemon 与 CLI 共用的**完整**凭证校验入口。
//
// 一次调用覆盖 `08` §1.3 流程图的全部拒绝情形：
//
//	· 文件不可读
//	· targets 段不合法（无 include 目标 / CIDR 非法 …）
//	· authorization 段时间窗不合法（缺失 / 顺序错 / 超 90 天 / 过期）
//
// `now` 由调用方传入（理由同 ValidateAuthorizationWindow）。
//
// ★ 这是**唯一**的完整校验入口：daemon 与 CLI 都调它。
// 两个入口各写一份必然漂移，而漂移的那一侧就是绕过路径
// （例如"CLI 拦住了过期凭证，但直接启动 daemon 能绕过"）。
func ValidateROEFile(path string, now time.Time) error {
	// 1. targets 段（含"至少一个 include 目标"的 fail-closed 判据）。
	if _, err := ParseScopeFile(path); err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	// 2. authorization 段的时间窗。
	auth, err := ParseAuthorizationFile(path)
	if err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	if err := ValidateAuthorizationWindow(auth, now); err != nil {
		return err
	}
	return nil
}
