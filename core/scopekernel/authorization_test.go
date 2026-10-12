package scopekernel

// 授权时间窗校验的测试（`docs/08` §1.3、`docs/schemas/roe.schema.json`）。
//
// # 为什么这组测试重要
//
// `roe.schema.json` 在 `valid_until` 的描述里明确写道：
//
//	"实现须校验 valid_until > valid_from，且跨度不超过 90 天
//	 （超长授权需在 PR 中说明理由）。跨度上限无法在 JSON Schema 内表达，
//	 由 Scope Kernel 强制。"
//
// 也就是说**这份校验被明确指派给 Scope Kernel** —— 但在本次修复之前，
// 全项目搜不到任何 `valid_until` 的使用：一条被指派却从未实现的安全约束。
//
// 后果：一份**已过期**的授权凭证会被正常接受。
// 授权有效期是"本次交战被允许的时间窗"，接受过期凭证等于让授权
// 无限续期 —— 直接违背 `08` §1.1 的"无凭证不启动"。
//
// 本文件的测试用**传入的 now** 做判定（`ValidateAuthorizationWindow`
// 是纯函数），因此三种时间情形都能确定性覆盖，不必 sleep 或改系统时钟。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAuthorizationWindowAcceptsValid(t *testing.T) {
	a := Authorization{
		ValidFrom:  mustParse(t, "2026-01-01T00:00:00Z"),
		ValidUntil: mustParse(t, "2026-03-31T00:00:00Z"), // 89 天
	}
	now := mustParse(t, "2026-02-01T00:00:00Z")
	if err := ValidateAuthorizationWindow(a, now); err != nil {
		t.Fatalf("合法时间窗不应被拒: %v", err)
	}
}

func TestAuthorizationWindowRejectsExpired(t *testing.T) {
	// ★ 本文件存在的核心理由：过期凭证此前**无人校验**。
	a := Authorization{
		ValidFrom:  mustParse(t, "2020-01-01T00:00:00Z"),
		ValidUntil: mustParse(t, "2020-02-01T00:00:00Z"),
	}
	now := mustParse(t, "2026-01-01T00:00:00Z")
	err := ValidateAuthorizationWindow(a, now)
	if err == nil {
		t.Fatal("过期凭证必须被拒绝 —— 否则等于授权无限续期")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("错误应说明已过期：%v", err)
	}
	// 错误必须给出两个时间点，否则用户无法判断该把哪个改到多久。
	if !strings.Contains(err.Error(), "2020-02-01") || !strings.Contains(err.Error(), "2026-01-01") {
		t.Errorf("错误应同时给出 valid_until 与当前时刻：%v", err)
	}
}

func TestAuthorizationWindowRejectsNotYetValid(t *testing.T) {
	a := Authorization{
		ValidFrom:  mustParse(t, "2027-01-01T00:00:00Z"),
		ValidUntil: mustParse(t, "2027-03-01T00:00:00Z"),
	}
	now := mustParse(t, "2026-01-01T00:00:00Z")
	err := ValidateAuthorizationWindow(a, now)
	if err == nil {
		t.Fatal("尚未生效的凭证必须被拒绝")
	}
	if !strings.Contains(err.Error(), "not yet valid") {
		t.Errorf("错误应说明尚未生效：%v", err)
	}
}

func TestAuthorizationWindowRejectsReversedOrder(t *testing.T) {
	// schema 原文要求校验 valid_until > valid_from。
	a := Authorization{
		ValidFrom:  mustParse(t, "2026-03-01T00:00:00Z"),
		ValidUntil: mustParse(t, "2026-01-01T00:00:00Z"),
	}
	err := ValidateAuthorizationWindow(a, mustParse(t, "2026-02-01T00:00:00Z"))
	if err == nil {
		t.Fatal("valid_until 早于 valid_from 必须被拒绝")
	}
	if !strings.Contains(err.Error(), "must be after") {
		t.Errorf("错误应说明顺序要求：%v", err)
	}
}

func TestAuthorizationWindowRejectsEqualTimestamps(t *testing.T) {
	// 相等也不合法：`valid_until > valid_from` 是**严格**不等式。
	// 零长度窗口意味着"从未被授权"。
	same := mustParse(t, "2026-01-01T00:00:00Z")
	a := Authorization{ValidFrom: same, ValidUntil: same}
	if err := ValidateAuthorizationWindow(a, same); err == nil {
		t.Fatal("零长度时间窗必须被拒绝（严格不等式）")
	}
}

func TestAuthorizationWindowRejectsOverlongSpan(t *testing.T) {
	// ★ 90 天上限：schema 说"跨度上限无法在 JSON Schema 内表达，
	// 由 Scope Kernel 强制" —— 本测试就是那份强制。
	a := Authorization{
		ValidFrom:  mustParse(t, "2026-01-01T00:00:00Z"),
		ValidUntil: mustParse(t, "2026-12-31T00:00:00Z"), // 364 天
	}
	err := ValidateAuthorizationWindow(a, mustParse(t, "2026-02-01T00:00:00Z"))
	if err == nil {
		t.Fatal("跨度超过 90 天必须被拒绝")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("错误应说明超限：%v", err)
	}
}

func TestAuthorizationSpanBoundaryIsInclusive(t *testing.T) {
	// 恰好 90 天应**通过**（上限是"不超过 90 天"）。
	from := mustParse(t, "2026-01-01T00:00:00Z")
	a := Authorization{ValidFrom: from, ValidUntil: from.Add(MaxAuthorizationSpan)}
	if err := ValidateAuthorizationWindow(a, from.Add(24*time.Hour)); err != nil {
		t.Fatalf("恰好 90 天应被接受（判据是「不超过」）: %v", err)
	}
	// 超过 1 秒即拒绝。
	b := Authorization{ValidFrom: from, ValidUntil: from.Add(MaxAuthorizationSpan + time.Second)}
	if err := ValidateAuthorizationWindow(b, from.Add(24*time.Hour)); err == nil {
		t.Fatal("超过 90 天 1 秒应被拒绝")
	}
}

func TestAuthorizationWindowRejectsMissingFields(t *testing.T) {
	// schema 把 valid_from / valid_until 放进 required 列表。
	// 零值（缺失）必须被拒绝，而不是被当作"无限制"。
	now := mustParse(t, "2026-02-01T00:00:00Z")

	onlyUntil := Authorization{ValidUntil: mustParse(t, "2026-03-01T00:00:00Z")}
	err := ValidateAuthorizationWindow(onlyUntil, now)
	if err == nil {
		t.Fatal("缺 valid_from 必须被拒绝")
	}
	if !strings.Contains(err.Error(), "valid_from") {
		t.Errorf("错误应指出缺哪个字段：%v", err)
	}

	onlyFrom := Authorization{ValidFrom: mustParse(t, "2026-01-01T00:00:00Z")}
	err = ValidateAuthorizationWindow(onlyFrom, now)
	if err == nil {
		t.Fatal("缺 valid_until 必须被拒绝")
	}
	if !strings.Contains(err.Error(), "valid_until") {
		t.Errorf("错误应指出缺哪个字段：%v", err)
	}
}

// ---- ParseAuthorization ----

func TestParseAuthorizationReadsWindow(t *testing.T) {
	raw := []byte(`
version: 1
authorization:
  granted_by: "T"
  granted_to: "T"
  contact: "a@b.test"
  ticket_id: "T-1"
  document_hash: "sha256:aaaa"
  valid_from: "2026-01-01T00:00:00+00:00"
  valid_until: "2026-03-01T00:00:00+00:00"
targets:
  include:
    - cidr: "192.0.2.0/24"
`)
	a, err := ParseAuthorization(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !a.ValidFrom.Equal(mustParse(t, "2026-01-01T00:00:00Z")) {
		t.Fatalf("valid_from = %v", a.ValidFrom)
	}
	if !a.ValidUntil.Equal(mustParse(t, "2026-03-01T00:00:00Z")) {
		t.Fatalf("valid_until = %v", a.ValidUntil)
	}
}

func TestParseAuthorizationRejectsMalformedYAML(t *testing.T) {
	if _, err := ParseAuthorization([]byte("not: valid: yaml: [")); err == nil {
		t.Fatal("损坏的 YAML 必须报错")
	}
}

// ---- ValidateROEFile（daemon 与 CLI 共用的完整入口）----

func writeROE(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "roe.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateROEFileAcceptsCompliant(t *testing.T) {
	now := mustParse(t, "2026-02-01T00:00:00Z")
	path := writeROE(t, `
version: 1
authorization:
  granted_by: "T"
  granted_to: "T"
  contact: "a@b.test"
  ticket_id: "T-1"
  document_hash: "sha256:aaaa"
  valid_from: "2026-01-01T00:00:00+00:00"
  valid_until: "2026-03-01T00:00:00+00:00"
targets:
  include:
    - cidr: "192.0.2.0/24"
`)
	if err := ValidateROEFile(path, now); err != nil {
		t.Fatalf("合规凭证不应被拒: %v", err)
	}
}

func TestValidateROEFileCatchesExpiredCredential(t *testing.T) {
	// 这是"CLI 与 daemon 共用同一入口"的核心价值：
	// 两处各写一份校验必然漂移，漂移的那侧就是绕过路径。
	path := writeROE(t, `
version: 1
authorization:
  granted_by: "T"
  granted_to: "T"
  contact: "a@b.test"
  ticket_id: "T-1"
  document_hash: "sha256:aaaa"
  valid_from: "2020-01-01T00:00:00+00:00"
  valid_until: "2020-02-01T00:00:00+00:00"
targets:
  include:
    - cidr: "192.0.2.0/24"
`)
	err := ValidateROEFile(path, mustParse(t, "2026-01-01T00:00:00Z"))
	if err == nil {
		t.Fatal("过期凭证必须被拒绝（此前面向 daemon 的路径完全不校验时间窗）")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("错误应说明过期：%v", err)
	}
}

func TestValidateROEFileStillCatchesMissingInclude(t *testing.T) {
	// 完整校验不能因为新增时间窗检查而**丢掉**原有的 targets 校验。
	path := writeROE(t, `
version: 1
authorization:
  granted_by: "T"
  granted_to: "T"
  contact: "a@b.test"
  ticket_id: "T-1"
  document_hash: "sha256:aaaa"
  valid_from: "2026-01-01T00:00:00+00:00"
  valid_until: "2026-03-01T00:00:00+00:00"
targets:
  include: []
`)
	err := ValidateROEFile(path, mustParse(t, "2026-02-01T00:00:00Z"))
	if err == nil {
		t.Fatal("空 include 列表必须被拒绝（默认拒绝策略下等于什么都不允许）")
	}
	if !strings.Contains(err.Error(), "include") {
		t.Errorf("错误应指向 include：%v", err)
	}
}

func TestValidateROEFileReportsMissingFile(t *testing.T) {
	if err := ValidateROEFile("/nonexistent/roe.yaml", time.Now()); err == nil {
		t.Fatal("文件不存在必须报错")
	}
}
