package scopekernel

import (
	"testing"
)

// 本文件是 url_prefix 规则的回归套件。
//
// 背景（缺陷）：I3 的 url_prefix 实现**只保留 host、丢弃 path**，
// 且用裸 strings.HasPrefix 比较 —— 导致
//   · `https://api.example.com/v2/` 连带授权 `/`、`/admin` 等未授权路径；
//   · `api.example.com` 命中 `api.example.com.evil.com`（相似域名越界）。
// 该规则当时全仓库零测试覆盖，因此 Q4「越界 100% fail-closed」在
// 缺一类规则的前提下"全绿"。本套件补齐这一类，并锁死上述两个方向。

func mustParseScope(t *testing.T, yaml string) Scope {
	t.Helper()
	scope, err := ParseScope([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseScope: %v", err)
	}
	return scope
}

// ---- 规则构造：host 与 path 必须都被保留 ----

func TestNewURLPrefixRuleKeepsHostAndPath(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPath string
	}{
		{"https://api.example.com/v2/", "api.example.com", "/v2/"},
		{"https://api.example.com/v2", "api.example.com", "/v2"},
		{"http://api.example.com", "api.example.com", ""},
		{"http://allowed@evil.com/x", "evil.com", "/x"},  // userinfo 不参与
		{"api.example.com/v2", "api.example.com", "/v2"}, // 裸 host+path
		{"api.example.com", "api.example.com", ""},
		{"https://API.Example.COM./V2/", "api.example.com", "/V2/"}, // host 归一化
	}
	for _, c := range cases {
		r, err := NewURLPrefixRule(c.in)
		if err != nil {
			t.Fatalf("NewURLPrefixRule(%q): %v", c.in, err)
		}
		if r.Host != c.wantHost {
			t.Errorf("%q: host = %q, want %q", c.in, r.Host, c.wantHost)
		}
		if r.PathPrefix != c.wantPath {
			t.Errorf("%q: path = %q, want %q", c.in, r.PathPrefix, c.wantPath)
		}
	}
}

// ---- 核心：路径约束必须真正生效（旧实现在此全败）----

func TestURLPrefixEnforcesPathScope(t *testing.T) {
	scope := mustParseScope(t, `
targets:
  include:
    - url_prefix: "https://api.example.com/v2/"
`)
	k := NewKernel(scope, nil, RateLimit{PerMinute: 1000})

	// 授权子树内 → 放行。
	for _, target := range []string{
		"api.example.com/v2/",
		"api.example.com/v2/users",
		"https://api.example.com/v2/users/1",
	} {
		if v := k.Check("s", target); !v.Allowed {
			t.Errorf("%q must be allowed (inside /v2/ subtree): %s", target, v.Reason)
		}
	}

	// 授权子树外 → 拒绝。旧实现把这些**全部放行**（授权绕过）。
	for _, target := range []string{
		"api.example.com",        // 根路径不在 /v2/ 内
		"api.example.com/",       // 同上
		"api.example.com/admin",  // 未授权路径
		"api.example.com/v1/",    // 相邻版本
		"api.example.com/v2evil", // 段边界：/v2/ 不应命中 /v2evil
	} {
		v := k.Check("s", target)
		if v.Allowed {
			t.Errorf("AUTHORIZATION BYPASS: %q must be denied, got allowed (%s)", target, v.Reason)
		}
		if v.FailedBy != "default_deny" {
			t.Errorf("%q: failed_by = %q, want default_deny", target, v.FailedBy)
		}
	}
}

// ---- 核心：相似域名不得命中（裸 HasPrefix 的经典越界）----

func TestURLPrefixRejectsSimilarDomains(t *testing.T) {
	scope := mustParseScope(t, `
targets:
  include:
    - url_prefix: "https://api.example.com/v2/"
`)
	k := NewKernel(scope, nil, RateLimit{PerMinute: 1000})

	// 这些域名**不是** api.example.com，必须拒绝。
	for _, host := range []string{
		"api.example.com.evil.com",
		"api.example.comX",
		"evilapi.example.com",
		"xapi.example.com",
		"api.example.com.evil.com/v2/",
	} {
		if v := k.Check("s", host); v.Allowed {
			t.Errorf("AUTHORIZATION BYPASS: %q must not match the url_prefix rule", host)
		}
	}
}

// ---- exclude 的 url_prefix 只应屏蔽子树，不屏蔽整站 ----

func TestURLPrefixExcludeOnlyBlocksSubtree(t *testing.T) {
	scope := mustParseScope(t, `
targets:
  include:
    - host: "app.example.com"
  exclude:
    - url_prefix: "https://app.example.com/admin/"
`)
	k := NewKernel(scope, nil, RateLimit{PerMinute: 1000})

	for _, target := range []string{"app.example.com", "app.example.com/public"} {
		if v := k.Check("s", target); !v.Allowed {
			t.Errorf("%q must remain allowed: %s", target, v.Reason)
		}
	}
	for _, target := range []string{"app.example.com/admin/", "app.example.com/admin/users"} {
		v := k.Check("s", target)
		if v.Allowed {
			t.Errorf("%q must be excluded", target)
		}
		if v.FailedBy != "exclude" {
			t.Errorf("%q: failed_by = %q, want exclude", target, v.FailedBy)
		}
	}
	// 段边界：/administrator 不是 /admin/ 子树 → 不应被排除。
	if v := k.Check("s", "app.example.com/administrator"); !v.Allowed {
		t.Errorf("path segment boundary violated: /administrator must not match /admin/: %s", v.Reason)
	}
}

// ---- 无路径的 url_prefix 退化为整站（但仍是精确 host）----

func TestURLPrefixWithoutPathMatchesWholeHost(t *testing.T) {
	scope := mustParseScope(t, `
targets:
  include:
    - url_prefix: "https://api.example.com"
`)
	k := NewKernel(scope, nil, RateLimit{PerMinute: 1000})

	if v := k.Check("s", "api.example.com/anything"); !v.Allowed {
		t.Errorf("pathless url_prefix must allow whole host: %s", v.Reason)
	}
	// 但相似域名仍必须拒绝。
	if v := k.Check("s", "api.example.com.evil.com"); v.Allowed {
		t.Error("AUTHORIZATION BYPASS: pathless url_prefix must still match host exactly")
	}
}

// ---- 路径比较不得被编码绕过 ----

func TestURLPrefixPathEncodingNotDecoded(t *testing.T) {
	// %2F 不应被解码为 "/" —— 否则 "/v2%2F..%2Fadmin" 会改变段边界语义。
	scope := mustParseScope(t, `
targets:
  include:
    - url_prefix: "https://api.example.com/v2/"
`)
	k := NewKernel(scope, nil, RateLimit{PerMinute: 1000})
	v := k.Check("s", "https://api.example.com/v2%2F..%2Fadmin")
	// 归一化拒绝或默认拒绝都可接受；**放行**不可接受。
	if v.Allowed {
		t.Errorf("encoded path traversal must not be allowed: %s", v.Reason)
	}
}

// ---- pathHasPrefix 的边界表（纯函数，逐条锁死）----

func TestPathHasPrefixBoundaries(t *testing.T) {
	cases := []struct {
		target, prefix string
		want           bool
	}{
		// 尾斜杠前缀 = 子树语义
		{"/v2/", "/v2/", true},
		{"/v2", "/v2/", true}, // 子树根
		{"/v2/users", "/v2/", true},
		{"/v2evil", "/v2/", false}, // 段边界
		{"/v1/", "/v2/", false},
		{"/", "/v2/", false},
		// 无尾斜杠前缀 = 自身或后代
		{"/v2", "/v2", true},
		{"/v2/users", "/v2", true},
		{"/v2evil", "/v2", false},
		// 空 target 视为根
		{"", "/v2/", false},
		{"", "/", true},
	}
	for _, c := range cases {
		if got := pathHasPrefix(c.target, c.prefix); got != c.want {
			t.Errorf("pathHasPrefix(%q, %q) = %v, want %v", c.target, c.prefix, got, c.want)
		}
	}
}

// ---- 与 host 规则的语义分离 ----

func TestHostRuleUnaffectedByURLPrefixChange(t *testing.T) {
	// host 规则本就要求精确相等，且忽略路径 —— 改动不得影响它。
	scope := mustParseScope(t, `
targets:
  include:
    - host: "app.example.com"
      ports: [80, 443]
`)
	k := NewKernel(scope, nil, RateLimit{PerMinute: 1000})
	if v := k.Check("s", "app.example.com:443"); !v.Allowed {
		t.Errorf("host rule with allowed port must pass: %s", v.Reason)
	}
	if v := k.Check("s", "app.example.com:8080"); v.Allowed {
		t.Error("host rule must still enforce the port list")
	}
	if v := k.Check("s", "app.example.com.evil.com"); v.Allowed {
		t.Error("host rule must not match similar domains")
	}
}
