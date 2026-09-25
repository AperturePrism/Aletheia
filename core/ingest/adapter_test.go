package ingest

import (
	"reflect"
	"testing"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want Version
		fail bool
	}{
		{"Nmap version 7.94", Version{7, 94, 0}, false},
		{"httpx v1.6.0", Version{1, 6, 0}, false},
		{"nuclei 3.2.7 (runtime)", Version{3, 2, 7}, false},
		{"7.94", Version{7, 94, 0}, false},
		{"no digits here", Version{}, true},
		{"", Version{}, true},
	}
	for _, tc := range cases {
		got, err := ParseVersion(tc.in)
		if tc.fail {
			if err == nil {
				t.Fatalf("ParseVersion(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseVersion(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseVersion(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestVersionInRange(t *testing.T) {
	r := VersionRange{Min: "7.80", Max: "7.99"}
	in, err := VersionInRange("Nmap version 7.94", r)
	if err != nil || !in {
		t.Fatalf("7.94 in [7.80,7.99] = %v, %v", in, err)
	}
	if in, _ = VersionInRange("7.79", r); in {
		t.Fatal("7.79 must be below range")
	}
	if in, _ = VersionInRange("8.0", r); in {
		t.Fatal("8.0 must be above range")
	}
	// 端点含入。
	if in, _ = VersionInRange("7.80", r); !in {
		t.Fatal("min endpoint must be inclusive")
	}
	// 区间端点本身不是版本 → fail-closed 返回错误。
	if _, err := VersionInRange("7.94", VersionRange{Min: "abc", Max: "7.99"}); err == nil {
		t.Fatal("bad range bound must error")
	}
	// 版本探测失败 → 错误而非误判。
	if _, err := VersionInRange("unknown", r); err == nil {
		t.Fatal("undetectable version must error")
	}
}

func testSchema() *ParamSchema {
	return &ParamSchema{
		Params: []ParamDef{
			{Name: "target", Type: ParamTarget, Required: true, ScopeChecked: true, Aliases: []string{"host", "url"}},
			{Name: "ports", Type: ParamPortRange, ArgFlag: "-p"},
			{Name: "timing", Type: ParamEnum, Choices: []string{"T2", "T3", "T4"}, ArgFlag: "-T"},
			{Name: "scripts", Type: ParamEnumList, Choices: []string{"default", "http-title"}, ArgFlag: "--script"},
			{Name: "verbose", Type: ParamBoolFlag, ArgFlag: "-v"},
			{Name: "wordlist", Type: ParamPath, ArgFlag: "-w", Default: "/usr/share/wordlists/common.txt"},
		},
	}
}

func TestSchemaValidate(t *testing.T) {
	s := testSchema()
	t.Run("unknown param rejected explicitly", func(t *testing.T) {
		_, err := s.Validate(map[string]string{"query": "x"})
		argErr, ok := err.(*ArgError)
		if !ok || argErr.Code != alethv1.ErrorCode_INVALID_ARGUMENT {
			t.Fatalf("want INVALID_ARGUMENT ArgError, got %#v", err)
		}
	})
	t.Run("alias resolves", func(t *testing.T) {
		got, err := s.Validate(map[string]string{"host": "192.0.2.1"})
		if err != nil {
			t.Fatal(err)
		}
		if got["target"] != "192.0.2.1" {
			t.Fatalf("alias not normalized: %#v", got)
		}
	})
	t.Run("missing required", func(t *testing.T) {
		_, err := s.Validate(nil)
		if err == nil {
			t.Fatal("want error for missing required target")
		}
	})
	t.Run("default filled when absent", func(t *testing.T) {
		got, err := s.Validate(map[string]string{"target": "192.0.2.1"})
		if err != nil {
			t.Fatal(err)
		}
		if got["wordlist"] != "/usr/share/wordlists/common.txt" {
			t.Fatalf("default not applied: %#v", got)
		}
	})
	t.Run("duplicate via alias", func(t *testing.T) {
		_, err := s.Validate(map[string]string{"target": "a.test", "host": "b.test"})
		if err == nil {
			t.Fatal("want error for param provided twice")
		}
	})
	t.Run("empty value", func(t *testing.T) {
		_, err := s.Validate(map[string]string{"target": "a.test", "ports": ""})
		if err == nil {
			t.Fatal("want error for empty value")
		}
	})
}

func TestSchemaRenderArgv(t *testing.T) {
	s := testSchema()
	a, err := s.RenderArgv(map[string]string{
		"host": "192.0.2.1", "verbose": "true", "timing": "T3",
	})
	if err != nil {
		t.Fatal(err)
	}
	// map 迭代顺序无关：渲染按 Schema 定义顺序（M1 §4.5）。
	// wordlist 缺省值生效；ports 未提供且无默认 → 不渲染。
	want := []string{"192.0.2.1", "-T", "T3", "-v", "-w", "/usr/share/wordlists/common.txt"}
	if !reflect.DeepEqual(a, want) {
		t.Fatalf("argv = %v, want %v", a, want)
	}
	b, err := s.RenderArgv(map[string]string{"url": "192.0.2.1", "verbose": "false", "timing": "T3"})
	if err != nil {
		t.Fatal(err)
	}
	wantB := []string{"192.0.2.1", "-T", "T3", "-w", "/usr/share/wordlists/common.txt"}
	if !reflect.DeepEqual(b, wantB) {
		t.Fatalf("argv = %v, want %v (false bool must not render)", b, wantB)
	}
}

func TestValidateValueInjection(t *testing.T) {
	// M1 §6 反注入：参数值含 shell 元字符时，渲染必须拒绝而非传递。
	s := testSchema()
	hostile := []string{
		"192.0.2.1;id", "192.0.2.1|id", "192.0.2.1&whoami", "$(id)",
		"`id`", "a b", "192.0.2.1\n80", "-iL/etc/passwd", "192.0.2.1\x1b[31m",
	}
	for _, h := range hostile {
		if _, err := s.RenderArgv(map[string]string{"target": h}); err == nil {
			t.Fatalf("hostile target %q accepted", h)
		}
	}
	if _, err := s.RenderArgv(map[string]string{"target": "192.0.2.1", "ports": "80;443"}); err == nil {
		t.Fatal("semicolon in port spec accepted")
	}
	if _, err := s.RenderArgv(map[string]string{"target": "192.0.2.1", "wordlist": "../../etc/passwd"}); err == nil {
		t.Fatal("path traversal accepted")
	}
	if _, err := s.RenderArgv(map[string]string{"target": "192.0.2.1", "timing": "T1"}); err == nil {
		t.Fatal("enum value outside allowlist accepted")
	}
}

func TestCatalog(t *testing.T) {
	mk := func(name string) Adapter {
		return &BaseAdapter{
			ToolName: name,
			SchemaDef: &ParamSchema{Params: []ParamDef{
				{Name: "target", Type: ParamTarget, Required: true},
			}},
		}
	}
	c, err := NewCatalog(mk("nmap"), mk("httpx"), mk("nuclei"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Names(); !reflect.DeepEqual(got, []string{"httpx", "nmap", "nuclei"}) {
		t.Fatalf("Names = %v, want dictionary order", got)
	}
	if a, ok := c.Get("nmap"); !ok || a.Name() != "nmap" {
		t.Fatal("Get(nmap) failed")
	}
	if _, ok := c.Get("masscan"); ok {
		t.Fatal("unregistered tool must not be found (T2 tool allowlist)")
	}
	if _, err := NewCatalog(mk("nmap"), mk("nmap")); err == nil {
		t.Fatal("duplicate adapter must fail fast")
	}
}
