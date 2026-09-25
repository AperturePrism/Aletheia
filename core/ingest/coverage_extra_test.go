package ingest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"github.com/AperturePrism/aleth/core/spectrum"
)

func TestValidateValuePathType(t *testing.T) {
	def := &ParamDef{Name: "templates", Type: ParamPath, ArgFlag: "-t"}
	valid := []string{"/usr/share/nuclei-templates", "tpl/custom_v2.yaml", "C:/tools/tpl"}
	for _, v := range valid {
		if err := validateValue(def, v); err != nil {
			t.Fatalf("valid path %q rejected: %v", v, err)
		}
	}
	invalid := []string{"../escape", "..\\.\\escape", "a b.yaml", "-flag", "tpl\ninject", "", "a;b"}
	for _, v := range invalid {
		if err := validateValue(def, v); err == nil {
			t.Fatalf("invalid path %q accepted", v)
		}
	}
}

func TestValidateValueBool(t *testing.T) {
	def := &ParamDef{Name: "flag", Type: ParamBoolFlag, ArgFlag: "-f"}
	if err := validateValue(def, "true"); err != nil {
		t.Fatal(err)
	}
	if err := validateValue(def, "yes"); err == nil {
		t.Fatal("non-literal bool accepted")
	}
}

func TestValidateValueForbiddenChars(t *testing.T) {
	def := &ParamDef{Name: "target", Type: ParamTarget}
	for _, v := range []string{"a\x00b", "a$b", "a(b)", "a[b]", "a{b}", "a!b", `a\b`, "a\"b", "a'b"} {
		if err := validateValue(def, v); err == nil {
			t.Fatalf("hostile value %q accepted", v)
		}
	}
}

func TestBaseAdapterParseWithoutParseFn(t *testing.T) {
	b := &BaseAdapter{ToolName: "x", SchemaDef: &ParamSchema{}}
	if _, err := b.Parse(nil, "exec_1"); err == nil {
		t.Fatal("adapter without ParseFn must fail explicitly")
	}
}

func TestArgErrorMessage(t *testing.T) {
	e := argErr(alethv1.ErrorCode_INVALID_ARGUMENT, "bad param %q", "x")
	if e.Error() != `bad param "x"` {
		t.Fatalf("ArgError.Error() = %q", e.Error())
	}
}

func TestVersionHelpers(t *testing.T) {
	// atoi 的空串与多位数分支。
	for s, want := range map[string]int{"": 0, "0": 0, "007": 7, "1234": 1234} {
		if got := atoi(s); got != want {
			t.Fatalf("atoi(%q) = %d, want %d", s, got, want)
		}
	}
	// compareVersion / sign 的三个分支经 VersionInRange 间接覆盖，
	// 这里直接锁语义。
	if compareVersion(Version{1, 2, 3}, Version{1, 2, 4}) >= 0 {
		t.Fatal("patch compare broken")
	}
}

func TestLineStartTableAndLineAt(t *testing.T) {
	b := []byte("line1\nline2\n\nline4")
	table := LineStartTable(b) // 行首偏移：0, 6, 12, 13
	if len(table) != 4 {
		t.Fatalf("table = %v", table)
	}
	cases := []struct {
		off  int64
		want uint32
	}{
		{0, 1}, {5, 1}, {6, 2}, {11, 2}, {12, 3}, {13, 4}, {18, 4},
	}
	for _, tc := range cases {
		if got := LineAt(table, tc.off); got != tc.want {
			t.Fatalf("LineAt(%d) = %d, want %d", tc.off, got, tc.want)
		}
	}
}

func TestQuality(t *testing.T) {
	q := Quality(10, 2, []string{"w"})
	if q.Coverage != 0.8 || q.UnparsedLines != 2 || len(q.Warnings) != 1 {
		t.Fatalf("quality = %#v", q)
	}
	if got := Quality(0, 0, nil).Coverage; got != 1.0 {
		t.Fatalf("empty coverage = %v, want 1.0", got)
	}
}

func TestRawRecordPreservesLine(t *testing.T) {
	r := RawRecord(7, "garbage output")
	if r.OrigLineStart != 7 || r.OrigLineEnd != 7 || r.FoldCount != 1 || !strings.HasPrefix(r.Template, "raw garbage") {
		t.Fatalf("raw record = %#v", r)
	}
}

func TestRawStoreIdempotent(t *testing.T) {
	dir := t.TempDir()
	store, err := NewRawStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("same bytes")
	h1, u1, err := store.Put(content)
	if err != nil {
		t.Fatal(err)
	}
	// 相同内容幂等：命中已有 blob，哈希一致（内容寻址）。
	h2, u2, err := store.Put(content)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 || u1 != u2 {
		t.Fatalf("put not idempotent: %s/%s vs %s/%s", h1, u1, h2, u2)
	}
	if len(h1) != 64 {
		t.Fatalf("hash length = %d, want sha256 hex (64)", len(h1))
	}
	// blob 真实落盘且可读回。
	back, err := os.ReadFile(u1)
	if err != nil || string(back) != string(content) {
		t.Fatalf("blob roundtrip: %v", err)
	}
}

func TestArgvHashDistinguishesElementBoundary(t *testing.T) {
	a := argvHash([]string{"ab", "c"})
	b := argvHash([]string{"a", "bc"})
	if a == b {
		t.Fatal("argv hash must distinguish element boundaries")
	}
}

func TestDefaultVersionProbeUnknownTool(t *testing.T) {
	if _, err := defaultVersionProbe(context.Background(), "totally-unknown-tool"); err == nil {
		t.Fatal("unregistered probe must fail explicitly")
	}
}

func TestToGRPNonArgError(t *testing.T) {
	err := toGRPC(errors.New("plain failure"))
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Internal {
		t.Fatalf("plain error mapping: %v", err)
	}
}

func TestFirstLine(t *testing.T) {
	if firstLine("a\nb") != "a" || firstLine("abc") != "abc" {
		t.Fatal("firstLine broken")
	}
}

func TestNormalizedVersion(t *testing.T) {
	if got := normalizedVersion("Nmap version 7.94 (build)"); got != "7.94.0" {
		t.Fatalf("normalized = %q", got)
	}
	if got := normalizedVersion("no version"); got != "" {
		t.Fatalf("normalized = %q, want empty", got)
	}
}

// ---- spectrum 补充（LinesToRecords / span 边界）----

func TestLinesToRecords(t *testing.T) {
	lines := []*alethv1.SpectrumLine{
		{OrigLineStart: 1, OrigLineEnd: 1, FoldCount: 1, Template: "a", Vars: map[string]string{"x": "1"}},
		nil, // nil 元素安全跳过
	}
	recs := spectrum.LinesToRecords(lines)
	if len(recs) != 1 || recs[0].Template != "a" || recs[0].FoldCount != 1 {
		t.Fatalf("records = %#v", recs)
	}
}

func TestNewRawStoreRejectsFileAsDir(t *testing.T) {
	// 以文件路径充当目录 → MkdirAll 失败 → 显式拒绝建 store。
	dir := t.TempDir()
	fileAsDir := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRawStore(fileAsDir); err == nil {
		t.Fatal("file path must not be accepted as store dir (fail-closed)")
	}
}

func TestFoldStrategyExposure(t *testing.T) {
	// M1 §4.1 接口的 FoldStrategy 方法经 BaseAdapter 暴露。
	a := &BaseAdapter{ToolName: "x", Fold: FoldStrategy{MaxFoldGroup: 10}}
	if a.FoldStrategy().MaxFoldGroup != 10 {
		t.Fatal("fold strategy not round-tripped")
	}
}
