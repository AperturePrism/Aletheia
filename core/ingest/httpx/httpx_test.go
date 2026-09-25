package httpx

import (
	"bytes"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"github.com/AperturePrism/aleth/core/ingest/testutil"
)

func parseFixture(t *testing.T, name string) *alethv1.EvidenceSpectrum {
	t.Helper()
	raw := testutil.Fixture(t, "httpx", name)
	raw = bytes.ReplaceAll(raw, []byte("@ESC@"), []byte("\x1b")) // 单个 ESC 字节
	sp, err := NewAdapter().Parse(raw, "exec_test")
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return sp
}

func TestParseBasic(t *testing.T) {
	sp := parseFixture(t, "v1.6.0-basic.jsonl")
	var endpoints, assets int
	for _, e := range sp.Entities {
		switch e.Kind {
		case alethv1.EntityKind_ENDPOINT:
			endpoints++
			if e.Attributes["url"] == "" || e.Attributes["method"] == "" {
				t.Fatalf("endpoint missing required draft fields: %#v", e.Attributes)
			}
		case alethv1.EntityKind_ASSET:
			assets++
		}
	}
	// 行 1/2/4 是有效 endpoint（行 3 failed、行 5 坏行）。
	if endpoints != 3 {
		t.Fatalf("endpoints = %d, want 3", endpoints)
	}
	if assets != 2 {
		t.Fatalf("assets = %d, want 2 (A records on lines 1/2)", assets)
	}
	// 坏行显式计数 + 保留为 raw 记录，禁止静默丢弃（M1 §4.3）。
	if sp.Quality.UnparsedLines != 1 {
		t.Fatalf("unparsed = %d, want 1", sp.Quality.UnparsedLines)
	}
	if len(sp.Quality.Warnings) < 1 {
		t.Fatalf("warnings = %#v, want >= 1 for unparsed lines", sp.Quality.Warnings)
	}
	// coverage = (5-1)/5 = 0.8。
	if sp.Quality.Coverage < 0.79 || sp.Quality.Coverage > 0.81 {
		t.Fatalf("coverage = %v, want 4/5", sp.Quality.Coverage)
	}
	rawRecords := 0
	for _, ln := range sp.Lines {
		if strings.HasPrefix(ln.Template, "raw ") {
			rawRecords += int(ln.FoldCount)
		}
	}
	if rawRecords != 1 {
		t.Fatalf("raw records = %d, want 1 (lossless)", rawRecords)
	}
}

func TestParseMethodDefault(t *testing.T) {
	// 行 4 缺 method 字段 → 显式默认 GET + warning + 置信度 0.8。
	sp := parseFixture(t, "v1.6.0-basic.jsonl")
	var last *alethv1.EntityDraft
	for _, e := range sp.Entities {
		if e.Kind == alethv1.EntityKind_ENDPOINT {
			last = e
		}
	}
	if last == nil || last.Attributes["method"] != "GET" || last.ParserConfidence != 0.8 {
		t.Fatalf("method default not applied: %#v", last)
	}
	found := false
	for _, w := range sp.Quality.Warnings {
		if strings.Contains(w, "defaulted to GET") {
			found = true
		}
	}
	if !found {
		t.Fatal("method default must be recorded as warning")
	}
}

func TestParseANSIInTitle(t *testing.T) {
	// 行 4 的 title 含原始 ESC 字节：清洗后该行必须可解析为合法 JSON。
	// unparsed 恰为 1（仅行 5）→ ANSI 行解析成功；若清洗失效它会变成第 2 行 unparsed。
	sp := parseFixture(t, "v1.6.0-basic.jsonl")
	if sp.Quality.UnparsedLines != 1 {
		t.Fatalf("ANSI line must parse after cleaning; unparsed = %d", sp.Quality.UnparsedLines)
	}
}

func TestParseEmpty(t *testing.T) {
	sp, err := NewAdapter().Parse(nil, "exec_test")
	if err != nil {
		t.Fatalf("empty output: %v", err)
	}
	if len(sp.Entities) != 0 || len(sp.Lines) != 0 || sp.Quality.Coverage != 1.0 {
		t.Fatalf("empty output: %#v", sp)
	}
}

func TestParseTruncatedTail(t *testing.T) {
	// 截断输出（M1 §6）：尾行 JSON 不完整 → 该行 unparsed，其余行不受影响。
	raw := []byte(`{"url":"http://a.test","method":"GET","failed":false,"status_code":200}
{"url":"http://b.te`)
	sp, err := NewAdapter().Parse(raw, "exec_test")
	if err != nil {
		t.Fatalf("truncated JSONL must not fail closed: %v", err)
	}
	if sp.Quality.UnparsedLines != 1 {
		t.Fatalf("unparsed = %d, want 1", sp.Quality.UnparsedLines)
	}
	if len(sp.Entities) != 1 {
		t.Fatalf("entities = %d, want 1 (first line intact)", len(sp.Entities))
	}
}

func TestParseCRLF(t *testing.T) {
	fixture := bytes.ReplaceAll(testutil.Fixture(t, "httpx", "v1.6.0-basic.jsonl"),
		[]byte("\n"), []byte("\r\n"))
	fixture = bytes.ReplaceAll(fixture, []byte("@ESC@"), []byte("\x1b"))
	lf := parseFixture(t, "v1.6.0-basic.jsonl")
	sp, err := NewAdapter().Parse(fixture, "exec_test")
	if err != nil {
		t.Fatalf("CRLF: %v", err)
	}
	if len(sp.Entities) != len(lf.Entities) || len(sp.Lines) != len(lf.Lines) {
		t.Fatalf("CRLF changed structure")
	}
}

func TestParseDeterministic(t *testing.T) {
	raw := bytes.ReplaceAll(testutil.Fixture(t, "httpx", "v1.6.0-basic.jsonl"),
		[]byte("@ESC@"), []byte("\x1b"))
	marshal := proto.MarshalOptions{Deterministic: true}
	var want []byte
	for run := 0; run < 3; run++ {
		sp, err := NewAdapter().Parse(raw, "exec_fixed")
		if err != nil {
			t.Fatal(err)
		}
		b, err := marshal.Marshal(sp)
		if err != nil {
			t.Fatal(err)
		}
		if want == nil {
			want = b
			continue
		}
		if !bytes.Equal(want, b) {
			t.Fatalf("run %d differs (determinism violated)", run)
		}
	}
}

func TestRenderArgv(t *testing.T) {
	argv, err := NewAdapter().RenderArgv(map[string]string{
		"url": "scanme.test", "ports": "80,443", "tech_detect": "true",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"httpx", "-json", "-silent", "-no-color", "scanme.test", "-p", "80,443", "-td"}
	if len(argv) != len(want) {
		t.Fatalf("argv = %v, want %v", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv = %v, want %v", argv, want)
		}
	}
}

func TestUnknownParam(t *testing.T) {
	if _, err := NewAdapter().RenderArgv(map[string]string{"query": "x", "url": "a.test"}); err == nil {
		t.Fatal("unknown param must be rejected explicitly (M1 §4.3 翻车点 3)")
	}
}
