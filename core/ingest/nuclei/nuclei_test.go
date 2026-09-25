package nuclei

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
	raw := testutil.Fixture(t, "nuclei", name)
	sp, err := NewAdapter().Parse(raw, "exec_test")
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return sp
}

func TestParseBasic(t *testing.T) {
	sp := parseFixture(t, "v3.2.7-basic.jsonl")
	var defects []*alethv1.EntityDraft
	for _, e := range sp.Entities {
		if e.Kind != alethv1.EntityKind_DEFECT {
			t.Fatalf("unexpected entity kind %v", e.Kind)
		}
		defects = append(defects, e)
		if e.Attributes["defect_type"] == "" || e.Attributes["status"] == "" {
			t.Fatalf("DEFECT missing required fields (05 §3.2): %#v", e.Attributes)
		}
	}
	// 行 1/2 matched → DEFECT；行 3 unmatched → 只保留观测。
	if len(defects) != 2 {
		t.Fatalf("defects = %d, want 2", len(defects))
	}
	if defects[0].Attributes["severity"] != "critical" || defects[0].Attributes["cve"] != "CVE-2021-44228" {
		t.Fatalf("first defect attrs = %#v", defects[0].Attributes)
	}
	if defects[0].Attributes["matched_url"] != "http://scanme.test:8080/" {
		t.Fatalf("matched_url = %q", defects[0].Attributes["matched_url"])
	}
	// unmatched 行保留为观测（无损），状态如实标注。
	// 注意折叠后 vars 值是有序列表（\x1f 连接），按列表项判断。
	var unmatchedFound bool
	for _, ln := range sp.Lines {
		for _, v := range strings.Split(ln.Vars["status"], "\x1f") {
			if v == "unmatched" {
				unmatchedFound = true
			}
		}
	}
	if !unmatchedFound {
		t.Fatal("unmatched observation must be preserved (M1 §2.2 N1: L0 不判定漏洞)")
	}
	// 行 4 截断 → unparsed。
	if sp.Quality.UnparsedLines != 1 {
		t.Fatalf("unparsed = %d, want 1", sp.Quality.UnparsedLines)
	}
	if len(sp.Quality.Warnings) < 1 {
		t.Fatal("unparsed line must produce warning")
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

func TestParseCRLF(t *testing.T) {
	fixture := bytes.ReplaceAll(testutil.Fixture(t, "nuclei", "v3.2.7-basic.jsonl"),
		[]byte("\n"), []byte("\r\n"))
	lf := parseFixture(t, "v3.2.7-basic.jsonl")
	sp, err := NewAdapter().Parse(fixture, "exec_test")
	if err != nil {
		t.Fatalf("CRLF: %v", err)
	}
	if len(sp.Entities) != len(lf.Entities) || len(sp.Lines) != len(lf.Lines) {
		t.Fatalf("CRLF changed structure")
	}
}

func TestParseDeterministic(t *testing.T) {
	raw := testutil.Fixture(t, "nuclei", "v3.2.7-basic.jsonl")
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
		"target": "scanme.test", "severity": "high,critical", "rate_limit": "100",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"nuclei", "-jsonl", "-nc", "-silent", "scanme.test", "-severity", "high,critical", "-rl", "100"}
	if strings.Join(argv, " ") != strings.Join(want, " ") {
		t.Fatalf("argv = %v, want %v", argv, want)
	}
}

func TestSeverityAllowlist(t *testing.T) {
	// 枚举白名单：severity 传入非白名单值必须显式拒绝。
	if _, err := NewAdapter().RenderArgv(map[string]string{"target": "a.test", "severity": "pwned"}); err == nil {
		t.Fatal("severity outside allowlist accepted")
	}
	// templates 是 ParamPath：路径穿越必须拒绝。
	if _, err := NewAdapter().RenderArgv(map[string]string{"target": "a.test", "templates": "../etc"}); err == nil {
		t.Fatal("path traversal accepted")
	}
}
