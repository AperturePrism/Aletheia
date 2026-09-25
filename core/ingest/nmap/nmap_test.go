package nmap

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"github.com/AperturePrism/aleth/core/ingest/testutil"
)

func parseFixture(t *testing.T, name string) *alethv1.EvidenceSpectrum {
	t.Helper()
	raw := testutil.Fixture(t, "nmap", name)
	sp, err := NewAdapter().Parse(raw, "exec_test")
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return sp
}

func TestParseBasic(t *testing.T) {
	sp := parseFixture(t, "v7.94-basic.xml")

	// 实体草稿：2 个 ASSET + 4 个 SERVICE（192.0.2.10: 3 端口；192.0.2.11: 1 端口）。
	var assets, services []*alethv1.EntityDraft
	for _, e := range sp.Entities {
		switch e.Kind {
		case alethv1.EntityKind_ASSET:
			assets = append(assets, e)
		case alethv1.EntityKind_SERVICE:
			services = append(services, e)
		default:
			t.Fatalf("unexpected entity kind %v", e.Kind)
		}
	}
	if len(assets) != 2 || len(services) != 4 {
		t.Fatalf("entities: %d assets, %d services; want 2/4", len(assets), len(services))
	}
	if assets[0].Attributes["addr"] != "192.0.2.10" {
		t.Fatalf("asset addr = %q", assets[0].Attributes["addr"])
	}
	if assets[0].SourceLine == 0 {
		t.Fatal("asset source_line must point at the original output line (05 §2.1)")
	}
	// 服务字段抽取：nginx 版本。
	ssh := services[3]
	if ssh.Attributes["product"] != "OpenSSH" || ssh.Attributes["version"] != "9.6p1" {
		t.Fatalf("ssh service attrs = %#v", ssh.Attributes)
	}
	if ssh.Attributes["host_addr"] != "192.0.2.11" {
		t.Fatalf("service host_addr = %q", ssh.Attributes["host_addr"])
	}
	if ssh.ParserConfidence != 1.0 {
		t.Fatalf("full-parse confidence = %v, want 1.0", ssh.ParserConfidence)
	}

	// 行记录：host 行 + port 行 = 6 条；折叠后允许更少，但 fold_count 总和不变。
	total := uint32(0)
	for _, ln := range sp.Lines {
		total += ln.FoldCount
	}
	if total < 6 {
		t.Fatalf("fold_count total = %d, want >= 6 (lossless)", total)
	}

	// 解析质量：XML 有效 → 全覆盖。
	if sp.Quality.Coverage != 1.0 || sp.Quality.UnparsedLines != 0 {
		t.Fatalf("quality = %#v, want coverage 1.0 unparsed 0", sp.Quality)
	}
}

func TestParseVersionTrap(t *testing.T) {
	// M1 §4.3 翻车点 1：rpcbind 的 "2 (RPC #100000)" 不得作为版本采信。
	sp := parseFixture(t, "v7.94-basic.xml")
	var trapHit bool
	for _, e := range sp.Entities {
		if e.Kind == alethv1.EntityKind_SERVICE && e.Attributes["service_name"] == "rpcbind" {
			trapHit = true
			if e.Attributes["version"] != "" {
				t.Fatalf("rpc program number leaked as version: %q", e.Attributes["version"])
			}
			if e.ParserConfidence != 0.5 {
				t.Fatalf("trap-hit confidence = %v, want 0.5", e.ParserConfidence)
			}
		}
	}
	if !trapHit {
		t.Fatal("rpcbind service draft not found")
	}
	found := false
	for _, w := range sp.Quality.Warnings {
		if strings.Contains(w, "leading-number version trap") {
			found = true
		}
	}
	if !found {
		t.Fatal("trap warning not recorded (must not be silent)")
	}
}

func TestParseANSI(t *testing.T) {
	// M1 §4.3 翻车点 2：原始 ESC 字节必须在解析前被移除，
	// 否则 XML 解析会直接失败（ESC 对 XML 1.0 非法）。
	// fixture 中 @ESC@ 代表单个 ESC 字节（0x1B）。
	raw := bytes.ReplaceAll(testutil.Fixture(t, "nmap", "v7.94-ansi.xml"), []byte("@ESC@"), []byte("\x1b"))
	sp, err := NewAdapter().Parse(raw, "exec_test")
	if err != nil {
		t.Fatalf("ANSI-polluted XML must parse after cleaning: %v", err)
	}
	for _, e := range sp.Entities {
		if e.Kind == alethv1.EntityKind_SERVICE {
			if got := e.Attributes["service_name"]; got != "http" {
				t.Fatalf("service_name after strip = %q, want %q", got, "http")
			}
		}
	}
}

func TestParseBrokenXMLFailClosed(t *testing.T) {
	// 截断输出（M1 §6 边界用例）：XML 破损必须整体失败，不允许半份结果。
	raw := []byte(`<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.0.2.9"`)
	if _, err := NewAdapter().Parse(raw, "exec_test"); err == nil {
		t.Fatal("truncated XML must fail closed")
	}
}

func TestParseEmpty(t *testing.T) {
	// 空输出（M1 §6 边界用例）：合法观测，0 实体、无告警、coverage=1。
	sp, err := NewAdapter().Parse(nil, "exec_test")
	if err != nil {
		t.Fatalf("empty output: %v", err)
	}
	if len(sp.Entities) != 0 || len(sp.Lines) != 0 {
		t.Fatalf("empty output produced entities/lines: %#v", sp)
	}
	if sp.Quality.Coverage != 1.0 {
		t.Fatalf("empty coverage = %v, want 1.0", sp.Quality.Coverage)
	}
}

func TestParseCRLF(t *testing.T) {
	// CRLF/LF 混用（M1 §6 边界用例）：行号在两种行尾下一致。
	lf := parseFixture(t, "v7.94-basic.xml")
	crlf := bytes.ReplaceAll(testutil.Fixture(t, "nmap", "v7.94-basic.xml"), []byte("\n"), []byte("\r\n"))
	sp, err := NewAdapter().Parse(crlf, "exec_test")
	if err != nil {
		t.Fatalf("CRLF input: %v", err)
	}
	if len(sp.Lines) != len(lf.Lines) || len(sp.Entities) != len(lf.Entities) {
		t.Fatalf("CRLF changed structure: %d lines vs %d", len(sp.Lines), len(lf.Lines))
	}
	for i := range sp.Entities {
		if sp.Entities[i].SourceLine != lf.Entities[i].SourceLine {
			t.Fatalf("entity %d source_line changed with line endings: %d vs %d",
				i, sp.Entities[i].SourceLine, lf.Entities[i].SourceLine)
		}
	}
}

func TestParseDeterministic(t *testing.T) {
	// Q6：相同输入多次运行，光谱（除执行上下文字段）字节级一致。
	// 注意：go/protobuf 对 map 字段的默认序列化顺序是故意随机化的，
	// Q6 验证必须使用 MarshalOptions.Deterministic（按键排序）——
	// 否则会把序列化器的随机性误判为解析器的非确定性。
	raw := testutil.Fixture(t, "nmap", "v7.94-basic.xml")
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
		"host": "192.0.2.10", "ports": "80,443", "timing": "T4",
		"scripts": "http-title,default", "service_detection": "true", "no_ping": "false",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"nmap", "-oX", "-",
		"192.0.2.10", "-p", "80,443", "-T", "T4",
		"--script", "http-title,default", "-sV",
	}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv = %v, want %v", argv, want)
	}
}

func TestSchemaParamNameMismatch(t *testing.T) {
	// M1 §4.3 翻车点 3：参数名不匹配必须显式报错，且别名可被归一。
	if _, err := NewAdapter().RenderArgv(map[string]string{"query": "192.0.2.1"}); err == nil {
		t.Fatal("unknown param must be rejected explicitly")
	}
	if _, err := NewAdapter().RenderArgv(map[string]string{"sV": "true", "host": "192.0.2.1"}); err != nil {
		t.Fatalf("alias must resolve: %v", err)
	}
}

func TestParseMissingStateDefaults(t *testing.T) {
	// status/state 缺省 → Record 里如实记 unknown（orDefault 分支）。
	raw := []byte(`<?xml version="1.0"?><nmaprun><host><address addr="192.0.2.30" addrtype="ipv4"/><ports><port protocol="tcp" portid="9999"><state/></port></ports></host></nmaprun>`)
	sp, err := NewAdapter().Parse(raw, "exec_test")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, ln := range sp.Lines {
		if ln.Vars["state"] == "unknown" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing state must be recorded as unknown")
	}
}
