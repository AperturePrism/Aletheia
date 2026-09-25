package spectrum

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCleanANSI(t *testing.T) {
	// M1 §4.3 翻车点 2 的真实形态：模块路径被 TTY 着色污染。
	got := string(CleanANSI([]byte("\x1b[45mftp\x1b[0m/vsftpd_234")))
	if got != "ftp/vsftpd_234" {
		t.Fatalf("CleanANSI = %q, want %q", got, "ftp/vsftpd_234")
	}
	// 截断的未终止 CSI 序列（输出被截断的常见形态）整体移除。
	if got := string(CleanANSI([]byte("a\x1b[3"))); got != "a" {
		t.Fatalf("truncated CSI: got %q, want %q", got, "a")
	}
	// 非 CSI 的两字节 ESC 序列。
	if got := string(CleanANSI([]byte("a\x1bc"))); got != "a" {
		t.Fatalf("two-byte ESC: got %q, want %q", got, "a")
	}
	// 无 ESC 的内容逐字节原样。
	plain := "plain text 123 \xff\xfe keep going"
	if got := string(CleanANSI([]byte(plain))); got != plain {
		t.Fatalf("plain passthrough: got %q, want %q", got, plain)
	}
	// 转义不跨行 → 行数与行号不变。
	in := "line1\x1b[31m-red\x1b[0m\nline2\nline3"
	if got := strings.Count(string(CleanANSI([]byte(in))), "\n"); got != 2 {
		t.Fatalf("line count after clean = %d, want 2", got)
	}
}

func TestSanitizeUTF8(t *testing.T) {
	if _, changed := SanitizeUTF8([]byte("合法 utf-8 \xe4\xb8\xad\xe6\x96\x87")); changed {
		t.Fatal("valid UTF-8 reported as changed")
	}
	got, changed := SanitizeUTF8([]byte("bad\xff\xfebytes"))
	if !changed {
		t.Fatal("invalid UTF-8 not reported")
	}
	if !strings.Contains(string(got), string(utf8.RuneError)) {
		t.Fatalf("replacement rune missing in %q", got)
	}
	// 不产生/删除换行：行号稳定性前提。
	before := strings.Count("a\xffb\nc", "\n")
	after := strings.Count(mustSanitize(t, "a\xffb\nc"), "\n")
	if before != after {
		t.Fatalf("newline count changed: %d -> %d", before, after)
	}
}

func TestSplitLines(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"lf", "a\nb\nc\n", []string{"a", "b", "c"}},
		{"crlf", "a\r\nb\r\n", []string{"a", "b"}},
		{"mixed", "a\r\nb\nc\rd", []string{"a", "b", "c", "d"}},
		{"no trailing newline", "a\nb", []string{"a", "b"}},
		{"empty lines preserved", "a\n\nb", []string{"a", "", "b"}},
		{"only newline", "\n", []string{""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SplitLines([]byte(tc.in))
			if len(got) != len(tc.want) {
				t.Fatalf("SplitLines = %#v, want %#v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("line %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
	if got := SplitLines(nil); got != nil {
		t.Fatalf("empty input: got %#v, want nil", got)
	}
}

func TestNormalizeLineLimit(t *testing.T) {
	big := strings.Repeat("x", DefaultMaxLineBytes+10)
	lines, warnings := Normalize([]byte("first\n"+big+"\nlast\n"), DefaultMaxLineBytes)
	if len(lines) != 3 {
		t.Fatalf("line count = %d, want 3", len(lines))
	}
	if len(lines[1]) != DefaultMaxLineBytes {
		t.Fatalf("line 2 length = %d, want %d (truncated)", len(lines[1]), DefaultMaxLineBytes)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "line 2") {
		t.Fatalf("warnings = %#v, want one entry mentioning line 2", warnings)
	}
}

func TestNormalizeCombined(t *testing.T) {
	// ANSI + 非法 UTF-8 + CRLF 混合（M1 §6 边界用例）。
	in := []byte("\x1b[1mok\x1b[0m\xff\r\nsecond\n")
	lines, warnings := Normalize(in, 0) // 0 → DefaultMaxLineBytes
	if len(lines) != 2 || lines[0] != "ok\ufffd" || lines[1] != "second" {
		t.Fatalf("lines = %#v", lines)
	}
	if len(warnings) == 0 {
		t.Fatal("expected UTF-8 warning")
	}
}

func mustSanitize(t *testing.T, s string) string {
	t.Helper()
	out, _ := SanitizeUTF8([]byte(s))
	return string(out)
}
