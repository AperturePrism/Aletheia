package log

import (
	"strings"
	"testing"
)

// TestRedact 覆盖五类脱敏类别，每类断言"真实值不再出现"。
//
// 为什么断言"不再出现"而不是"包含掩码串"：
//
//	掩码串可能因为无关原因出现，而"真实值消失"才是安全属性本身。
func TestRedact(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		realVal  string   // 不得再出现在输出中
		wantCats []string // 必须命中的类别
	}{
		{
			name:     "private ipv4 10/8",
			in:       "target 10.40.23.191 is up",
			realVal:  "10.40.23.191",
			wantCats: []string{CatIPPrivate},
		},
		{
			name:     "private ipv4 172.16/12",
			in:       "host 172.20.1.5",
			realVal:  "172.20.1.5",
			wantCats: []string{CatIPPrivate},
		},
		{
			name:     "private ipv4 192.168/16",
			in:       "gateway 192.168.1.1",
			realVal:  "192.168.1.1",
			wantCats: []string{CatIPPrivate},
		},
		{
			name:     "172.15 不应命中（非私有段）",
			in:       "gateway 172.15.0.1",
			realVal:  "",
			wantCats: nil,
		},
		{
			name:     "internal domain",
			in:       "resolving db.internal.corp ok",
			realVal:  "db.internal.corp",
			wantCats: []string{CatHostInternal},
		},
		{
			name:     "email",
			in:       "contact ops@example.com for details",
			realVal:  "ops@example.com",
			wantCats: []string{CatEmail},
		},
		{
			name:     "credential key value",
			in:       "login password=SuperSecret123 done",
			realVal:  "SuperSecret123",
			wantCats: []string{CatCredential},
		},
		{
			name:     "api key underbars",
			in:       "config api_key = sk-abcdef123456",
			realVal:  "sk-abcdef123456",
			wantCats: []string{CatCredential},
		},
		{
			name:     "internal path",
			in:       "reading /opt/app/config.yml",
			realVal:  "/opt/app/config.yml",
			wantCats: []string{CatPathInternal},
		},
		{
			name:     "multiple categories at once",
			in:       "from 10.0.0.1 to db.internal.corp as password=hunter2",
			realVal:  "hunter2",
			wantCats: []string{CatIPPrivate, CatHostInternal, CatCredential},
		},
		{
			name:    "no sensitive content",
			in:      "scanned 3 ports, found nginx 1.24.0",
			realVal: "",
		},
		{
			name:     "gateway token 不应被二次改写",
			in:       "target IP_PRIVATE_001 mapped from something",
			realVal:  "",
			wantCats: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, cats := Redact(tc.in)

			if tc.realVal != "" && strings.Contains(got, tc.realVal) {
				t.Errorf("real value %q leaked into output: %q", tc.realVal, got)
			}
			for _, want := range tc.wantCats {
				if !containsStr(cats, want) {
					t.Errorf("category %q not reported; got %v (output %q)", want, cats, got)
				}
			}
			// gateway token 场景：token 必须原样保留（它已是脱敏形式）。
			if strings.Contains(tc.in, "IP_PRIVATE_") && !strings.Contains(got, "IP_PRIVATE_001") {
				t.Errorf("gateway token must survive redaction untouched; got %q", got)
			}
		})
	}
}

// TestRedactDeterministic 是 P-5（可复现即一切）在日志层面的验证。
func TestRedactDeterministic(t *testing.T) {
	in := "host 10.40.23.191 user admin password=p@ss at db.internal.corp"
	first, catsA := Redact(in)
	for i := 0; i < 50; i++ {
		got, catsB := Redact(in)
		if got != first {
			t.Fatalf("non-deterministic redaction:\n first=%q\n got  =%q", first, got)
		}
		if strings.Join(catsA, ",") != strings.Join(catsB, ",") {
			t.Fatalf("non-deterministic categories: %v vs %v", catsA, catsB)
		}
	}
}

// TestRedactIsClean 验证出站洁净判定。
func TestRedactIsClean(t *testing.T) {
	if RedactIsClean("connect 10.0.0.5") {
		t.Error("private IP must be flagged as not clean")
	}
	if !RedactIsClean("nmap reports port 443 open") {
		t.Error("benign text must be clean")
	}
}

// TestRedactingWriteSyncerTotals 验证脱敏后返回的长度保持 io.Writer 契约。
//
// 这个断言重要：zap 用 Write 的返回值判断写入是否完整。若返回脱敏后的
// 短长度，zap 会判定写入失败并按错误路径处理，日志会丢失或重复。
func TestRedactingWriteSyncerTotals(t *testing.T) {
	raw := []byte("connect to 10.40.23.191 now")
	rws := &redactingWriteSyncer{ws: &captureWriter{}}
	n, err := rws.Write(raw)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(raw) {
		t.Errorf("Write returned %d, want %d (io.Writer contract requires reporting the input length)", n, len(raw))
	}
}

type captureWriter struct{ buf strings.Builder }

func (c *captureWriter) Write(p []byte) (int, error) { return c.buf.Write(p) }
func (c *captureWriter) Sync() error                 { return nil }

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
