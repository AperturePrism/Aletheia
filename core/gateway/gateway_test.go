package gateway

import (
	"strings"
	"testing"
)

func TestTokenizeDeterministic(t *testing.T) {
	// M6 §4.1：同一真实值在同一会话内必须映射到同一 token（非随机）。
	g := NewGateway()
	in := "scan 10.40.23.191 and db.internal.corp"
	out1, _ := g.Tokenize(in)
	out2, _ := g.Tokenize(in)
	if out1 != out2 {
		t.Fatalf("tokenize not deterministic:\n%s\n%s", out1, out2)
	}
	if !strings.Contains(out1, "IP_PRIVATE_001") {
		t.Fatalf("IP token missing: %s", out1)
	}
	if !strings.Contains(out1, "HOST_INTERNAL_001") {
		t.Fatalf("host token missing: %s", out1)
	}
	if strings.Contains(out1, "10.40.23.191") || strings.Contains(out1, "db.internal.corp") {
		t.Fatal("real values must not survive tokenization")
	}
}

func TestDetokenizeRoundTrip(t *testing.T) {
	g := NewGateway()
	real := "admin:P@ssw0rd"
	tokenized, _ := g.Tokenize("password: " + real)
	if strings.Contains(tokenized, "P@ssw0rd") {
		t.Fatal("credential must be tokenized before leaving the process")
	}
	back := g.Detokenize(tokenized) // 工具执行前一刻回注
	if !strings.Contains(back, real) {
		t.Fatalf("detokenize must restore the real value, got %q", back)
	}
}

func TestScanOutboundBlocksLeaks(t *testing.T) {
	g := NewGateway()
	leaks := g.ScanOutbound("output contains 10.40.23.191, dumped /etc/shadow and passwd=secret123")
	cats := map[string]bool{}
	for _, h := range leaks {
		cats[h.Category] = true
		// 告警摘必须掩码：日志不含完整真实值（05 §6.4）。
		if !strings.Contains(h.Excerpt, "*") {
			t.Fatalf("excerpt not masked: %q", h.Excerpt)
		}
	}
	if !cats["IP_PRIVATE"] || !cats["CREDENTIAL"] || !cats["PATH_INTERNAL"] {
		t.Fatalf("missing leak categories: %v", cats)
	}
}

func TestScanOutboundCleanAfterTokenize(t *testing.T) {
	// Q5 主张：先 Tokenize 再 ScanOutbound 必须干净 —— 两道防线的组合。
	g := NewGateway()
	in := "target 192.168.5.5, path /opt/app/config.yml, mail a@corp.internal"
	tokenized, _ := g.Tokenize(in)
	if hits := g.ScanOutbound(tokenized); len(hits) != 0 {
		t.Fatalf("tokenized output must be clean, hits: %v", hits)
	}
}

func TestCredentialPatternClassics(t *testing.T) {
	// CREDENTIAL 模式的代表性正反例。
	g := NewGateway()
	mustHit := []string{"password: hunter2", "API_KEY = abc", "token=abcdef", "passwd: xyz"}
	for _, s := range mustHit {
		if len(g.ScanOutbound(s)) == 0 {
			t.Fatalf("credential leak not detected: %q", s)
		}
	}
	clean := []string{"password policy reviewed", "the token economy"} // 无 [:]= 值形态
	for _, s := range clean {
		if hits := g.ScanOutbound(s); len(hits) != 0 {
			t.Fatalf("false positive: %q -> %v", s, hits)
		}
	}
}
