package gateway

import (
	"context"
	"strings"
	"testing"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// 本文件是 GatewayService gRPC 适配的测试（05 §6.4）。
//
// 最关键的一组断言：**真实值不出现在任何响应里**（07 §A2）。
// 契约的 `TokenMapping` 没有可放真实值的字段，因此这里断言的是
// "响应文本里搜不到输入的真实值" —— 这是端到端的性质，而不是
// 某个字段的存在性。

func tokenize(t *testing.T, s *Server, session, content string) *alethv1.TokenizeResult {
	t.Helper()
	res, err := s.Tokenize(context.Background(),
		&alethv1.TokenizeRequest{SessionId: session, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestTokenizeReplacesSensitiveValues(t *testing.T) {
	s := NewServer()
	res := tokenize(t, s, "s1", "target 10.40.23.5 is up")
	if strings.Contains(res.GetTokenized(), "10.40.23.5") {
		t.Fatalf("tokenized text still contains the real IP: %q", res.GetTokenized())
	}
	if !strings.Contains(res.GetTokenized(), "IP_PRIVATE_") {
		t.Fatalf("expected an IP_PRIVATE token, got %q", res.GetTokenized())
	}
}

func TestTokenizeResponseNeverCarriesRealValues(t *testing.T) {
	// ★ 07 §A2 的端到端断言：响应里搜不到真实值。
	const secret = "10.40.23.5"
	const cred = "P@ssw0rd123"
	s := NewServer()
	res := tokenize(t, s, "s1",
		"host "+secret+" password="+cred+" contact ops@corp.internal")

	// 把整个响应序列化成文本（含全部字段）后搜索。
	blob := res.String()
	for _, real := range []string{secret, cred, "ops@corp.internal"} {
		if strings.Contains(blob, real) {
			t.Errorf("real value %q leaked into the TokenizeResult protobuf: %s", real, blob)
		}
	}
}

func TestTokenizeMappingsCarryNoRealValues(t *testing.T) {
	// 逐字段确认 TokenMapping 只有 category / token / masked_value，
	// 且 masked_value 也不是真实值。
	s := NewServer()
	res := tokenize(t, s, "s1", "target 10.40.23.5")
	if len(res.GetMappings()) == 0 {
		t.Fatal("expected at least one mapping")
	}
	for _, m := range res.GetMappings() {
		if m.GetCategory() == "" || m.GetToken() == "" {
			t.Errorf("mapping must carry category and token: %+v", m)
		}
		if strings.Contains(m.GetMaskedValue(), "10.40.23.5") {
			t.Errorf("masked_value must not contain the real value: %q", m.GetMaskedValue())
		}
		if m.GetMaskedValue() == m.GetToken() {
			t.Errorf("masked_value should mask the token's sequence number: %q", m.GetMaskedValue())
		}
	}
}

func TestTokenizeIsDeterministicWithinSession(t *testing.T) {
	// M6 §4.1：同一真实值在**同一会话内**必须映射到同一 token ——
	// 否则模型无法建立跨证据的关联。
	s := NewServer()
	a := tokenize(t, s, "s1", "target 10.40.23.5")
	b := tokenize(t, s, "s1", "again 10.40.23.5")
	if a.GetTokenized() == "" || b.GetTokenized() == "" {
		t.Fatal("empty tokenization")
	}
	// 两次的 token 必须一致。
	if a.GetMappings()[0].GetToken() != b.GetMappings()[0].GetToken() {
		t.Fatalf("same value must map to the same token: %q vs %q",
			a.GetMappings()[0].GetToken(), b.GetMappings()[0].GetToken())
	}
}

func TestSessionsAreIsolated(t *testing.T) {
	// 映射表按会话隔离 —— 跨会话共用会让两个会话的编号互相影响，
	// 破坏"同值同 token"的确定性。
	s := NewServer()
	a := tokenize(t, s, "sA", "target 10.40.23.5")
	// 在另一个会话里先映射别的值，再映射同一个值 ——
	// 该会话内它应当是 _001（而不是被会话 A 的编号带偏）。
	_ = tokenize(t, s, "sB", "other 192.168.1.1")
	b := tokenize(t, s, "sB", "target 10.40.23.5")
	if a.GetMappings()[0].GetToken() != "IP_PRIVATE_001" {
		t.Fatalf("session A first token = %q, want IP_PRIVATE_001", a.GetMappings()[0].GetToken())
	}
	if b.GetMappings()[0].GetToken() != "IP_PRIVATE_002" {
		t.Fatalf("session B second token = %q, want IP_PRIVATE_002 "+
			"(sessions must not share the sequence counter)", b.GetMappings()[0].GetToken())
	}
}

func TestEmptySessionFallsBackToDefault(t *testing.T) {
	s := NewServer()
	res := tokenize(t, s, "", "target 10.40.23.5")
	if !strings.Contains(res.GetTokenized(), "IP_PRIVATE_") {
		t.Fatalf("empty session_id must still tokenize: %q", res.GetTokenized())
	}
}

func TestDetokenizeRestoresRealValues(t *testing.T) {
	// Detokenize 是**唯一**会返回真实值的接口 —— 它在语义上就是
	// "给工具用的"（05 §6.4："仅工具执行前一刻调用"）。
	s := NewServer()
	res := tokenize(t, s, "s1", "target 10.40.23.5")
	out, err := s.Detokenize(context.Background(),
		&alethv1.DetokenizeRequest{SessionId: "s1", Content: res.GetTokenized()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.GetRestored(), "10.40.23.5") {
		t.Fatalf("detokenize must restore the real value, got %q", out.GetRestored())
	}
}

func TestScanOutboundDetectsLeaks(t *testing.T) {
	s := NewServer()
	res, err := s.ScanOutbound(context.Background(),
		&alethv1.ScanRequest{SessionId: "s1", Content: "leaked 10.40.23.5 here"})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetClean() {
		t.Fatal("content with a private IP must not be reported clean")
	}
	if len(res.GetHits()) != 1 {
		t.Fatalf("hits = %d, want 1", len(res.GetHits()))
	}
}

func TestScanOutboundHitExcerptIsMasked(t *testing.T) {
	// ★ 命中的 excerpt 必须是掩码形式 —— 告警日志不含真实值（07 §A2）。
	s := NewServer()
	res, _ := s.ScanOutbound(context.Background(),
		&alethv1.ScanRequest{SessionId: "s1", Content: "leaked 10.40.23.5 here"})
	for _, h := range res.GetHits() {
		if strings.Contains(h.GetExcerptMasked(), "10.40.23.5") {
			t.Errorf("hit excerpt must be masked, got %q", h.GetExcerptMasked())
		}
	}
	// 整个响应也不能含真实值。
	if strings.Contains(res.String(), "10.40.23.5") {
		t.Errorf("ScanResult protobuf leaked the real value: %s", res.String())
	}
}

func TestScanOutboundCleanContent(t *testing.T) {
	s := NewServer()
	res, err := s.ScanOutbound(context.Background(),
		&alethv1.ScanRequest{SessionId: "s1", Content: "nmap reports port 443 open"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.GetClean() || len(res.GetHits()) != 0 {
		t.Fatalf("benign content must be clean, got %+v", res)
	}
}

func TestTokenizeThenScanIsClean(t *testing.T) {
	// ★ Q5 的组合主张（I3 交付时的"机制层补偿验证"）：
	// **Tokenize → ScanOutbound 的组合必然干净**。
	//
	// 这是隐私网关最核心的性质：脱敏之后再做一次出站扫描，
	// 不应再命中任何泄漏模式。若不成立，说明脱敏不完整。
	s := NewServer()
	const content = "host 10.40.23.5 db.internal.corp user@corp.internal password=S3cret"
	tok := tokenize(t, s, "s1", content)
	res, err := s.ScanOutbound(context.Background(),
		&alethv1.ScanRequest{SessionId: "s1", Content: tok.GetTokenized()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.GetClean() {
		t.Fatalf("tokenized content must scan clean, but got hits: %+v "+
			"(tokenized=%q)", res.GetHits(), tok.GetTokenized())
	}
}

func TestCategoryOfToken(t *testing.T) {
	for _, tc := range []struct{ tok, want string }{
		{"IP_PRIVATE_001", "IP_PRIVATE"},
		{"HOST_INTERNAL_012", "HOST_INTERNAL"},
		{"EMAIL_003", "EMAIL"},
		{"CREDENTIAL_007", "CREDENTIAL"},
		{"PATH_INTERNAL_042", "PATH_INTERNAL"},
		{"GARBAGE", ""},
		{"", ""},
	} {
		if got := categoryOfToken(tc.tok); got != tc.want {
			t.Errorf("categoryOfToken(%q) = %q, want %q", tc.tok, got, tc.want)
		}
	}
}

func TestMaskTokenKeepsCategoryHidesSequence(t *testing.T) {
	if got := maskToken("IP_PRIVATE_001"); got != "IP_PRIVATE_***" {
		t.Errorf("maskToken = %q, want IP_PRIVATE_***", got)
	}
	if got := maskToken("unknown"); got != "***" {
		t.Errorf("maskToken(unknown) = %q, want ***", got)
	}
}
