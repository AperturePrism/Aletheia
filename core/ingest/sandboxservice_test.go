package ingest

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/AperturePrism/aleth/core/api/aleth/v1"
)

func TestExecIDSignDomainMatchesFocalplane(t *testing.T) {
	// 与 agents/src/aletheia/focalplane/execverifier.py 的
	// EXEC_ID_SIGN_DOMAIN = b"aleth/exec-id/v1\x00" 字节级一致。
	// 域分离漂移 = Go 侧签名全部验不过 —— M4 独立验签的前提，
	// 用固定字节断言锁死。
	want := []byte{'a', 'l', 'e', 't', 'h', '/', 'e', 'x', 'e', 'c', '-',
		'i', 'd', '/', 'v', '1', 0x00}
	if string(ExecIDSignDomain) != string(want) {
		t.Fatalf("sign domain drifted: %q", ExecIDSignDomain)
	}
}

func TestExecSignerSignVerifyRoundTrip(t *testing.T) {
	signer, err := GenerateExecSigner()
	if err != nil {
		t.Fatal(err)
	}
	sig := signer.sign("exec_test_1")
	if !signer.Verify("exec_test_1", sig) {
		t.Fatal("signature should verify")
	}
	if signer.Verify("exec_other", sig) {
		t.Fatal("signature must not verify for a different exec_id")
	}
}

func TestExecSignerLoadFailClosed(t *testing.T) {
	if _, err := LoadExecSignerFromHex("zz-not-hex"); err == nil {
		t.Fatal("invalid hex must fail")
	}
	if _, err := LoadExecSignerFromHex(hex.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("wrong-length key must fail")
	}
}

func TestExecSignerLoadFromFileSameKey(t *testing.T) {
	signer, err := GenerateExecSigner()
	if err != nil {
		t.Fatal(err)
	}
	// 仅含 hex 私钥的文件（与 NAS /work/probe_key.hex 同形态）。
	privHex := hex.EncodeToString(signer.priv)
	path := filepath.Join(t.TempDir(), "exec_key.hex")
	if err := os.WriteFile(path, []byte(privHex), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadExecSignerFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PublicKeyHex() != signer.PublicKeyHex() {
		t.Fatal("loaded signer must derive the same public key")
	}
}

// fakeFullRunner 脚本化执行后端（编排逻辑测试；真实执行由
// processsandbox_test.go 覆盖）。
type fakeFullRunner struct {
	stdout   []byte
	stderr   []byte
	exitCode int
	runErr   error
	gotArgv  []string
}

func (f *fakeFullRunner) ExecuteFull(
	_ context.Context, _ string, argv []string,
) (string, []byte, []byte, int, error) {
	f.gotArgv = argv
	return "exec_fake_0001", f.stdout, f.stderr, f.exitCode, f.runErr
}

// sandboxTestAdapter 的 target 参数走位置渲染（argv 尾参）。
func sandboxTestAdapter() Adapter {
	return &BaseAdapter{
		ToolName: "sandbox-test-tool",
		Versions: VersionRange{Min: "0.0.1", Max: "9.9.9"},
		SchemaDef: &ParamSchema{Params: []ParamDef{
			{Name: "target", Type: ParamTarget, Required: true, ScopeChecked: true},
		}},
		ParseFn: func(raw []byte, execID string) (*alethv1.EvidenceSpectrum, error) {
			return &alethv1.EvidenceSpectrum{ExecId: execID}, nil
		},
	}
}

func newSandboxServiceForTest(t *testing.T, runner SandboxFullRunner) (*SandboxService, *ExecSigner) {
	t.Helper()
	c, err := NewCatalog(sandboxTestAdapter())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewRawStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := GenerateExecSigner()
	if err != nil {
		t.Fatal(err)
	}
	return NewSandboxService(c, store, runner, signer), signer
}

func TestSandboxSignExecIdIssuesUnique(t *testing.T) {
	svc, signer := newSandboxServiceForTest(t, &fakeFullRunner{})
	a, err := svc.SignExecId(context.Background(), &alethv1.SignExecIdRequest{Purpose: "test"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.SignExecId(context.Background(), &alethv1.SignExecIdRequest{Purpose: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ExecId == "" || a.ExecId == b.ExecId {
		t.Fatalf("exec_id must be non-empty and unique: %q vs %q", a.ExecId, b.ExecId)
	}
	if a.IssuedAt == nil {
		t.Fatal("issued_at must be set")
	}
	if !signer.Verify(a.ExecId, a.Signature) {
		t.Fatal("signature must verify against signer key")
	}
}

func TestSandboxExecuteSignsAndStores(t *testing.T) {
	runner := &fakeFullRunner{stdout: []byte("line-one\nline-two\n"), exitCode: 0}
	svc, signer := newSandboxServiceForTest(t, runner)
	res, err := svc.Execute(context.Background(), &alethv1.SandboxExecRequest{
		ToolName: "sandbox-test-tool",
		Params:   map[string]string{"target": "10.40.23.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || res.Error != nil {
		t.Fatalf("expected success: exit=%d err=%v", res.ExitCode, res.Error)
	}
	if !signer.Verify(res.ExecId, res.Signature) {
		t.Fatal("exec signature must verify")
	}
	if res.StdoutRef == nil || res.StdoutRef.ContentHash == "" {
		t.Fatal("stdout must be content-addressed")
	}
	if res.StdoutRef.LineCount != 2 || res.StdoutRef.SizeBytes != uint64(len("line-one\nline-two\n")) {
		t.Fatalf("stdout ref must count lines/bytes: %+v", res.StdoutRef)
	}
	if res.StderrRef != nil {
		t.Fatal("empty stderr should not produce a ref")
	}
	// argv 由 Schema 渲染（tool 名 + 位置参数），未经 shell。
	if len(runner.gotArgv) != 2 || runner.gotArgv[0] != "sandbox-test-tool" || runner.gotArgv[1] != "10.40.23.5" {
		t.Fatalf("argv must be schema-rendered: %v", runner.gotArgv)
	}
}

func TestSandboxExecuteFailureStillReturnsEvidence(t *testing.T) {
	// 契约原文：「必须非零码退出并把证据抛出来」—— 工具失败（非零
	// 退出 / 运行错误）时，已捕获输出与 exec_id+签名 仍然返回，
	// 失败是**结果**而不是把证据吞掉的 RPC 错误。
	runner := &fakeFullRunner{
		stdout:   []byte("partial output\n"),
		stderr:   []byte("boom: connection refused\n"),
		exitCode: 7,
		runErr:   errFakeRun,
	}
	svc, signer := newSandboxServiceForTest(t, runner)
	res, err := svc.Execute(context.Background(), &alethv1.SandboxExecRequest{
		ToolName: "sandbox-test-tool",
		Params:   map[string]string{"target": "10.40.23.5"},
	})
	if err != nil {
		t.Fatalf("tool failure must be a result, not an RPC error: %v", err)
	}
	if res.ExitCode != 7 || res.Error == nil {
		t.Fatalf("failure must carry exit code and error: %+v", res)
	}
	if res.StdoutRef == nil || res.StderrRef == nil {
		t.Fatal("evidence refs must survive tool failure")
	}
	if !signer.Verify(res.ExecId, res.Signature) {
		t.Fatal("even a failed execution gets a verifiable exec signature")
	}
}

var errFakeRun = &fakeRunError{}

type fakeRunError struct{}

func (*fakeRunError) Error() string { return "fake: tool exited non-zero" }

func TestSandboxExecuteUnknownToolRejected(t *testing.T) {
	svc, _ := newSandboxServiceForTest(t, &fakeFullRunner{})
	if _, err := svc.Execute(context.Background(), &alethv1.SandboxExecRequest{
		ToolName: "not-a-tool",
		Params:   map[string]string{"target": "10.40.23.5"},
	}); err == nil {
		t.Fatal("unknown tool must be rejected")
	}
}
