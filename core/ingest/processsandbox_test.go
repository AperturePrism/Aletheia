package ingest

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// platformEchoArgv 返回跨平台的「打印一段文本」argv（不依赖 shell 元字符）。
func platformEchoArgv(text string) []string {
	if runtime.GOOS == "windows" {
		return []string{"cmd", "/C", "echo " + text}
	}
	return []string{"sh", "-c", "echo " + text}
}

func TestProcessSandboxExecutesRealCommand(t *testing.T) {
	sb := NewProcessSandbox(0)
	execID, stdout, err := sb.Execute(context.Background(), "test-tool", platformEchoArgv("sandbox-marker-7"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.HasPrefix(execID, "exec_") {
		t.Fatalf("exec_id should have exec_ prefix, got %q", execID)
	}
	if !strings.Contains(string(stdout), "sandbox-marker-7") {
		t.Fatalf("stdout missing marker: %q", stdout)
	}
}

func TestProcessSandboxExecIDUnique(t *testing.T) {
	sb := NewProcessSandbox(0)
	id1, _, err := sb.Execute(context.Background(), "t", platformEchoArgv("a"))
	if err != nil {
		t.Fatal(err)
	}
	id2, _, err := sb.Execute(context.Background(), "t", platformEchoArgv("b"))
	if err != nil {
		t.Fatal(err)
	}
	if id1 == id2 {
		t.Fatalf("exec_id must be unique per execution: %q twice", id1)
	}
}

func TestProcessSandboxTimeoutKills(t *testing.T) {
	// 直接执行慢命令本体（不经 cmd/sh 包装）：Windows 上 Kill 只作用于
	// 直接子进程，经 shell 包装会杀不到孙进程（ping 继续跑完）。
	sb := NewProcessSandbox(300 * time.Millisecond)
	var sleepArgv []string
	if runtime.GOOS == "windows" {
		sleepArgv = []string{"ping", "-n", "10", "127.0.0.1"}
	} else {
		sleepArgv = []string{"sleep", "10"}
	}
	start := time.Now()
	_, _, err := sb.Execute(context.Background(), "slow-tool", sleepArgv)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("process not killed promptly: %s", elapsed)
	}
}

func TestProcessSandboxMinimalEnv(t *testing.T) {
	// 子进程不应看到调用方注入的环境变量（凭据不入沙箱的进程级对应）。
	t.Setenv("ALETH_SANDBOX_LEAK_PROBE", "secret-value")
	sb := NewProcessSandbox(0)
	var probe []string
	if runtime.GOOS == "windows" {
		probe = []string{"cmd", "/C", "if defined ALETH_SANDBOX_LEAK_PROBE (echo LEAKED) else (echo CLEAN)"}
	} else {
		probe = []string{"sh", "-c", "echo ${ALETH_SANDBOX_LEAK_PROBE:-CLEAN}"}
	}
	_, stdout, err := sb.Execute(context.Background(), "env-probe", probe)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stdout, []byte("secret-value")) {
		t.Fatalf("sandbox env leaked: %q", stdout)
	}
}

func TestProcessSandboxRejectsEmptyArgv(t *testing.T) {
	sb := NewProcessSandbox(0)
	if _, _, err := sb.Execute(context.Background(), "t", nil); err == nil {
		t.Fatal("empty argv must be rejected")
	}
}

func TestProcessSandboxUnknownBinaryFails(t *testing.T) {
	sb := NewProcessSandbox(0)
	if _, _, err := sb.Execute(context.Background(), "t", []string{"aleth-no-such-binary-xyz"}); err == nil {
		t.Fatal("unknown binary must fail")
	}
}
