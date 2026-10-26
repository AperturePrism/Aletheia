package ingest

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDockerArgsHardeningFlags(t *testing.T) {
	d := NewDockerSandbox(DockerSandboxOptions{
		Image: "aletheia/tools:1",
		// 刻意不配 Network/Memory/CPus —— 可选项缺省时不产生 flag。
	})
	args := d.dockerArgs("nmap", []string{"nmap", "-p", "3000", "10.40.23.5"})

	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--rm",                                   // 用后即毁
		"--read-only",                            // 只读 rootfs
		"--cap-drop ALL",                         // 最小权限
		"--pids-limit 128",                       // fork 防御
		"--stop-timeout",                         // 超时时 dockerd 负责杀容器
		"--tmpfs /tmp:rw,noexec,nosuid,size=64m", // 可写层仅 /tmp
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("docker args missing hardening flag %q: %s", want, joined)
		}
	}
	// 镜像名之后紧跟容器内 argv（nmap -p 3000 10.40.23.5）。
	imgIdx := indexOf(args, "aletheia/tools:1")
	if imgIdx < 0 || imgIdx+3 >= len(args)+0 || args[imgIdx+1] != "nmap" {
		t.Errorf("container argv must follow image: %v", args)
	}
	if strings.Contains(joined, "--network") || strings.Contains(joined, "--memory") {
		t.Errorf("unset options must not emit flags: %s", joined)
	}
}

func TestDockerArgsOptionalFlags(t *testing.T) {
	d := NewDockerSandbox(DockerSandboxOptions{
		Image:    "aletheia/tools:1",
		Network:  "aleth-proxied",
		MemoryMB: 512,
		CPus:     1.5,
	})
	joined := strings.Join(d.dockerArgs("t", []string{"t"}), " ")
	for _, want := range []string{"--network aleth-proxied", "--memory 512m", "--cpus 1.5"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing optional flag %q: %s", want, joined)
		}
	}
}

func TestDockerSandboxExecuteFullEmptyArgv(t *testing.T) {
	d := NewDockerSandbox(DockerSandboxOptions{Image: "x"})
	if _, _, _, _, err := d.ExecuteFull(context.Background(), "t", nil); err == nil {
		t.Fatal("empty argv must be rejected")
	}
}

func TestDockerSandboxExecuteFullViaFakeCLI(t *testing.T) {
	d := NewDockerSandbox(DockerSandboxOptions{Image: "aletheia/tools:1", Timeout: 30 * time.Second})
	d.dockerBin = fakeDockerCLI(t, "echo docker-marker-9\nexit 0\n")

	execID, stdout, _ /*stderr*/, exitCode, err := d.ExecuteFull(
		context.Background(), "echo-tool", []string{"echo", "docker-marker-9"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.HasPrefix(execID, "exec_") {
		t.Fatalf("exec_id prefix: %q", execID)
	}
	if exitCode != 0 {
		t.Fatalf("exit code: %d", exitCode)
	}
	if !strings.Contains(string(stdout), "docker-marker-9") {
		t.Fatalf("stdout missing marker: %q", stdout)
	}
}

func TestDockerSandboxExecuteFullFailureReturnsEvidence(t *testing.T) {
	// fake CLI 非零退出：「失败仍返回证据」语义与 ProcessSandbox 一致。
	d := NewDockerSandbox(DockerSandboxOptions{Image: "x", Timeout: 30 * time.Second})
	d.dockerBin = fakeDockerCLI(t, "echo partial\nexit 7\n")

	execID, stdout, _ /*stderr*/, exitCode, err := d.ExecuteFull(
		context.Background(), "failing-tool", []string{"failing-tool"})
	if err == nil {
		t.Fatal("non-zero exit must surface as error")
	}
	if exitCode != 7 {
		t.Fatalf("exit code: %d", exitCode)
	}
	if !strings.Contains(string(stdout), "partial") {
		t.Fatalf("partial output must survive failure: %q", stdout)
	}
	if !strings.HasPrefix(execID, "exec_") {
		t.Fatalf("failed execution still gets exec_id: %q", execID)
	}
}

// fakeDockerCLI 生成行为可控的伪 docker CLI（shell 脚本，忽略入参按
// body 执行 —— 编排层测试不依赖真实 docker）。仅 Linux/macOS 可执行；
// Windows 本地跳过（CI 的 Linux job 提供覆盖）。
func fakeDockerCLI(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake docker CLI (shell script) unavailable on windows; covered by linux CI")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-docker")
	script := "#!/bin/sh\n" + body
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}
