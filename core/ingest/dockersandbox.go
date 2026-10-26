// DockerSandbox —— SandboxFullRunner 的容器级实现（M6 §7.1 的完整形态）。
//
// 与 ProcessSandbox（进程级第一版）同接口可互换；隔离边界从「进程 +
// 外层容器」升级为「每次执行一个一次性容器」：
//
//	· --rm            用后即毁，无状态残留；
//	· --read-only     只读 rootfs，可写层仅 --tmpfs /tmp（工具工作目录）；
//	· --cap-drop ALL  丢弃全部 Linux capabilities（最小权限）；
//	· --pids-limit    进程数上限（fork 炸弹防御）；
//	· --memory/--cpus 资源上限（超大输出/死循环的资源面兜底）；
//	· 网络模式参数化 —— M6 §7.1 要求「出站必须经 ScopeKernel 代理」，
//	  专用 bridge + 出站代理是部署级配置（run_args 注入，不在代码里
//	  假设拓扑）。
//
// exec_id 生成、输出上限与超时语义与 ProcessSandbox 一致；工具镜像
// 由部署方预构建（白名单工具集），镜像名参数化。
//
// 本实现面向 Linux 部署（docker CLI）；单测通过注入 fake CLI 与
// dockerArgs 纯函数覆盖编排逻辑，真实容器执行在有 docker 的环境
// 手动验证（tests/sandbox/ 同款 e2e 模式）。
package ingest

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// DockerSandbox 以一次性容器执行工具。
type DockerSandbox struct {
	image     string
	network   string
	memoryMB  int
	cpus      float64
	pidsLimit int
	timeout   time.Duration
	dockerBin string // 测试注入 fake CLI；默认 "docker"
}

// DockerSandboxOptions 是容器沙箱的部署参数。
type DockerSandboxOptions struct {
	// Image 工具镜像（白名单工具集，部署方预构建）。
	Image string
	// Network docker 网络模式/名（如专用 bridge；空 = docker 默认）。
	// M6 §7.1：出站必须经 ScopeKernel 代理 —— 专用网络与代理拓扑由部署方定义。
	Network string
	// MemoryMB / CPus 资源上限（0 = 不限）。
	MemoryMB int
	CPus     float64
	// PidsLimit 容器内进程数上限（0 = 默认 128）。
	PidsLimit int
	// Timeout 单次执行上限（<=0 用 DefaultSandboxTimeout）。
	Timeout time.Duration
}

// NewDockerSandbox 构造容器沙箱。
func NewDockerSandbox(opts DockerSandboxOptions) *DockerSandbox {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultSandboxTimeout
	}
	if opts.PidsLimit <= 0 {
		opts.PidsLimit = 128
	}
	return &DockerSandbox{
		image:     opts.Image,
		network:   opts.Network,
		memoryMB:  opts.MemoryMB,
		cpus:      opts.CPus,
		pidsLimit: opts.PidsLimit,
		timeout:   opts.Timeout,
		dockerBin: "docker",
	}
}

// dockerArgs 构造 docker run 的完整 argv（纯函数，测试锚点）。
// argv[0] 是 dockerBin 本身；容器内命令从 args[5] 起。
func (d *DockerSandbox) dockerArgs(toolName string, argv []string) []string {
	args := []string{
		"run", "--rm",
		"--name", "aleth-sandbox-" + toolName + "-" + fmt.Sprintf("%d", time.Now().UnixNano()%1e9),
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"--cap-drop", "ALL",
		"--pids-limit", fmt.Sprintf("%d", d.pidsLimit),
		"--stop-timeout", fmt.Sprintf("%d", int(d.timeout.Seconds())),
	}
	if d.network != "" {
		args = append(args, "--network", d.network)
	}
	if d.memoryMB > 0 {
		args = append(args, "--memory", fmt.Sprintf("%dm", d.memoryMB))
	}
	if d.cpus > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%g", d.cpus))
	}
	args = append(args, d.image)
	args = append(args, argv...)
	return args
}

// ExecuteFull 在一次性容器中执行 argv（SandboxFullRunner 接口）。
func (d *DockerSandbox) ExecuteFull(
	ctx context.Context, toolName string, argv []string,
) (execID string, stdout, stderr []byte, exitCode int, err error) {
	if len(argv) == 0 {
		return "", nil, nil, -1, fmt.Errorf("docker-sandbox: empty argv for tool %q", toolName)
	}
	execID, err = newExecID()
	if err != nil {
		return "", nil, nil, -1, fmt.Errorf("docker-sandbox: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, d.dockerBin, d.dockerArgs(toolName, argv)...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	runErr := cmd.Run()
	exitCode = -1
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	stdout, stderr = outBuf.Bytes(), errBuf.Bytes()

	if runErr != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			// docker run 被 kill 后容器可能仍在：--stop-timeout 让 dockerd
			// 先 SIGTERM 后 SIGKILL 容器；此处报告超时语义。
			return execID, stdout, stderr, exitCode,
				fmt.Errorf("docker-sandbox: tool %q timed out after %s", toolName, d.timeout)
		}
		return execID, stdout, stderr, exitCode,
			fmt.Errorf("docker-sandbox: tool %q failed (exit %d): %w", toolName, exitCode, runErr)
	}
	if len(stdout) > MaxToolOutputBytes {
		return execID, stdout, stderr, exitCode, fmt.Errorf(
			"docker-sandbox: tool %q output %d bytes exceeds limit %d",
			toolName, len(stdout), MaxToolOutputBytes)
	}
	return execID, stdout, stderr, exitCode, nil
}
