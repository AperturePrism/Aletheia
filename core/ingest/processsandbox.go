// ProcessSandbox —— SandboxRunner 的进程级实现（M6 §7 的第一版形态）。
//
// 隔离语义（如实登记的阶段性边界）：
//
//	· 单进程沙箱：无 shell、最小固定 env、一次性临时工作目录、
//	  上下文超时（ctx 截止或 Timeout 上限先到即杀）、输出字节上限；
//	· 外层容器边界由部署形态提供 —— NAS/生产部署中 alethd 本身运行
//	  在专用容器内（进程边界即容器边界）。Docker/Kata 级容器隔离
//	  （M6 §7.1 的完整要求：只读镜像、临时卷、网络经 ScopeKernel
//	  代理）是 P1 后续交付项，实现同一 SandboxRunner 接口即可替换。
//
// exec_id 签发（M6 §7.2）：本实现是 exec_id 的唯一生成点 —— L0 不得
// 自行生成（M1 §2.2 N6）。签名（SignedExecId）的消费方是账本 Append
// 路径的 G-1 验签，该路径由调用方构造 AppendEvidenceRequest —— 签名
// 服务随 Append 代理接线一并交付（交接文档登记），此处不预置死代码。
package ingest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// DefaultSandboxTimeout 是单次工具执行的默认上限（对齐 G-4 复现预算
// 量级；nmap -sV 单目标实测远低于此）。
const DefaultSandboxTimeout = 5 * time.Minute

// MaxToolOutputBytes 是工具 stdout 的字节上限 —— 防御性约束：无上限
// 的输出会把证据存储与内存一起拖垮（M1 §8 风险表「超大输出」）。
const MaxToolOutputBytes = 32 << 20 // 32 MiB

// ProcessSandbox 以受限子进程执行工具。
type ProcessSandbox struct {
	timeout time.Duration
}

// NewProcessSandbox 构造进程沙箱。timeout <= 0 时用 DefaultSandboxTimeout。
func NewProcessSandbox(timeout time.Duration) *ProcessSandbox {
	if timeout <= 0 {
		timeout = DefaultSandboxTimeout
	}
	return &ProcessSandbox{timeout: timeout}
}

// Execute 在一次性临时目录中以最小 env 执行 argv，返回签发的 exec_id
// 与原始 stdout。argv 由适配器 Schema 确定性渲染（R5），不含 shell。
func (s *ProcessSandbox) Execute(ctx context.Context, toolName string, argv []string) (string, []byte, error) {
	execID, stdout, _, _, err := s.ExecuteFull(ctx, toolName, argv)
	return execID, stdout, err
}

// ExecuteFull 是完整形态（SandboxService.Execute 消费）：额外返回
// stderr 与退出码 —— 契约要求工具失败时证据（输出引用）仍然返回，
// 因此失败路径也带回已捕获的输出。
func (s *ProcessSandbox) ExecuteFull(
	ctx context.Context, toolName string, argv []string,
) (execID string, stdout, stderr []byte, exitCode int, err error) {
	if len(argv) == 0 {
		return "", nil, nil, -1, fmt.Errorf("sandbox: empty argv for tool %q", toolName)
	}

	execID, err = newExecID()
	if err != nil {
		return "", nil, nil, -1, fmt.Errorf("sandbox: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	workDir, mkErr := os.MkdirTemp("", "aleth-sandbox-")
	if mkErr != nil {
		return execID, nil, nil, -1, fmt.Errorf("sandbox: workdir: %w", mkErr)
	}
	defer func() { _ = os.RemoveAll(workDir) }()

	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...)
	cmd.Dir = workDir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"LANG=C",
		"LC_ALL=C",
		"HOME=" + filepath.Join(workDir, "home"), // 无宿主 HOME（凭据不入沙箱）
	}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	runErr := cmd.Run()
	exitCode = cmd.ProcessState.ExitCode()
	stdout, stderr = outBuf.Bytes(), errBuf.Bytes()

	if runErr != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return execID, stdout, stderr, exitCode,
				fmt.Errorf("sandbox: tool %q timed out after %s", toolName, s.timeout)
		}
		return execID, stdout, stderr, exitCode,
			fmt.Errorf("sandbox: tool %q failed (exit %d): %w", toolName, exitCode, runErr)
	}
	if len(stdout) > MaxToolOutputBytes {
		return execID, stdout, stderr, exitCode, fmt.Errorf(
			"sandbox: tool %q output %d bytes exceeds limit %d", toolName, len(stdout), MaxToolOutputBytes)
	}
	return execID, stdout, stderr, exitCode, nil
}

// newExecID 生成 exec_{uuid7}。与 newSpectrumID 同款 uuidv7 布局
// （parseutil.go 的豁免理由同样适用：执行标识不参与 Q6 确定性对比）。
func newExecID() (string, error) {
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], uint64(time.Now().UnixMilli())&0xFFFF_FFFF_FFFF)
	if _, err := rand.Read(b[8:]); err != nil {
		return "", fmt.Errorf("crypto/rand unavailable: %w", err)
	}
	b[6] = (b[6] & 0x0F) | 0x70 // version 7
	b[8] = (b[8] & 0x3F) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("exec_%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
