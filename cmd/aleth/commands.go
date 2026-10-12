package main

// aleth 的命令实现。
//
// I0 的实现策略：这些命令对 daemon 的调用返回"未实现"而不是假成功。
//
// 为什么不用假成功：一个返回 "started" 但其实什么都没启动的 CLI，
// 会让脚本与 CI 误判状态。对齐 05 §0 C2「失败必须显式」与
// 09 §6 #4「mock 会掩盖契约不一致」。
//
// I0 交付的是 CLI 的**形状**（子命令树、flag、退出码、输出格式），
// 真实行为随各迭代逐步接通。

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// 默认 daemon 监听地址。与 core/config.DefaultListenAddr 保持一致。
//
// 这里不 import config 包：CLI 只做控制平面，不应把全量配置系统拖进
// 一个轻量二进制。两处重复一个常量，由 tests/contract 的一致性测试兜底。
const defaultListenAddr = "127.0.0.1"
const defaultListenPort = 7723

// daemonPIDFile 返回 daemon 的 pid 文件路径。
func daemonPIDFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, ".aleth", "alethd.pid")
}

// alethdBinaryPath 返回 alethd 可执行文件的查找路径。
//
// 顺序：PATH → 与 aleth 同目录。后者使用户只解压一个目录即可工作，
// 不需要把 bin/ 加进 PATH。
func alethdBinaryPath() (string, error) {
	if p, err := exec.LookPath("alethd"); err == nil {
		return p, nil
	}
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot locate self: %w", err)
	}
	sibling := filepath.Join(filepath.Dir(self), "alethd")
	if _, err := os.Stat(sibling); err == nil {
		return sibling, nil
	}
	return "", fmt.Errorf("alethd not found in PATH or next to aleth (%s)", sibling)
}

func runDaemonStart(cmd *cobra.Command, authPath string) error {
	// 08 §1.1 硬约束 1：无凭证不启动。
	//
	// CLI 这里先挡一次，是为了给出比 alethd 内部更明确的用法提示；
	// 真正的防线在 alethd（因为 daemon 可以被直接启动，绕过本 CLI）。
	// 两层都要有 —— 单靠 CLI 挡不住"直接跑 alethd"的路径。
	if authPath == "" {
		return fmt.Errorf("Authorization Anchor: 拒绝启动 —— 未提供授权凭证\n" +
			"  依据 docs/08 §1.1：无凭证不启动，不是警告、不是降级。\n" +
			"  用法：aleth daemon start --authorization roe.yaml\n" +
			"  凭证格式见 docs/08 §2；JSON Schema 见 docs/schemas/roe.schema.json")
	}
	if _, err := os.Stat(authPath); err != nil {
		return fmt.Errorf("授权凭证文件不可读: %w", err)
	}

	foreground, _ := cmd.Flags().GetBool("foreground")
	daemonBin, err := alethdBinaryPath()
	if err != nil {
		return err
	}

	args := []string{"--authorization", authPath}
	if cfgPath, _ := cmd.Flags().GetString("config"); cfgPath != "" {
		args = append(args, "--config", cfgPath)
	}

	if foreground {
		// 前台运行：把进程交给用户终端（也便于 -m 直接看日志）。
		c := exec.Command(daemonBin, args...)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		c.Stdin = os.Stdin
		return c.Run()
	}

	c := exec.Command(daemonBin, args...)
	// 后台守护：不继承 stdout/stderr，否则终端关闭会连坐 daemon。
	logDir := filepath.Join(filepath.Dir(daemonPIDFile()), "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return fmt.Errorf("mkdir log dir: %w", err)
	}
	logFile, err := os.OpenFile(filepath.Join(logDir, "alethd.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open daemon log: %w", err)
	}
	c.Stdout = logFile
	c.Stderr = logFile
	if err := c.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("start daemon: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(daemonPIDFile()), 0o700); err != nil {
		return fmt.Errorf("mkdir pid dir: %w", err)
	}
	if err := os.WriteFile(daemonPIDFile(), []byte(fmt.Sprintf("%d\n", c.Process.Pid)), 0o600); err != nil {
		return fmt.Errorf("write pid file: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "alethd started (pid %d), listening on %s:%d\n",
		c.Process.Pid, defaultListenAddr, defaultListenPort)
	fmt.Fprintf(cmd.OutOrStdout(), "Open the WebUI at http://%s:%d\n", defaultListenAddr, defaultListenPort)
	fmt.Fprintf(cmd.OutOrStdout(), "Logs: %s\n", logFile.Name())
	_ = logFile.Close()
	return nil
}

func runDaemonStop(cmd *cobra.Command, _ []string) error {
	data, err := os.ReadFile(daemonPIDFile())
	if err != nil {
		return fmt.Errorf("daemon 未在运行（pid 文件不存在: %s）", daemonPIDFile())
	}
	// 与 readDaemonPID 同一严格口径（Atoi 而非 Sscanf）——
	// 见该函数的说明：`%d` 是前缀匹配，会把 "12x34" 读成 12，
	// 从而去操作一个无关的进程。
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return fmt.Errorf("pid 文件损坏（内容不是合法 pid）: %s", daemonPIDFile())
	}

	// ★ 平台差异由 stopProcess 封装（daemon_unix.go / daemon_windows.go）。
	//
	// 此前这里直接 `proc.Signal(os.Interrupt)`，在 Windows 上**必然失败**
	// （`not supported by windows`），且失败路径仍删除了 pid 文件 ——
	// 于是 daemon 继续运行、pid 文件却没了，用户再无 CLI 手段停它。
	// 那把"停止失败"（可恢复）变成了"进程失控"（不可发现）。
	//
	// 现在的语义：**只有确认进程已退出，才删 pid 文件**。
	// 删不掉 pid 文件不影响正确性（下次 start 会覆盖它），
	// 但删早了会让运行中的 daemon 失去可发现性 —— 两者不对称。
	if err := stopProcess(pid); err != nil {
		return fmt.Errorf(
			"%w\n  pid 文件保留在 %s —— 未确认进程已退出时不删除它，\n"+
				"  以免运行中的 daemon 失去可发现性。确认进程状态后可手动删除。",
			err, daemonPIDFile())
	}
	_ = os.Remove(daemonPIDFile())
	fmt.Fprintf(cmd.OutOrStdout(), "alethd (pid %d) stopped\n", pid)
	return nil
}

// StatusOutput 是 `aleth status` 的 JSON 结构。
//
// 字段命名与 05 的 ID 约定保持一致，便于脚本直接与 API 返回值对齐。
type StatusOutput struct {
	DaemonRunning bool `json:"daemon_running"`
	// PID daemon 进程号（未运行时省略）。
	//
	// 存在理由：CI 排查"为什么端口被占"时，光知道 daemon_running=true
	// 不够，还需要 pid 去查是哪个进程。
	PID        int    `json:"daemon_pid,omitempty"`
	ListenAddr string `json:"listen_addr"`
	Version    string `json:"version"`
	SessionID  string `json:"session_id,omitempty"`
	TaskStatus string `json:"task_status,omitempty"`

	// Budget 与 05 §6.3 BudgetState 对齐。
	BudgetTotal    uint32  `json:"budget_total_tokens,omitempty"`
	BudgetConsumed uint32  `json:"budget_consumed_tokens,omitempty"`
	BudgetUtil     float64 `json:"budget_utilization,omitempty"`
	CircuitOpen    bool    `json:"budget_circuit_open,omitempty"`
}

func runStatus(cmd *cobra.Command, format string) error {
	out := StatusOutput{
		DaemonRunning: false,
		ListenAddr:    fmt.Sprintf("%s:%d", defaultListenAddr, defaultListenPort),
		Version:       version,
	}

	// ★ 用 **pid 文件 + 进程存活探测** 判断 daemon 是否在运行。
	//
	// 此前这里**无条件**写 `false`，于是 daemon 明明在跑，
	// `aleth status --format json` 也报 `daemon_running: false`。
	//
	// 这对 `06` §3.2 的「④ CI 集成」是直接的破坏：CI 脚本靠这个字段
	// 决定"要不要先启动 daemon"，而它恒为 false 会让脚本每次
	// 都尝试启动 → 端口冲突 → 误判为环境故障。
	//
	// 判据链：pid 文件存在 → 该 pid 的进程仍在 → daemon 在运行。
	// 两步都要查：pid 文件可能残留（daemon 被强杀时来不及清理），
	// 因此**不能只信文件**。
	//
	// 仍未接线的是"查询 daemon 内部状态"（会话/成本/进度）——
	// 那需要 gRPC 客户端；本字段只回答"进程在不在"。
	if pid, ok := readDaemonPID(); ok && processAlive(pid) {
		out.DaemonRunning = true
		out.PID = pid
	}

	// ★ 写 cobra 的 writer（`cmd.OutOrStdout()`）而不是 `os.Stdout`。
	//
	// 此前硬编码 os.Stdout，带来两个后果：
	//   1. **命令不可测** —— 测试无法捕获输出（本文件的测试因此才发现这点）；
	//   2. **无法被调用方重定向** —— 用 `SetOut` 的程序化调用拿到空输出。
	//
	// 这是 cobra 命令的标准约定：输出一律走 cmd 的 writer。
	// 修它不是"为了让测试过"，而是让命令真正可组合（06 §3.2 的
	// 设计取向："面向脚本可组合"）。
	return writeStatus(cmd.OutOrStdout(), format, out)
}

// readDaemonPID 读取 pid 文件。第二返回值表示是否可读且格式合法。
//
// 与 `runDaemonStop` 的读取逻辑共用同一格式约定。
//
// ★ 用 `strconv.Atoi` 而不是 `fmt.Sscanf("%d")`：
// Sscanf 的 `%d` 是**前缀匹配**，`"12x34"` 会被解析成 `12` 并返回成功。
// 那意味着一个损坏的 pid 文件会让 CLI 去操作一个**无关的进程** ——
// 在 stop 路径上这是灾难性的（杀掉别人的进程）。
// Atoi 要求整串都是数字，因此 `12x34` 被如实拒绝。
// （由 TestReadDaemonPIDRejectsGarbage 抓到。）
func readDaemonPID() (int, bool) {
	data, err := os.ReadFile(daemonPIDFile())
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// writeStatus 渲染状态输出（抽出来是为了可独立测试两种格式）。
func writeStatus(w io.Writer, format string, out StatusOutput) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	if _, err := fmt.Fprintf(w, "aleth %s\n", version); err != nil {
		return err
	}
	if out.DaemonRunning {
		if _, err := fmt.Fprintf(w,
			"daemon: running (pid %d)\n", out.PID); err != nil {
			return err
		}
	} else {
		// 未运行时说清"怎么启动"，而不是只报一个 false。
		if _, err := fmt.Fprintf(w,
			"daemon: not running (pid file absent or stale)\n"); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "endpoint: %s\n", out.ListenAddr); err != nil {
		return err
	}
	// 会话/成本/进度需要 daemon 内部的 gRPC 查询 —— 如实说明未接线，
	// 而不是留白让用户以为"没有数据"等同于"没有会话"。
	_, err := fmt.Fprintf(w,
		"session/budget: unavailable (CLI gRPC client not wired yet)\n")
	return err
}
