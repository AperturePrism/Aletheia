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
	"os"
	"os/exec"
	"path/filepath"

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

func runDaemonStop(_ *cobra.Command, _ []string) error {
	data, err := os.ReadFile(daemonPIDFile())
	if err != nil {
		return fmt.Errorf("daemon 未在运行（pid 文件不存在: %s）", daemonPIDFile())
	}
	var pid int
	if _, err := fmt.Sscanf(string(data), "%d", &pid); err != nil {
		return fmt.Errorf("pid 文件损坏: %w", err)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("找不到进程 %d: %w", pid, err)
	}
	if err := proc.Signal(os.Interrupt); err != nil {
		// SendSignal 失败通常意味着进程已退出 —— 清理 pid 文件后视为成功。
		_ = os.Remove(daemonPIDFile())
		return fmt.Errorf("发送停止信号失败（进程可能已退出）: %w", err)
	}
	_ = os.Remove(daemonPIDFile())
	fmt.Printf("alethd (pid %d) stop signal sent\n", pid)
	return nil
}

// StatusOutput 是 `aleth status` 的 JSON 结构。
//
// 字段命名与 05 的 ID 约定保持一致，便于脚本直接与 API 返回值对齐。
type StatusOutput struct {
	DaemonRunning bool   `json:"daemon_running"`
	ListenAddr    string `json:"listen_addr"`
	Version       string `json:"version"`
	SessionID     string `json:"session_id,omitempty"`
	TaskStatus    string `json:"task_status,omitempty"`

	// Budget 与 05 §6.3 BudgetState 对齐。
	BudgetTotal    uint32  `json:"budget_total_tokens,omitempty"`
	BudgetConsumed uint32  `json:"budget_consumed_tokens,omitempty"`
	BudgetUtil     float64 `json:"budget_utilization,omitempty"`
	CircuitOpen    bool    `json:"budget_circuit_open,omitempty"`
}

func runStatus(format string) error {
	out := StatusOutput{
		DaemonRunning: false,
		ListenAddr:    fmt.Sprintf("%s:%d", defaultListenAddr, defaultListenPort),
		Version:       version,
	}

	// I0 不实现"查询运行中的 daemon"——那需要 daemon 侧 gRPC 客户端，
	// 而服务端能力尚在建设中。这里只报告 CLI 侧可确定的事实。
	//
	// 如实报告 daemon 未连接，而不是假装查到了空状态：
	// 假成功会让 05 §0 C2「失败必须显式」失效。
	out.DaemonRunning = false

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	fmt.Printf("aleth %s\n", version)
	fmt.Printf("daemon: not connected (I0: 客户端尚未接线)\n")
	fmt.Printf("expected endpoint: %s\n", out.ListenAddr)
	return nil
}
