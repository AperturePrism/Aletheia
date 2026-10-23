//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// stopProcess 在 Unix 上向 daemon 发送 SIGTERM。
//
// # 为什么用 SIGTERM 而不是 SIGINT
//
// SIGINT 的语义是"用户按下 Ctrl-C"，通常应被前台程序处理；
// SIGTERM 的语义是"请退出"，是**服务终止的标准信号** ——
// 而 daemon 正是服务。`aleth daemon stop` 是管理者发起的终止，
// 不是用户在终端里打断。
//
// daemon 侧用 `signal.Notify` 捕获 SIGTERM/SIGINT 并优雅退出
// （见 cmd/alethd/main.go 的 rootCtx 处理）。
//
// # 与 Windows 实现的差异（刻意且如实）
//
// Windows 没有 SIGTERM，因此那边用 `TerminateProcess` 强杀。
// 两个平台的**保证不同**：
//
//	· Unix：daemon 有机会走 graceful shutdown（关闭监听、flush、记日志）
//	· Windows：进程被直接终止，依赖"每次写操作即落盘"的设计
//
// 这个差异不该被文档掩盖 —— 它影响的是"Windows 上停止后
// 是否能保证账本已 flush"，而答案是"依赖 WAL，而非依赖退出钩子"。
func stopProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("找不到进程 %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("发送 SIGTERM 到进程 %d 失败: %w", pid, err)
	}
	// 等它真的退出 —— 否则调用方紧接着 `start` 会撞上端口占用。
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf(
		"已发送 SIGTERM，但进程 %d 在 10s 内未退出（graceful shutdown 可能卡住）", pid)
}

// processAlive 报告进程是否仍存在（signal 0 探测）。
//
// 先 FindProcess 再 Signal(0)：进程不存在时 FindProcess 在 Unix 上
// 返回 ESRCH，因此两步都要检查。
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// signal 0 不发送信号，只做权限与存在性检查（POSIX）。
	return proc.Signal(syscall.Signal(0)) == nil
}

// helperCommand 启动一个长驻辅助进程供 stopProcess 的真实终止测试使用。
//
// 用 coreutils 的 sleep（而非测试二进制的 helper-process 惯例）：
// CI Linux 上实测 SIGTERM 后测试二进制 10s 不退出（根因未明，疑似
// go test 运行时对信号的额外处理），而 sleep 对 SIGTERM 100% 终止 ——
// 本测试要验证的是 stopProcess 的行为，不是被杀进程的信号处理。
func helperCommand() *exec.Cmd {
	return exec.Command("sleep", "60")
}
