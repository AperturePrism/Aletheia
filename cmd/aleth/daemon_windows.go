//go:build windows

package main

import (
	"fmt"
	"os"
	"time"
)

// stopProcess 在 Windows 上终止 daemon。
//
// # 为什么需要平台特定实现
//
// Linux/macOS 上 `proc.Signal(os.Interrupt)` 发送 SIGINT，daemon 的
// `signal.Notify` 能捕获并优雅退出。但 **Windows 的 `os.Process.Signal`
// 只支持 `os.Kill`** —— 传 `os.Interrupt` 会返回
// `not supported by windows`。
//
// 实测后果（本文件存在的原因）：`aleth daemon stop` 在 Windows 上
// **必然失败**，而且原实现失败后仍删除了 pid 文件 ——
// 于是 daemon 继续运行、pid 文件却没了，用户再无办法用 CLI 停它。
// 那比"停止失败"更糟：它把一个可恢复的问题变成了**不可发现**的问题。
//
// # 为什么用 Kill 而不是更温和的方式
//
// 更优雅的 Windows 做法是发送 WM_CLOSE 或生成一个 console ctrl event，
// 但两者都要求 daemon 是 GUI 进程或共享同一个 console ——
// 而 daemon 是**后台进程**（`daemon start` 不继承 stdout/stderr），
// 两个条件都不满足。
//
// `os.Process.Kill` 在 Windows 上等价于 `TerminateProcess`（强制终止），
// 因此**不会**触发 daemon 的 graceful shutdown。这个代价是可接受的：
//
//	· daemon 的持久状态（账本 / 心智地图）在**每次写操作后即落盘**，
//	  不依赖退出时 flush（append-only + WAL 的设计使然）；
//	· 稳定性测试（Q8）本来就是用 SIGKILL 级别的意外终止来验证
//	  "崩溃后数据仍一致"。
//
// 也就是说：强杀在这个系统里是**被设计覆盖**的场景，
// 而不是需要避免的事故。
func stopProcess(pid int) error {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("找不到进程 %d: %w", pid, err)
	}
	// FindProcess 在 Windows 上总是成功（即使进程不存在），
	// 因此 Kill 的结果才是真正的判据。
	if err := proc.Kill(); err != nil {
		return fmt.Errorf("终止进程 %d 失败: %w", pid, err)
	}
	// 等它真的退出 —— 否则调用方紧接着 `start` 会撞上端口占用。
	// 5s 是经验值：Windows 的 TerminateProcess 通常毫秒级完成，
	// 超时说明进程处于不可中断状态（如内核态 IO），此时如实报告。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf(
		"已发送终止信号，但进程 %d 在 5s 内未退出（可能处于不可中断状态）", pid)
}

// processAlive 报告进程是否仍存在。
//
// 用 `os.FindProcess` + 一个零值信号不可靠（Windows 上 FindProcess 恒成功、
// Signal(0) 也不被支持），因此直接查询系统进程表。
func processAlive(pid int) bool {
	const stillActive = 259 // STILL_ACTIVE
	h, err := openProcessForQuery(pid)
	if err != nil {
		return false
	}
	defer closeHandle(h)
	code, err := exitCodeOf(h)
	if err != nil {
		// 查不到退出码 → 保守认为还活着（宁可多等也不误报已停止）。
		return true
	}
	return code == stillActive
}
