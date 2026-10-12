//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

// openProcessForQuery 打开进程句柄以查询其退出码。
//
// 只需要 `PROCESS_QUERY_LIMITED_INFORMATION`（Vista+），
// 而不是 `PROCESS_QUERY_INFORMATION` —— 后者需要更高权限，
// 在非提升的终端里对某些系统进程会失败。
// 用最小必要权限是 Windows 安全实践，也让本命令在普通会话里稳定工作。
func openProcessForQuery(pid int) (windows.Handle, error) {
	return windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
}

// closeHandle 关闭句柄（失败无补救手段，忽略返回值）。
func closeHandle(h windows.Handle) { _ = windows.CloseHandle(h) }

// exitCodeOf 读取进程退出码。
//
// 值为 `STILL_ACTIVE`(259) 表示进程仍在运行；`GetExitCodeProcess`
// 对已退出进程返回其真实退出码，因此"能读到非 259"即"已退出"。
//
// 注意：259 也可能是某个进程**恰好**以 259 退出的值 —— 这是 Windows
// 上众所周知的歧义。对本用途（等待 daemon 退出）影响可忽略：
// 最坏情况是多等 5s 后报"未退出"，而不是误判"已停止"而继续操作
// （保守方向是对的：宁可多等，不可在旧进程还活着时启动新的）。
func exitCodeOf(h windows.Handle) (uint32, error) {
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return 0, err
	}
	return code, nil
}
