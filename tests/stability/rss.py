"""RSS 采样器（tests/stability/rss.py）。

Q8 稳定性 harness 的内存判据来源：`run.sh` 每个采样周期调用一次，读取被测
进程的工作集（Windows `WorkingSetSize` / Linux `VmRSS`），单位 KB。

**为什么不用 shell 里的 `powershell -Command Get-Process`：**

1. harness 要在本机 Windows 与 CI Linux 两侧跑通，shell 分支会重复维护采样
   逻辑，且两边解析方式完全不同（无共享真源）。
2. 从 bash 调用外部解释器在受限 shell 环境下可能被拦截，而失败**只表现为
   空输出** —— 空值经 `awk` 后变成空串，最终让「RSS 增长 < 5%」这条 Q8
   核心判据退化为**恒真的假绿灯**（`docs/10` §0「绿灯替代有效」的同一类风险）。
   这比直接判定失败更危险：它会给出一个看起来通过的结论。

本模块把采样失败变成**显式错误**（非零退出 + stderr），由 `run.sh` 计入
`rss_failures` 并参与最终判定 —— 采样不到 ≠ 没有内存泄漏。

**PID 口径**：只接受 **OS 原生 PID**。Git Bash（MSYS2）的 `$!` 是 MSYS 虚拟
PID，其映射文件 `/proc/<pid>/winpid` 只对 MSYS 运行时可见、原生 Python 读不到，
因此转换只能在 shell 侧做（`run.sh` 的 `native_pid()`）。本模块不做转换。

依赖：仅 Python 标准库（`ctypes` / `pathlib`），不引入第三方包
（`docs/09` §5 第 3 条：新增依赖必须请示）。

退出码：0 = 采样成功（stdout 为整数 KB，独占一行）；1 = 采样失败。
"""

from __future__ import annotations

import argparse
import ctypes
import sys
from ctypes import wintypes
from pathlib import Path

# Windows：PROCESS_QUERY_LIMITED_INFORMATION 是最小可读权限（不需要
# PROCESS_VM_READ）。Vista+ 可用。
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class _ProcessMemoryCounters(ctypes.Structure):
    """PROCESS_MEMORY_COUNTERS（windows.h）。

    字段顺序与类型须与 Win32 结构逐一对应；`cb` 必须先填结构体大小，
    否则 `GetProcessMemoryInfo` 直接失败。
    """

    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def _rss_kb_windows(pid: int) -> int:
    """经 psapi 读取工作集（Windows）。`pid` 必须是真实 Windows PID。"""
    # ctypes.WinDLL 只在 win32 存在，故在函数体内取该属性（运行时求值），
    # 保证本模块在 Linux 上仍可导入。
    win_dll = ctypes.WinDLL
    kernel32 = win_dll("kernel32", use_last_error=True)
    psapi = win_dll("psapi", use_last_error=True)

    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ProcessMemoryCounters),
        wintypes.DWORD,
    ]

    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        raise OSError(f"OpenProcess(pid={pid}) failed, err={ctypes.get_last_error()}")
    try:
        counters = _ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            raise OSError(f"GetProcessMemoryInfo(pid={pid}) failed, err={ctypes.get_last_error()}")
        return int(counters.WorkingSetSize) // 1024
    finally:
        kernel32.CloseHandle(handle)


def _rss_kb_linux(pid: int) -> int:
    """读 /proc/<pid>/status 的 VmRSS（Linux；单位已是 kB）。"""
    status_path = Path(f"/proc/{pid}/status")
    try:
        status = status_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OSError(f"cannot read {status_path}: {exc}") from exc
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    raise OSError(f"VmRSS not found in {status_path}")


def sample_rss_kb(pid: int) -> int:
    """按平台分派采样；不支持的平台显式拒绝，不静默返回 0。"""
    if sys.platform == "win32":
        return _rss_kb_windows(pid)
    if sys.platform.startswith("linux"):
        return _rss_kb_linux(pid)
    raise OSError(f"unsupported platform for RSS sampling: {sys.platform}")


def main() -> int:
    parser = argparse.ArgumentParser(description="sample a process working set (RSS) in KB")
    parser.add_argument("--pid", type=int, required=True, help="目标进程（OS 原生 PID）")
    args = parser.parse_args()

    try:
        kb = sample_rss_kb(args.pid)
    except (OSError, ValueError) as exc:
        print(f"RSS_SAMPLE_ERROR: {exc}", file=sys.stderr)
        return 1

    print(kb)
    return 0


if __name__ == "__main__":
    sys.exit(main())
