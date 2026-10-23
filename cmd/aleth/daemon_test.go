package main

// `aleth daemon` 生命周期的测试（06 §3.2 职责①：启动/停止/**重启**）。
//
// # 为什么这组测试重要
//
// 实测发现两个真实缺陷，都在"真跑一遍"之前不可见：
//
//  1. **`daemon stop` 在 Windows 上必然失败**：`proc.Signal(os.Interrupt)`
//     返回 `not supported by windows`。更糟的是失败路径**仍删除了 pid
//     文件** —— daemon 继续运行、pid 文件却没了，用户再无 CLI 手段停它。
//     那把"停止失败"（可恢复）变成了"进程失控"（不可发现）。
//  2. **`status` 无条件报 `daemon_running: false`**：daemon 明明在跑也报
//     false。对 `06` §3.2 的「④ CI 集成」是直接破坏 ——
//     CI 脚本靠该字段决定"要不要先启动 daemon"，恒 false 会让脚本每次
//     都尝试启动 → 端口冲突 → 误判为环境故障。
//
// 本文件锁定这两条，并覆盖 restart 的关键语义。

import (
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---- pid 文件读取（status 与 stop 共用同一套解析）----

func TestReadDaemonPIDReturnsFalseWhenAbsent(t *testing.T) {
	// 用一个临时 HOME 隔离，避免影响真实 pid 文件。
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	if _, ok := readDaemonPID(); ok {
		t.Fatal("pid 文件不存在时应返回 ok=false")
	}
}

func TestReadDaemonPIDParsesWellFormedFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("USERPROFILE", dir)
	t.Setenv("HOME", dir)
	path := daemonPIDFile()
	if err := os.MkdirAll(strings.TrimSuffix(path, lastPathSegment(path)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pid, ok := readDaemonPID()
	if !ok {
		t.Fatal("合法 pid 文件应被解析")
	}
	if pid != 12345 {
		t.Fatalf("pid = %d, want 12345", pid)
	}
}

func TestReadDaemonPIDRejectsGarbage(t *testing.T) {
	// 损坏的 pid 文件不得被当作有效 —— 否则 status 会去找一个
	// 不存在的 pid，或更糟：报出一个无意义的进程号。
	for _, bad := range []string{"", "abc", "-1", "0", "12x34", "  \n"} {
		dir := t.TempDir()
		t.Setenv("USERPROFILE", dir)
		t.Setenv("HOME", dir)
		path := daemonPIDFile()
		if err := os.MkdirAll(strings.TrimSuffix(path, lastPathSegment(path)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if pid, ok := readDaemonPID(); ok {
			t.Errorf("内容 %q 不应被解析为有效 pid，实际得到 %d", bad, pid)
		}
	}
}

// lastPathSegment 返回路径最后一段（用于构造父目录）。
func lastPathSegment(p string) string {
	idx := strings.LastIndexAny(p, `/\`)
	if idx < 0 {
		return p
	}
	return p[idx:]
}

// ---- status 的 daemon 探测 ----

func TestStatusReportsRunningDaemon(t *testing.T) {
	// ★ 回归：status 曾**无条件**报 daemon_running=false。
	//
	// 这里用**当前测试进程自己的 pid** 写进 pid 文件 —— 它必然存活，
	// 因此这是在真实断言"探测逻辑认得活进程"，而不是构造一个假的
	// "alive 返回 true"。
	dir := t.TempDir()
	t.Setenv("USERPROFILE", dir)
	t.Setenv("HOME", dir)
	path := daemonPIDFile()
	if err := os.MkdirAll(strings.TrimSuffix(path, lastPathSegment(path)), 0o700); err != nil {
		t.Fatal(err)
	}
	self := os.Getpid()
	if err := os.WriteFile(path, []byte(strconv.Itoa(self)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := execRoot(t, "status", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		DaemonRunning bool `json:"daemon_running"`
		PID           int  `json:"daemon_pid"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("输出不是合法 JSON: %v\n%s", err, out)
	}
	if !parsed.DaemonRunning {
		t.Fatalf("pid 文件指向一个存活的进程时，必须报 daemon_running=true。"+
			"（原缺陷：恒为 false，会破坏 06 §3.2 的 CI 集成路径）\n输出：%s", out)
	}
	if parsed.PID != self {
		t.Fatalf("daemon_pid = %d, want %d（CI 排查端口占用时需要它）",
			parsed.PID, self)
	}
}

func TestStatusReportsNotRunningForStalePIDFile(t *testing.T) {
	// ★ 残留 pid 文件（daemon 被强杀时来不及清理）**不得**让 status
	// 误报"在运行" —— 因此必须同时查"进程是否真的活着"。
	//
	// 用一个几乎不可能存在的 pid。选 2^31-1 这类值：正规系统里
	// pid 上限远低于此（Linux 默认 4194304），因此它是安全的"不存在"。
	dir := t.TempDir()
	t.Setenv("USERPROFILE", dir)
	t.Setenv("HOME", dir)
	path := daemonPIDFile()
	if err := os.MkdirAll(strings.TrimSuffix(path, lastPathSegment(path)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("2147483646\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := execRoot(t, "status", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		DaemonRunning bool `json:"daemon_running"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.DaemonRunning {
		t.Fatalf("残留 pid 文件指向不存在的进程时不得报在运行。\n输出：%s", out)
	}
}

func TestStatusHumanOutputDistinguishesRunningFromNot(t *testing.T) {
	// 人类可读输出要**说清**状态，而不是两种情形都印同一句。
	dir := t.TempDir()
	t.Setenv("USERPROFILE", dir)
	t.Setenv("HOME", dir)

	outNot, err := execRoot(t, "status")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(outNot, "not running") {
		t.Errorf("未运行时应明确说明：%s", outNot)
	}

	// 写入存活 pid，再跑一次。
	path := daemonPIDFile()
	if err := os.MkdirAll(strings.TrimSuffix(path, lastPathSegment(path)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outRun, err := execRoot(t, "status")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(outRun, "running") {
		t.Errorf("运行中时应明确说明：%s", outRun)
	}
	if outRun == outNot {
		t.Error("两种状态的输出不应相同 —— 那等于没有传达状态")
	}
}

func TestStatusSaysWhatIsUnavailable(t *testing.T) {
	// 会话/成本/进度未接线时**如实说明**，而不是留白 ——
	// 留白会让用户把"没有数据"读成"没有会话"（docs/10 §0）。
	dir := t.TempDir()
	t.Setenv("USERPROFILE", dir)
	t.Setenv("HOME", dir)
	out, err := execRoot(t, "status")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "unavailable") {
		t.Errorf("未接线的部分应显式标注 unavailable：%s", out)
	}
}

// ---- restart ----

func TestDaemonRestartCommandExists(t *testing.T) {
	// 06 §3.2 职责①的原文是「启动/停止/**重启** daemon」——
	// restart 此前缺失。
	root := rootCmd()
	for _, c := range root.Commands() {
		if c.Name() != "daemon" {
			continue
		}
		for _, sub := range c.Commands() {
			if sub.Name() == "restart" {
				return
			}
		}
	}
	t.Fatal("daemon restart 缺失 —— 06 §3.2 职责①明确要求它")
}

func TestRestartRequiresAuthorizationBeforeStopping(t *testing.T) {
	// ★ 关键语义：凭证校验必须在**停止现有 daemon 之前**。
	//
	// 若顺序反了，"拒绝启动"会变成"服务被中断" —— 用户拿不到
	// 授权凭证时，却把正在工作的服务停掉了。
	//
	// 断言方式：先让一个"daemon"（本测试进程）看起来在运行，
	// 然后不带 --authorization 调 restart —— 必须报错，且
	// pid 文件**保持不变**（证明没走到停止逻辑）。
	dir := t.TempDir()
	t.Setenv("USERPROFILE", dir)
	t.Setenv("HOME", dir)
	path := daemonPIDFile()
	if err := os.MkdirAll(strings.TrimSuffix(path, lastPathSegment(path)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := execRoot(t, "daemon", "restart")
	if err == nil {
		t.Fatal("无凭证时必须拒绝重启（08 §1.1：无凭证不启动）")
	}
	if !strings.Contains(err.Error(), "授权凭证") {
		t.Errorf("错误信息应说明缺凭证：%v", err)
	}
	// pid 文件必须还在 —— 证明没有先停后报错。
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("凭证校验失败时不得改动 pid 文件（否则等于先中断了服务）：%v", statErr)
	}
	blob, _ := os.ReadFile(path)
	if strings.TrimSpace(string(blob)) != strconv.Itoa(os.Getpid()) {
		t.Fatal("pid 文件内容被改动了 —— 停止逻辑不应被执行")
	}
}

func TestRestartHelpMentionsAuthorization(t *testing.T) {
	out, err := execRoot(t, "daemon", "restart", "--help")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "--authorization") {
		t.Errorf("restart --help 应说明 --authorization：%s", out)
	}
}

// ---- 平台差异（stopProcess 的两个实现）----

func TestStopProcessRejectsNonExistentPID(t *testing.T) {
	// 不存在的 pid 必须返回错误，而不是静默成功 ——
	// 静默成功会让调用方以为进程已停，随后删除 pid 文件。
	if err := stopProcess(2147483646); err == nil {
		t.Fatal("不存在的 pid 应返回错误")
	}
}

func TestProcessAliveForSelf(t *testing.T) {
	// 基础自检：当前进程必然存活。
	if !processAlive(os.Getpid()) {
		t.Fatal("processAlive(自己) 必须为 true")
	}
}

// ---- ★ 真实终止一个进程（覆盖平台实现的实际路径）----

func TestStopProcessActuallyTerminatesAProcess(t *testing.T) {
	// ★ 这组断言的存在理由（一次未通过的变异验证）：
	//
	// 我最初只用"不存在的 pid"测 stopProcess —— 那走的是
	// `FindProcess` 失败路径，**从不执行真正的终止调用**。
	// 后果：把 Windows 实现改回有缺陷的 `proc.Signal(os.Interrupt)`
	// （在 Windows 上是 `not supported by windows`）时，
	// **测试全绿** —— 因为它根本没走到那一步。
	//
	// 那是典型的"用绿灯替换有效性"。因此这里启动一个**真实的长驻
	// 子进程**并终止它：这才覆盖到 `proc.Kill()` / SIGTERM 的实际路径。
	//
	// 被终止的是本测试自己启动的睡眠进程，不涉及任何项目进程 ——
	// 测试不得杀别人的进程，这是底线。
	cmd := execCommandHelper(t)
	if err := cmd.Start(); err != nil {
		t.Fatalf("无法启动辅助进程: %v", err)
	}
	pid := cmd.Process.Pid

	// 确认它确实活着（否则后面的断言会因"本来就死了"而假通过）。
	if !processAlive(pid) {
		_ = cmd.Wait()
		t.Fatal("辅助进程启动后应处于存活状态")
	}

	if err := stopProcess(pid); err != nil {
		// 即便失败也要回收，避免泄漏子进程。
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("stopProcess 应能终止一个真实进程: %v", err)
	}

	// 终止后必须**确认**已死 —— 这正是 stopProcess 的契约
	//（"只有确认进程已退出，才删 pid 文件"）。
	if processAlive(pid) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("stopProcess 返回后进程必须已退出")
	}
	_ = cmd.Wait() // 回收僵尸
}

func TestStopProcessWaitsForExit(t *testing.T) {
	// stopProcess 的返回值语义是"已确认退出"，不是"已发送信号"。
	// 这里断言返回后立刻探测即为已死（无需额外等待）。
	cmd := execCommandHelper(t)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if err := stopProcess(pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	if processAlive(pid) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("stopProcess 返回时进程仍在运行 —— 它必须等到确认退出")
	}
	_ = cmd.Wait()
}

// execCommandHelper 启动一个**真实长驻**的辅助进程。
//
// 需要它是因为：只测"不存在的 pid"不会执行真正的终止调用。
// 必须有一个活的进程可杀，才覆盖到 `proc.Kill()` / SIGTERM 的实际路径。
//
// 实现用 Go 标准 helper-process 惯例：重新 exec 本测试二进制，
// 以 GO_HELPER_PROCESS=1 触发 TestHelperSleepProcess（sleep 60s、
// 不捕获信号）。早先版本用 `go env -w` 读 stdin 阻塞 —— 该行为
// 在 CI Linux 上不成立（SIGTERM 后 10s 不退出，测试超时），已废弃。
//
// 被终止的是本测试自己启动的进程，不涉及任何项目进程或系统进程。
func execCommandHelper(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperSleepProcess")
	cmd.Env = append(os.Environ(), "GO_HELPER_PROCESS=1")
	return cmd
}

// TestHelperSleepProcess 是 execCommandHelper 的被测负载：长驻、
// 不捕获信号 —— SIGTERM/ Kill 都会确定性地终止它。
func TestHelperSleepProcess(t *testing.T) {
	if os.Getenv("GO_HELPER_PROCESS") != "1" {
		return // 正常测试运行时是空操作
	}
	time.Sleep(60 * time.Second)
}
