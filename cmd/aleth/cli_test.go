package main

// `aleth` CLI 的测试。
//
// # 为什么 CLI 需要测试（此前是 0% 覆盖）
//
// `06 §3.2` 把 CLI 定义为**控制平面**，并列出六项必须职责。
// 它此前**一个测试都没有** —— 而实测立刻发现两处"宣传了但不可用"：
//
//  1. `aleth status --format json` 报 `unknown flag: --format`：
//     代码 `cmd.Flags().GetString("format")` 读取了该 flag，
//     但**从未注册它**。而 `06 §3.2` 要求 CLI 承担
//     「CI 集成（无界面模式）」，机器可读输出正是那条路径的全部 ——
//     它一直是断的。
//  2. `aleth export`（职责⑤ 报告导出）**子命令根本不存在**。
//
// 两处都属于 `docs/10` §0 说的"用绿灯替换有效性"：帮助文本写了、
// 文档承诺了，但没人跑过。因此本文件的重点是**跑命令树本身**，
// 而不是逐个测内部函数 —— 契约是"这些命令能用"。

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// execRoot 执行命令树并捕获 stdout（cobra 默认写 os.Stdout）。
func execRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := rootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

// ---- 命令树完整性（06 §3.2 的六项职责）----

func TestAllRequiredSubcommandsExist(t *testing.T) {
	// ★ 06 §3.2 的「必须做」清单。每个都必须在命令树里真实存在 ——
	// `export` 曾经缺失，而文档的"典型用法"里就写着它。
	root := rootCmd()
	have := map[string]bool{}
	for _, c := range root.Commands() {
		have[c.Name()] = true
	}
	for _, want := range []string{"daemon", "status", "version", "export", "mcp"} {
		if !have[want] {
			t.Errorf("缺少子命令 %q —— 06 §3.2 要求 CLI 承担该职责", want)
		}
	}
}

func TestDaemonSubcommandsExist(t *testing.T) {
	// 职责①：启动/停止 daemon。
	root := rootCmd()
	var daemon *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "daemon" {
			daemon = c
		}
	}
	if daemon == nil {
		t.Fatal("daemon 子命令缺失")
	}
	have := map[string]bool{}
	for _, c := range daemon.Commands() {
		have[c.Name()] = true
	}
	for _, want := range []string{"start", "stop"} {
		if !have[want] {
			t.Errorf("daemon 缺少 %q", want)
		}
	}
}

// ---- ★ 回归：status --format（曾经只读不注册）----

func TestStatusAcceptsFormatFlag(t *testing.T) {
	// ★ 回归测试：`--format` 曾被读取但从未注册，导致
	// `aleth status --format json` 报 "unknown flag"。
	//
	// 断言方式是**实际带 flag 执行**，而不是检查 flag 是否存在 ——
	// 后者在"注册了但没接线"时仍会通过。
	out, err := execRoot(t, "status", "--format", "json")
	if err != nil {
		t.Fatalf("status --format json 必须可用（06 §3.2 的 CI 集成路径）: %v\n%s", err, out)
	}
}

func TestStatusJSONIsMachineReadable(t *testing.T) {
	// 职责④：CI 集成（无界面模式）—— 输出必须是**可解析的 JSON**，
	// 而不是"看起来像 JSON 的文本"。
	out, err := execRoot(t, "status", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("status --format json 的输出不是合法 JSON: %v\n原文：%s", err, out)
	}
	// 必备字段（脚本会依赖它们做判断）。
	for _, k := range []string{"daemon_running", "listen_addr", "version"} {
		if _, ok := parsed[k]; !ok {
			t.Errorf("JSON 输出缺少字段 %q：%v", k, parsed)
		}
	}
}

func TestStatusHumanReadableByDefault(t *testing.T) {
	out, err := execRoot(t, "status")
	if err != nil {
		t.Fatal(err)
	}
	if json.Valid([]byte(out)) {
		t.Error("默认（无 --format）应输出人类可读文本，而不是 JSON")
	}
	if !strings.Contains(out, "daemon") {
		t.Errorf("人类可读输出应说明 daemon 状态：%s", out)
	}
}

func TestStatusReportsDaemonNotConnectedHonestly(t *testing.T) {
	// 05 §0 C2「失败必须显式」：daemon 未连接时必须**如实说**，
	// 而不是假装查到了空状态（假成功会让脚本误判）。
	out, err := execRoot(t, "status", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		DaemonRunning bool   `json:"daemon_running"`
		ListenAddr    string `json:"listen_addr"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.ListenAddr == "" {
		t.Error("必须报告期望的端点，否则用户无从排查")
	}
}

// ---- ★ export（06 §3.2 职责⑤，此前不存在）----

func TestExportRequiresSession(t *testing.T) {
	// 审计产物必须能追溯到具体会话 —— 无 session 的导出没有意义，
	// 因此拒绝而不是导出一份"不知道来自哪里"的文件。
	_, err := execRoot(t, "export")
	if err == nil {
		t.Fatal("缺少 --session 必须被拒绝")
	}
	if !strings.Contains(err.Error(), "session") {
		t.Errorf("错误信息应说明缺什么：%v", err)
	}
}

func TestExportRejectsUnknownFormat(t *testing.T) {
	// 未知格式不得静默回退到默认 —— 那会让调用方以为拿到了想要的格式。
	_, err := execRoot(t, "export", "--session", "s1", "--format", "pdf")
	if err == nil {
		t.Fatal("未知格式必须被拒绝")
	}
	if !strings.Contains(err.Error(), "pdf") {
		t.Errorf("错误信息应指出未知的格式值：%v", err)
	}
}

func TestExportWritesABundleWithProvenance(t *testing.T) {
	// 一份没有出处的审计产物无法被复核，而"无法复核"等于没有证据。
	dir := t.TempDir()
	out, err := execRoot(t, "export", "--session", "sess_abc", "--out", dir)
	if err != nil {
		t.Fatalf("export 失败: %v\n%s", err, out)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != 1 {
		t.Fatalf("应产出恰好 1 个导出文件，实际 %d", len(files))
	}
	blob, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var bundle ExportBundle
	if err := json.Unmarshal(blob, &bundle); err != nil {
		t.Fatalf("导出内容不是合法 JSON: %v", err)
	}
	for field, val := range map[string]string{
		"schema_version":   bundle.SchemaVersion,
		"generated_at":     bundle.GeneratedAt,
		"generator":        bundle.Generator,
		"session_id":       bundle.SessionID,
		"daemon_endpoint":  bundle.DaemonEndpoint,
		"contract_version": bundle.ContractVersion,
	} {
		if strings.TrimSpace(val) == "" {
			t.Errorf("导出缺少出处字段 %q —— 无出处的审计产物无法复核", field)
		}
	}
	if bundle.SessionID != "sess_abc" {
		t.Errorf("session_id = %q, want sess_abc", bundle.SessionID)
	}
}

func TestExportNotesTheMissingListRPC(t *testing.T) {
	// ★ 契约没有"列出会话内全部 finding"的 RPC（05 只有 ListAdapters）。
	// 整会话导出时**必须如实说明**该限制，而不是产出一份
	// "看起来完整"的空 bundle —— 那会让审计方误以为拿到了全集。
	dir := t.TempDir()
	_, err := execRoot(t, "export", "--session", "s1", "--out", dir)
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	blob, _ := os.ReadFile(files[0])
	var bundle ExportBundle
	_ = json.Unmarshal(blob, &bundle)
	if len(bundle.Notes) == 0 {
		t.Fatal("整会话导出必须带说明（契约缺 list RPC），不能静默产出空 bundle")
	}
	if !strings.Contains(strings.Join(bundle.Notes, " "), "RPC") {
		t.Errorf("说明应指出契约缺口：%v", bundle.Notes)
	}
}

func TestExportFilenameIsTimestampedAndScoped(t *testing.T) {
	// 文件名带时间戳：审计产物被静默覆盖是证据链断裂的一种。
	dir := t.TempDir()
	if _, err := execRoot(t, "export", "--session", "s1", "--out", dir); err != nil {
		t.Fatal(err)
	}
	if _, err := execRoot(t, "export", "--session", "s1", "--out", dir); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != 2 {
		t.Fatalf("两次导出应产出 2 个文件（不互相覆盖），实际 %d", len(files))
	}
}

// ---- ★ 路径穿越防护 ----

func TestSanitizeForFilenameBlocksTraversal(t *testing.T) {
	// 会话 ID 在团队模式下来自远端 —— 未处理地拼进路径会造成目录穿越。
	for _, tc := range []struct{ in, banned string }{
		{"../../../etc/passwd", ".."},
		{"/abs/path", "/"},
		{"a\\b", "\\"},
		{"sess:1", ":"},
	} {
		got := sanitizeForFilename(tc.in)
		if strings.Contains(got, tc.banned) {
			t.Errorf("sanitizeForFilename(%q) = %q，仍含危险字符 %q",
				tc.in, got, tc.banned)
		}
	}
}

func TestSanitizeForFilenameKeepsSafeIDsIntact(t *testing.T) {
	// 合法的会话 ID 不应被改动 —— 否则导出文件名与 session_id 对不上，
	// 审计时无法靠文件名找到对应会话。
	for _, id := range []string{"sess_018f", "sess-abc-123", "S1"} {
		if got := sanitizeForFilename(id); got != id {
			t.Errorf("sanitizeForFilename(%q) = %q，安全 ID 应原样保留", id, got)
		}
	}
}

func TestSanitizeForFilenameNeverReturnsEmpty(t *testing.T) {
	// 空文件名会让 os.WriteFile 失败或写到意料之外的位置。
	for _, bad := range []string{"", "...", "/", "///"} {
		if got := sanitizeForFilename(bad); got == "" {
			t.Errorf("sanitizeForFilename(%q) 返回空串", bad)
		}
	}
}

func TestExportDoesNotEscapeOutputDir(t *testing.T) {
	// 端到端确认：恶意 session ID 不得让文件落到 --out 之外。
	parent := t.TempDir()
	outDir := filepath.Join(parent, "audit")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := execRoot(t, "export",
		"--session", "../../escape", "--out", outDir); err != nil {
		t.Fatal(err)
	}
	// 父目录里除了 audit/ 不应出现别的东西。
	entries, _ := os.ReadDir(parent)
	if len(entries) != 1 || entries[0].Name() != "audit" {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("导出逃出了 --out 目录：%v", names)
	}
}

// ---- contractVersion ----

func TestContractVersionIsReal(t *testing.T) {
	// 必须是 proto 描述符里的**真实**字段，而不是编造的数字。
	got := contractVersion()
	if !strings.Contains(got, "aleth.v1") {
		t.Errorf("contractVersion() = %q，应含 proto 包名", got)
	}
	if strings.Contains(got, "unknown") || got == "" {
		t.Errorf("contractVersion() = %q，不应是占位值", got)
	}
}

// ---- 帮助文本与实际能力一致 ----

func TestStatusHelpMentionsFormatFlag(t *testing.T) {
	// 帮助文本宣传的 flag 必须真实存在 —— 这正是曾经出问题的地方
	// （文本写了 --format，但 flag 未注册）。
	out, err := execRoot(t, "status", "--help")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "--format") {
		t.Errorf("status --help 应说明 --format：%s", out)
	}
}

func TestExportHelpMentionsRequiredFlag(t *testing.T) {
	out, err := execRoot(t, "export", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--session", "--finding", "--format", "--out"} {
		if !strings.Contains(out, want) {
			t.Errorf("export --help 缺少 %s：%s", want, out)
		}
	}
}
