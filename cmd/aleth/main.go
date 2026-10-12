// Command aleth 是 Aletheia 的控制平面 CLI。
//
// 对应 06 §3.2：
//
//	aleth CLI（控制平面）
//	必须做：① 启动/停止/重启 daemon ② 会话状态查询 ③ 脚本化批量操作
//	         ④ CI 集成（无界面模式） ⑤ 报告导出 ⑥ 范围与授权凭证录入
//	不做： ❌ 不做交互式渗透会话的主界面（那是 WebUI）
//	       ❌ 不做实时进展的可视化（status 只给摘要）
//	       ❌ 不做证据链浏览（可导出，但浏览用 WebUI）
//	设计取向：面向"脚本可组合"而非"人机对话"
//
// I0 实现最小可用集：daemon start/stop、status、version。
// 其余子命令在对应迭代补齐（run/export 见 I6/I11）。
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version 由构建时 -ldflags "-X main.version=..." 注入。
//
// 不写死在代码里：否则每次发版都要改源码，且无法从二进制反推版本。
var version = "dev"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aleth",
		Short: "Aletheia 控制平面 CLI",
		Long: `aleth 是 Aletheia 的控制平面，不是渗透会话的主界面。

载体职责边界（docs/06 §3）：
  · 交互式渗透会话 → WebUI（浏览器打开 http://127.0.0.1:7723）
  · 脚本化 / CI    → 本 CLI

常用示例：
  aleth daemon start --authorization roe.yaml
  aleth daemon stop
  aleth status --session sess_018f... --format json
  aleth version

权限边界（docs/07 §5 权限分离矩阵）：
  CLI 不可绕过闸门 —— 它与其他载体走完全相同的授权与范围校验。`,
		SilenceUsage: true,
	}
	cmd.PersistentFlags().StringP("config", "c", "", "配置文件路径（YAML）")
	cmd.AddCommand(
		daemonCmd(),
		statusCmd(),
		versionCmd(),
		// I11（04 §4 前端交付物）：MCP 接口（06 §3.4）。
		mcpCmd(),
		// 06 §3.2 职责⑤：报告导出。此前**该子命令不存在** ——
		// 而"导出证据供外部审计"正是本项目第一原则对外的接口。
		exportCmd(),
	)
	return cmd
}

func daemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "启动/停止 alethd 守护进程",
		Long: `管理 alethd 守护进程。

alethd 承载全部业务逻辑；本命令只负责它的生命周期。
启动需要授权凭证（docs/08 §1：无凭证不启动）。`,
	}

	start := &cobra.Command{
		Use:   "start",
		Short: "启动守护进程",
		Long: `启动 alethd。

依据 docs/08 §1.1，Authorization Anchor 校验发生在最早时机 ——
在绑定端口、加载模型、初始化沙箱之前。因此 --authorization 是必填项。

缺失凭证时的退出码为 3（docs/08 §1.3），便于 CI 与监控识别。`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			auth, _ := cmd.Flags().GetString("authorization")
			return runDaemonStart(cmd, auth)
		},
	}
	start.Flags().String("authorization", "",
		"授权凭证文件路径（roe.yaml，schema 见 docs/schemas/roe.schema.json）。必填。")
	start.Flags().Bool("foreground", false, "前台运行（默认后台守护）")

	stop := &cobra.Command{
		Use:          "stop",
		Short:        "停止守护进程",
		SilenceUsage: true,
		RunE:         runDaemonStop,
	}

	// 职责①（06 §3.2：「启动/停止/**重启** daemon」）——
	// restart 此前缺失。它不是简单的 stop+start 语法糖：
	// 必须**确认旧进程真的退出**再启动新的，否则新进程会撞上端口占用，
	// 而用户看到的是"重启失败"而非"旧进程没停下来"。
	restart := &cobra.Command{
		Use:   "restart",
		Short: "重启守护进程",
		Long: `重启守护进程（先停再起）。

与 "stop && start" 的区别：本命令会**等待旧进程真正退出**后再启动新的。
否则新进程会因端口被占用而启动失败 —— 那种错误信息会误导用户去查
端口冲突，而真实原因是旧进程还没停干净。`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			auth, _ := cmd.Flags().GetString("authorization")
			return runDaemonRestart(cmd, auth)
		},
	}
	restart.Flags().String("authorization", "",
		"授权凭证文件路径（roe.yaml）。必填 —— 重启同样是启动。")
	restart.Flags().Bool("foreground", false, "前台运行（默认后台守护）")

	cmd.AddCommand(start, stop, restart)
	return cmd
}

// runDaemonRestart 停掉现有 daemon（若有）后重新启动。
func runDaemonRestart(cmd *cobra.Command, authPath string) error {
	// 08 §1.1：无凭证不启动 —— 重启也是启动，因此同一校验。
	// **先校验再停止**：若凭证缺失就拒绝，不能先把正在工作的
	// daemon 停掉再报错（那会把"拒绝启动"变成"服务被中断"）。
	if authPath == "" {
		return fmt.Errorf("Authorization Anchor: 拒绝重启 —— 未提供授权凭证\n" +
			"  依据 docs/08 §1.1：无凭证不启动。\n" +
			"  注意：本命令**在停止现有 daemon 之前**就校验凭证，\n" +
			"  以免把一个运行中的服务停掉之后才报错。\n" +
			"  用法：aleth daemon restart --authorization roe.yaml")
	}

	// 只有确认在运行才停 —— 没在运行时 restart 等价于 start。
	if pid, ok := readDaemonPID(); ok && processAlive(pid) {
		if err := stopProcess(pid); err != nil {
			// 停不掉就**不启动**：两个实例同时跑会争用同一份
			// SQLite 与端口，后果比"重启失败"严重得多。
			return fmt.Errorf("重启中止：无法停止现有 daemon（pid %d）：%w", pid, err)
		}
		_ = os.Remove(daemonPIDFile())
		fmt.Fprintf(cmd.OutOrStdout(), "stopped old daemon (pid %d)\n", pid)
	}
	return runDaemonStart(cmd, authPath)
}

func statusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "查询 daemon 与会话状态（脚本可解析）",
		Long: `查询 daemon 与会话状态。

--format json 输出机器可读 JSON。这是一个控制平面命令：
只给摘要，不做实时进展可视化（那是 WebUI 的职责，docs/06 §3.2）。`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, _ := cmd.Flags().GetString("format")
			return runStatus(cmd, format)
		},
	}
	// ★ 这个 flag 曾经**只被读取、从未被注册** ——
	// `aleth status --format json` 报 "unknown flag"，而帮助文本却在宣传它。
	//
	// 后果不只是"少个选项"：`06 §3.2` 要求 CLI 承担
	// 「CI 集成（无界面模式）」，而机器可读输出正是那条路径的全部 ——
	// 它一直是断的，且因为没人跑过而无人发现。
	cmd.Flags().String("format", "",
		"输出格式：json（机器可读）或留空（人类可读）")
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "version",
		Short:        "打印版本信息",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Printf("aleth %s\n", version)
			return nil
		},
	}
}
