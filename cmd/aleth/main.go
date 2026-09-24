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

	cmd.AddCommand(start, stop)
	return cmd
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "查询 daemon 与会话状态（脚本可解析）",
		Long: `查询 daemon 与会话状态。

--format json 输出机器可读 JSON。这是一个控制平面命令：
只给摘要，不做实时进展可视化（那是 WebUI 的职责，docs/06 §3.2）。`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, _ := cmd.Flags().GetString("format")
			return runStatus(format)
		},
	}
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
