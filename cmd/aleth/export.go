package main

// `aleth export` —— 导出证据链供审计（docs/06 §3.2 的职责⑤）。
//
// # 为什么这个命令重要
//
// `06 §3.2` 把「报告导出」列为 CLI 的六项必须职责之一，典型用法给出：
//
//	aleth export --session sess_018f... --format evidence-bundle --out ./audit/
//
// 而此前 CLI 只有 version / status / daemon / mcp 四个子命令 ——
// **export 根本不存在**。
//
// 这条路径的缺失尤其要紧：本项目的第一原则是"结论必须由证据显现"，
// 而**导出证据供外部审计**正是这条原则对外的接口。
// 没有它，"可证明性"只能在 WebUI 里看，无法交给第三方复核。
//
// # 导出的内容与边界
//
// 导出的是**账本里已有的东西**（05 §5.3 的 `TracedEvidenceChain`）：
// finding → assertions → evidence → side_effects，含归因校验结果。
//
// **不导出**：
//   · 任何推测（HYPOTHESIS 不在 `Report` 结构里，契约层面杜绝）
//   · 任何真实敏感值（账本里存的是 token，真实值不出 Privacy Gateway）
//
// 这两条不是实现选择，而是契约与 R7 已经保证的事实 ——
// 本命令只是把已经安全的数据搬到磁盘上。

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// 支持的导出格式（06 §3.2 提到 evidence-bundle；JSON 是它的载体）
const (
	exportFormatBundle = "evidence-bundle"
	exportFormatJSON   = "json"
)

func exportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "导出证据链供外部审计（06 §3.2 职责⑤）",
		Long: `导出会话的证据链，用于第三方复核与合规归档。

典型用法：
  aleth export --session sess_018f... --format evidence-bundle --out ./audit/
  aleth export --session sess_018f... --finding finding_abc --format json

导出内容（账本里已有的东西）：
  finding → assertions → evidence → side-effect observations
  含归因双向校验结果（不一致会显著标注 —— 那是 P0 事件）

**不导出推测**：契约的 Report 结构里没有 HYPOTHESIS 字段，
这是类型层面的保证，不是本命令的取舍。

**不导出真实敏感值**：账本里存的是 token（真实值不出 Privacy Gateway，R7）。`,
		SilenceUsage: true,
		RunE:         runExport,
	}
	cmd.Flags().String("session", "", "要导出的会话 ID（必填）")
	cmd.Flags().String("finding", "", "只导出指定 finding（留空 = 会话全部）")
	cmd.Flags().String("format", exportFormatBundle,
		"导出格式：evidence-bundle（默认）或 json")
	cmd.Flags().String("out", "", "输出目录（默认当前目录）")
	cmd.Flags().String("daemon", "", "daemon 的 gRPC 地址（默认 127.0.0.1:7724）")
	return cmd
}

// ExportBundle 是一次导出的顶层结构。
//
// 刻意**自带元信息**（生成时间、来源、工具版本、契约版本）——
// 一份没有出处的审计产物无法被复核，而"无法复核"等于没有证据。
type ExportBundle struct {
	// SchemaVersion 本导出格式的版本（独立于契约版本）。
	SchemaVersion string `json:"schema_version"`
	// GeneratedAt 生成时刻（UTC, RFC3339）。
	GeneratedAt string `json:"generated_at"`
	// Generator 产出工具与版本。
	Generator string `json:"generator"`
	// SessionID 来源会话。
	SessionID string `json:"session_id"`
	// DaemonEndpoint 数据来源端点（审计要知道数据从哪来）。
	DaemonEndpoint string `json:"daemon_endpoint"`
	// ContractVersion 契约生成物版本（`05` §0 的冻结标识）。
	ContractVersion string `json:"contract_version"`
	// Chains 每条证据链（按 finding）。
	Chains []*alethv1.TracedEvidenceChain `json:"chains"`
	// Notes 导出过程中的说明（如"部分 finding 无法追溯"）。
	//
	// 存在的理由：**失败必须显式**（05 §0 C2）——
	// 若某个 finding 拉取失败，不能静默少一条，必须写进这里。
	Notes []string `json:"notes"`
}

func runExport(cmd *cobra.Command, _ []string) error {
	session, _ := cmd.Flags().GetString("session")
	finding, _ := cmd.Flags().GetString("finding")
	format, _ := cmd.Flags().GetString("format")
	outDir, _ := cmd.Flags().GetString("out")
	daemonAddr, _ := cmd.Flags().GetString("daemon")

	if strings.TrimSpace(session) == "" {
		return fmt.Errorf("--session 必填（审计产物必须能追溯到具体会话）")
	}
	if format != exportFormatBundle && format != exportFormatJSON {
		return fmt.Errorf("未知格式 %q：支持 %s / %s",
			format, exportFormatBundle, exportFormatJSON)
	}
	if daemonAddr == "" {
		daemonAddr = "127.0.0.1:7724"
	}
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("无法创建输出目录 %s: %w", outDir, err)
	}

	conn, err := grpc.NewClient(daemonAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	bundle := &ExportBundle{
		SchemaVersion:   "1",
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		Generator:       "aleth " + version,
		SessionID:       session,
		DaemonEndpoint:  daemonAddr,
		ContractVersion: contractVersion(),
	}

	ledger := alethv1.NewLedgerServiceClient(conn)

	if finding != "" {
		// 单条 finding：直接追溯。
		chain, err := ledger.TraceFinding(cmd.Context(),
			&alethv1.TraceFindingRequest{FindingId: finding})
		if err != nil {
			return fmt.Errorf("追溯 finding %s 失败: %w", finding, err)
		}
		bundle.Chains = append(bundle.Chains, chain)
	} else {
		// 整会话：契约**没有**"列出会话内全部 finding"的 RPC
		// （`05` 只有 ListAdapters 一个 List 方法）。
		//
		// 因此这里如实说明该限制并给出可用的替代路径，而不是
		// 编造一份"看起来完整"的导出 —— 那会让审计方误以为
		// 拿到的是全集（docs/10 §0：不能让"没查"伪装成"没问题"）。
		bundle.Notes = append(bundle.Notes,
			"契约未提供「列出会话内全部 finding」的 RPC（05 只有 ListAdapters）。"+
				"整会话导出需要 --finding 逐个指定，或在 WebUI 的报告与导出页（页面 8）"+
				"按 finding_id 浏览后导出。该缺口已登记为待补的 contract: PR。")
	}

	// 写盘。文件名带会话与时间戳，避免多次导出互相覆盖 ——
	// 审计产物被静默覆盖是证据链断裂的一种。
	// ★ 时间戳精确到**纳秒**：毫秒粒度在 CI 的快速机器上仍会碰撞
	//（两次连续导出 < 1ms → 同名覆盖，TestExportFilenameIsTimestampedAndScoped
	// 在 ubuntu runner 上抓到的真实失败；本机 Windows 较慢无法复现）。
	// 纳秒粒度 + 同名兜底双保险（见下方 exists 循环）。
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	name := fmt.Sprintf("evidence-bundle_%s_%s.json", sanitizeForFilename(session), stamp)
	path := filepath.Join(outDir, name)

	// 同名兜底：即便纳秒粒度仍被外部因素对齐（如时钟回拨），
	// 追加序号而不是覆盖 —— 审计产物永不静默覆盖。
	for seq := 2; ; seq++ {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			break
		}
		path = filepath.Join(outDir,
			fmt.Sprintf("evidence-bundle_%s_%s-%d.json", sanitizeForFilename(session), stamp, seq))
	}

	// 用缩进 JSON：审计产物是给人读的，紧凑格式会让 diff 失去意义。
	blob, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化导出内容失败: %w", err)
	}
	if err := os.WriteFile(path, append(blob, '\n'), 0o644); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", path, err)
	}

	fmt.Printf("已导出 %d 条证据链 → %s\n", len(bundle.Chains), path)
	for _, n := range bundle.Notes {
		fmt.Printf("  注：%s\n", n)
	}
	return nil
}

// contractVersion 返回契约的版本标识。
//
// 取 protobuf 文件描述符里的 `aleth.v1` 包名 + 生成代码的版本号 ——
// 这是**真实存在**的标识，而不是我编一个数字填进去。
// 审计方拿它可以核对"导出用的契约与我手上的 proto 是否同一版"。
//
// 为什么不用 git sha：CLI 二进制可能在没有 git 的环境里构建，
// 而 proto 版本是编译期就固化进二进制的。
func contractVersion() string {
	fd := alethv1.File_aleth_v1_aletheia_proto
	// 包名（aleth.v1）+ 语法版本（proto3）—— 两者都是描述符里的
	// 真实字段，不需要我编造版本号。
	//
	// 更强的标识是描述符的字节哈希，但那需要 protodesc 编组，
	// 收益（防"同名不同内容"）相对复杂度不值 —— 本字段的用途是
	// 让审计方做**粗核对**（"是不是同一份契约家族"）。
	return fmt.Sprintf("%s/%s", fd.Package(), fd.Syntax())
}

// sanitizeForFilename 把会话 ID 变成安全的文件名片段。
//
// 会话 ID 由调用方提供，可能含路径分隔符或 `..` ——
// 未经处理地拼进路径会造成**目录穿越**（写到 --out 之外）。
// 这不是假想威胁：会话 ID 在团队模式下来自远端。
//
// 做法：只保留字母、数字、下划线、连字符；其余替换为 `-`。
// 刻意不做"删除"而归一化，因为不同 ID 可能因此碰撞成同一文件名。
func sanitizeForFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := b.String()
	if out == "" {
		return "unknown"
	}
	// 防 `..` 之类的纯点序列（上面的规则已把 `.` 换成 `-`，这里是双保险）。
	if strings.Trim(out, "-") == "" {
		return "unknown"
	}
	return out
}
