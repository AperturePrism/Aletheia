// 任务图的确定性 ID 派生（`contract:2026-11-02` 修复）。
//
// # 为什么需要它
//
// `Plan` 此前直接采用调用方给的 `graph_id`；调用方不给就**留空**。
// 而契约里下游每一步都要它：
//
//	NextReady(session_id, graph_id, slots)
//	GetGraph(session_id, graph_id)
//	Checkpoint / Rewind / Fork 的图版本对齐
//
// 实测后果（本轮撞到的）：Python 执行侧拿到空 `graph_id`，
// 按"空值即失败"处理，于是**整场渗透在第一步就中断**。
// 而错误信息是"Orchestrator 未返回 graph_id"——一眼看不出根因在 Plan。
//
// # 为什么用内容哈希而不是自增计数器
//
// `Server` 里确实有个 `seq uint64`，但用它会让**同一份计划在不同进程
// 生命周期里得到不同 ID** —— 这直接违背 P-5（可复现）：
// 检查点、rewind、fork 都比对图版本，ID 不稳定就无法判断
// "这两个检查点是不是同一张图"。
//
// 内容哈希的性质恰好是我们要的：
//   · 同样的计划 → 同样的 ID（跨重启稳定）；
//   · 计划变了 → ID 变（能区分改写前后的图）。
//
// # 哈希口径
//
// 只纳入**结构性**字段（任务 id / 依赖 / 角色 / 预算），不纳入
// 标题与目标文本。理由：标题是给人读的措辞，改一个错别字不该让
// 一张图的身份变掉（那会让已有的检查点失联）。而 id/依赖/角色/预算
// 变了，就是另一张图。

package orchestrate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// graphIDPrefix 是派生 ID 的前缀，便于从日志里一眼分辨
// "调用方指定的 ID" 与 "服务端派生的 ID"。
const graphIDPrefix = "g_"

// deriveGraphID 为任务图派生一个确定性 ID。
//
// 格式：`g_<session>_<12 位十六进制>`。
// 带上 session 前缀是为了让不同会话的图 ID 在日志里可读、可区分
// （纯哈希值在排查时毫无线索）。
func deriveGraphID(g *Graph) string {
	h := sha256.New()
	// 按 id 排序后逐个写入，保证与 map 遍历顺序无关（Go 的 map 遍历
	// 顺序是随机的 —— 不排序会让同一张图每次得到不同哈希）。
	ids := make([]string, 0, len(g.Tasks))
	for id := range g.Tasks {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		t := g.Tasks[id]
		deps := append([]string(nil), t.DependsOn...)
		sort.Strings(deps)
		// 用 0x1f（单元分隔符）而不是逗号/竖线：任务 id 里理论上可能
		// 出现任何可打印字符，用分隔符会被"注入"式撞值。
		fmt.Fprintf(h, "%s\x1f%s\x1f%d\x1f%d\x1e", id, strings.Join(deps, "\x1f"),
			t.Role, t.Budget)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("%s%s_%s", graphIDPrefix, g.SessionID, sum[:12])
}
