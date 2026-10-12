// Package mcp 把 Aletheia 的能力暴露为 MCP server（06 §3.4）。
//
// # 定位（06 §3.4）
//
// MCP 是**集成接口**，与 WebUI（主界面）、CLI（控制平面）并列：
//
//	| 方向     | 内容 |
//	| 作为消费者 | 消费外部 MCP server 提供的工具 |
//	| 作为提供者 | 把 Aletheia 的能力暴露为 MCP server，让外部 agent 调用 |
//
// # ★ 一条不可妥协的约束（06 §3.4 原文）
//
// > **通过 MCP 暴露的能力必须与 WebUI/CLI 遵循完全相同的闸门与范围校验，
// > 不得有绕过路径。**
//
// 这条约束决定了本包的结构：MCP 的每个 tool handler **不自己实现任何
// 校验**，而是调用与 WebUI/CLI 相同的服务接口（`IngestService`、
// `ScopeService` 等）。因此不存在"MCP 专用的宽松路径"。
//
// 本包提供 `Gate` 接口作为这条约束的**显式承载体**：MCP 工具调用前
// 必须经 `Gate.Authorize`，而它的实现是**从既有服务拿裁决**，
// 不是重新判断。若某天有人想给 MCP 加一条"例外"，会先撞上这个接口。
//
// # ❌ 明确不做（06 §3.4）
//
// > **不把 UI 外包给 MCP 客户端** —— 这正是 HexStrike 的教训。
// > MCP 客户端不知道 Aletheia 的领域概念，无法为证据链、光圈投影、
// > 冲突矩阵设计合适界面。
//
// 因此本包只暴露**能力**（工具调用），不暴露任何"界面替代品"。
package mcp

import (
	"context"
	"fmt"
)

// Gate 是 MCP 工具调用的闸门（06 §3.4 的"不得有绕过路径"）。
//
// 实现方必须**复用既有服务**（ScopeService 的范围裁决、
// PrivacyGateway 的脱敏、Governor 的预算预扣），而不是重新判断 ——
// 重新判断就是第二套实现，而两套必然漂移。
type Gate interface {
	// Authorize 在工具执行前做闸门校验。
	//
	// 返回的 error 必须是**显式拒绝**（含原因），
	// 不得返回 nil 表示"没查" —— 与 P-4（失败即熔断不降级）一致。
	Authorize(ctx context.Context, req ToolCall) error
}

// ToolCall 是一次 MCP 工具调用的描述（脱敏后的参数）。
type ToolCall struct {
	// SessionID 调用所属会话。
	SessionID string
	// ToolName 要执行的工具（必须在内置适配器白名单内）。
	ToolName string
	// Target 目标（用于范围校验）。inspect 类工具可为空。
	Target string
	// Params 参数（已校验的键值对）。
	Params map[string]string
	// CallerID 调用方标识（外部 agent 的名字，写入审计）。
	//
	// 存在理由：MCP 的调用方是**外部进程**，审计必须能区分
	// "WebUI 点的"与"某个外部 agent 调用的"—— 否则事后无法追责。
	CallerID string
}

// ErrUnauthorized 是闸门拒绝的哨兵错误。
type ErrUnauthorized struct {
	Reason string
}

func (e *ErrUnauthorized) Error() string {
	return fmt.Sprintf("mcp: tool call refused by the gate: %s", e.Reason)
}

// denyAllGate 是**默认**闸门：拒绝一切。
//
// # 为什么默认是拒绝而不是放行
//
// MCP 的调用方是外部 agent（Claude Desktop / Cursor 等），
// 它们**不受本项目的红约束**：项目能约束自己的 agent 不自终止
// （09 §R6），但约束不了外部 agent 的行为。
//
// 因此"未配置闸门"必须是拒绝而不是放行 —— 与 08 §1.1 的
// 「无凭证不启动」同一思路：把"忘了配置"变成"显式拒绝"。
type denyAllGate struct{}

func (denyAllGate) Authorize(context.Context, ToolCall) error {
	return &ErrUnauthorized{
		Reason: "no gate configured; MCP tool calls require an explicit " +
			"gate wired to ScopeService/PrivacyGateway/Governor " +
			"(06 §3.4: MCP must not have a bypass path)",
	}
}

// NewDenyAllGate 返回拒绝一切的闸门（用于未配置时的安全默认）。
func NewDenyAllGate() Gate { return denyAllGate{} }
