// Package orchestrate 实现 M5 编排层（L4）—— 规划与调度。
//
// 契约依据：05 §6 ｜ 模块规格：modules/M5 ｜ 迭代：I6（规划与调度）
//
// # 核心设计决策：不让 LLM 做长程规划（M5 §2）
//
// 依据 CHECKMATE 的实测结论：让 LLM 生成 PDDL 领域描述交给经典规划器求解，
// 比原生 agent 成功率高 20%+、快 50%+、便宜 50%+。教训是
// **LLM 不擅长的长程规划，交给算法**。
//
// 因此职责切成两半：
//
//	LLM（Planner）只回答一个窄问题："针对这个目标，有哪些任务？依赖是什么？"
//	              → 输出 TaskGraph（纯结构，不含执行序列）
//	确定性规划器（零 LLM）：拓扑排序 + 资源约束 + 关键路径
//	              → 输出可执行序列与并发分组
//
// **契约硬约束**：`NextReady` 的实现禁止调用 LLM（05 §6.2 原文，
// 模块规格 §6 要求 CI 静态检查）。本包因此不引入任何 LLM 客户端 ——
// 这不是"暂时不做"，而是设计上不允许。
//
// # 边界（M5 §3.2）
//
//	N1 不装配上下文（向 M3 请求 ContextBundle）
//	N2 不校验证据（向 M4 提交断言）
//	N3 不执行工具（向 M1 请求）
//	N4 不做范围裁决（向 M6 ScopeKernel 请求）
//	N5 **不自行终止会话**（必须经 M4 Arbiter）
//	N6 不修改证据账本
package orchestrate

import (
	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// ---- 失败模式库（M5 §4.2）----

// FailureType 是结构化的失败类型。
//
// **为什么必须结构化而不是纯文本**（M5 §4.2 原文）：简单重试会重复同样的
// 失败；Refiner 依据**结构化的失败类型**改写指令（如 CONTEXT_MISSING →
// 提高光圈档位重新装配上下文）。纯文本的失败描述无法驱动这种定向改写。
type FailureType string

const (
	// FailContextMissing 上下文缺关键实体 —— 缓解：提高光圈档位。
	FailContextMissing FailureType = "CONTEXT_MISSING"
	// FailToolMisuse 参数/工具选错 —— 缓解：换工具或修参数。
	FailToolMisuse FailureType = "TOOL_MISUSE"
	// FailWrongHypothesis 假设方向错误 —— 缓解：回到假设分支并重规划。
	FailWrongHypothesis FailureType = "WRONG_HYPOTHESIS"
	// FailTimeout 超时 —— 缓解：收窄任务范围。
	FailTimeout FailureType = "TIMEOUT"
	// FailPrematureStop 过早放弃 —— 缓解：继续深挖，不换方向。
	FailPrematureStop FailureType = "PREMATURE_STOP"
	// FailHallucination 幻觉 —— 缓解：终止该 agent 并要求重新取证。
	FailHallucination FailureType = "HALLUCINATION"
)

// AllFailureTypes 是全部已知失败类型（测试与校验用）。
func AllFailureTypes() []FailureType {
	return []FailureType{
		FailContextMissing, FailToolMisuse, FailWrongHypothesis,
		FailTimeout, FailPrematureStop, FailHallucination,
	}
}

// ParseFailureType 把字符串解析为失败类型；未知类型返回 false。
//
// 未知类型**不静默归为默认**：Refiner 依据类型做定向改写，把未知类型
// 当成某个已有类型会产生错误的缓解动作。
func ParseFailureType(s string) (FailureType, bool) {
	for _, t := range AllFailureTypes() {
		if string(t) == s {
			return t, true
		}
	}
	return "", false
}

// ---- 熔断器（M5 §4.4）----

// CircuitThresholds 是熔断阈值（M5 §4.4 的默认值，可外置配置）。
//
// 模块规格 §8 明确"阈值外置可调"，因此做成结构体而非常量 ——
// 但**默认值必须与规格一致**，调高阈值属于安全决策而非调优。
type CircuitThresholds struct {
	// MaxAgentHallucinations 单 agent 幻觉计数上限（> 3 → 停止该 agent）。
	MaxAgentHallucinations uint32
	// MaxSessionHallucinationRatio 会话幻觉占比上限（> 0.10 → 终止会话）。
	MaxSessionHallucinationRatio float64
	// BudgetNarrowRatio 预算消耗达到此比例 → 光圈收窄（≥ 0.80）。
	BudgetNarrowRatio float64
	// MaxNoProgressSteps 无进展步数上限（> 15 → rewind）。
	MaxNoProgressSteps uint32
}

// DefaultThresholds 返回 M5 §4.4 的默认阈值。
func DefaultThresholds() CircuitThresholds {
	return CircuitThresholds{
		MaxAgentHallucinations:       3,
		MaxSessionHallucinationRatio: 0.10,
		BudgetNarrowRatio:            0.80,
		MaxNoProgressSteps:           15,
	}
}

// CircuitAction 是熔断动作。
type CircuitAction int

const (
	// ActionNone 无需动作。
	ActionNone CircuitAction = iota
	// ActionStopAgent 停止该 agent 并交 Refiner 改写。
	ActionStopAgent
	// ActionNarrowAperture 光圈自动收窄（M3），只保留高价值任务。
	ActionNarrowAperture
	// ActionHardStop 硬熔断，产出中间报告。
	ActionHardStop
	// ActionRewind 回到最近检查点。
	ActionRewind
	// ActionTerminateSession 终止整场会话（幻觉占比超限 / 范围越界）。
	ActionTerminateSession
)

// String 返回动作的可读名（审计日志用）。
func (a CircuitAction) String() string {
	switch a {
	case ActionStopAgent:
		return "STOP_AGENT"
	case ActionNarrowAperture:
		return "NARROW_APERTURE"
	case ActionHardStop:
		return "HARD_STOP"
	case ActionRewind:
		return "REWIND"
	case ActionTerminateSession:
		return "TERMINATE_SESSION"
	default:
		return "NONE"
	}
}

// CircuitState 是熔断器评估的输入。
type CircuitState struct {
	// ScopeViolation 本步是否发生范围越界尝试。
	//
	// **任何一次越界都立即 fail-closed 熔断全部**（M5 §4.4 表格最后一行
	// 的第二项）。这是最高优先级的条件 —— 它在评估顺序中排第一，
	// 因为它是唯一涉及"可能触碰未授权系统"的条件（07 §T5.5）。
	ScopeViolation bool

	// AgentHallucinations 各 agent 的幻觉计数。
	AgentHallucinations map[string]uint32
	// SessionTotalSteps / SessionHallucinations 用于算会话幻觉占比。
	SessionTotalSteps     uint32
	SessionHallucinations uint32

	// BudgetTotal / BudgetConsumed 预算状态（来自 M6 Governor）。
	BudgetTotal    uint64
	BudgetConsumed uint64

	// NoProgressSteps 连续无进展步数。
	NoProgressSteps uint32
}

// EvaluateCircuit 按 M5 §4.4 评估熔断条件，返回应执行的动作。
//
// 评估顺序即优先级（从严到宽）：
//
//  1. 范围越界 → 终止整场会话（fail-closed，无例外）
//  2. 预算耗尽 → 硬熔断
//  3. 会话幻觉占比超限 → 终止会话
//  4. 单 agent 幻觉超限 → 停止该 agent
//  5. 预算消耗达 80% → 收窄光圈
//  6. 无进展步数超限 → rewind
//
// 返回的第二个值是触发原因（写入审计，供 07 §8 的事件响应流程使用）。
// 多个条件同时满足时只返回最高优先级的动作 —— 熔断一旦触发即终止评估，
// 这与"fail-closed 不降级"一致。
func EvaluateCircuit(s CircuitState, th CircuitThresholds) (CircuitAction, string) {
	// 1. 范围越界：最高优先级，不可协商（M5 §4.4 / 09 §R8）。
	if s.ScopeViolation {
		return ActionTerminateSession, "scope violation attempt: fail-closed termination of the whole session"
	}

	// 2. 预算耗尽 → 硬熔断（产出中间报告，见 §4.4）。
	if s.BudgetTotal > 0 && s.BudgetConsumed >= s.BudgetTotal {
		return ActionHardStop, "budget exhausted: producing interim report"
	}

	// 3. 会话幻觉占比超限 → 终止会话。
	// 分母为零时不算占比（没有步骤就没有"占比"这一概念）。
	if s.SessionTotalSteps > 0 && th.MaxSessionHallucinationRatio > 0 {
		ratio := float64(s.SessionHallucinations) / float64(s.SessionTotalSteps)
		if ratio > th.MaxSessionHallucinationRatio {
			return ActionTerminateSession,
				"session hallucination ratio exceeded: evidence is not trustworthy"
		}
	}

	// 4. 单 agent 幻觉超限 → 停止该 agent。
	// 按 agent_id 排序遍历，保证多个 agent 同时超限时的结果确定（P-5）。
	for _, id := range sortedKeys(s.AgentHallucinations) {
		if s.AgentHallucinations[id] > th.MaxAgentHallucinations {
			return ActionStopAgent, "agent " + id + " exceeded hallucination threshold"
		}
	}

	// 5. 预算消耗达阈值 → 收窄光圈（M3 §4.1 的"恒定曝光"联动）。
	if s.BudgetTotal > 0 && th.BudgetNarrowRatio > 0 {
		ratio := float64(s.BudgetConsumed) / float64(s.BudgetTotal)
		if ratio >= th.BudgetNarrowRatio {
			return ActionNarrowAperture, "budget consumption reached the narrowing threshold"
		}
	}

	// 6. 无进展步数超限 → rewind 到最近检查点。
	if s.NoProgressSteps > th.MaxNoProgressSteps {
		return ActionRewind, "no-progress window exceeded: rewinding to the latest checkpoint"
	}

	return ActionNone, ""
}

// ---- 任务图状态流转 ----

// TaskState 是调度器维护的单个任务状态。
//
// 与合约的 alethv1.Task 不同：这里只保留求解与状态流转所需的字段，
// 避免把 proto 消息当可变状态用（那会让"同一份图被两处修改"成为可能）。
type TaskState struct {
	ID        string
	Title     string
	Objective string
	Role      alethv1.AgentRole
	DependsOn []string
	Status    alethv1.TaskStatus
	Budget    uint32
	Attempt   uint32
	Failures  []*alethv1.FailureRecord
	// TargetEntityHints 是 M5 §8 要求 Planner 输出的**结构化**目标实体提示。
	//
	// 为什么必须结构化（M5 §8 风险栏原文）：M3 的 Autofocus 依赖任务描述里
	// 命名了实体；若 Planner 只给自然语言，Autofocus 只能靠文本抽取兜底，
	// 召回率不稳定。结构化 hints 是这条依赖链的可靠入口。
	TargetEntityHints []string
}
