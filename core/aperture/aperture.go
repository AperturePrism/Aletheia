// Package aperture 实现 M3 光圈控制（L2）—— 本项目的核心创新。
//
// 契约依据：05 §4 ｜ 模块规格：modules/M3 ｜ 迭代：I5
//
// # 一句话
//
// 记忆在图里，上下文只是焦点的投影 —— 信息不因离开上下文而丢失。
//
// # 要解决的问题（D4 上下文失忆）
//
// 调研记录的真实表现：agent 发现了一个隐藏 API 参数，随后被另一个端点
// 分心，**20 步之后完全遗忘了这个线索**。根因是现有项目把上下文窗口
// 当记忆用 —— 上下文满了就只能丢弃，丢弃即永久丢失。
//
// M3 的解法：上下文不承载记忆，只承载"当前焦点的投影"。需要时可重新投影。
//
// # 不可协商的约束（M3 §2.2 N4 / §3.1 R4）
//
// **不允许截断装配结果。** 截断会产生"信息看起来完整但实际缺失"的静默
// 错误 —— 那是 D1 幻觉式成功的温床。超预算时必须显式失败并降档重选。
// 本包的 Assemble 返回 ErrOverBudget 而不是返回一个"差不多"的包。
package aperture

import (
	"fmt"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// StopProfile 是一档光圈的参数（M3 §4.1 的表格）。
type StopProfile struct {
	Stop           alethv1.ApertureSetting_Stop
	MaxHops        uint32
	MaxEntities    uint32
	DepthPerEntity uint32
	// Label 是人类可读的档位名（f/1.4 等），用于审计与渲染。
	Label string
	// Semantics 说明该档位的适用任务（M3 §4.1 的"适用任务"列）。
	Semantics string
}

// profiles 是 M3 §4.1 光圈模型的实现。
//
// 数值直接取自模块规格，不做"优化"：
// f/1.4 宽而浅（攻击面总览）、f/4 平衡（常规分析）、f/16 窄而深（单点利用）。
var profiles = map[alethv1.ApertureSetting_Stop]StopProfile{
	alethv1.ApertureSetting_F_1_4: {
		Stop:           alethv1.ApertureSetting_F_1_4,
		MaxHops:        1,
		MaxEntities:    200,
		DepthPerEntity: 1,
		Label:          "f/1.4",
		Semantics:      "大孔径：宽而浅 —— 攻击面总览、初始侦察规划",
	},
	alethv1.ApertureSetting_F_4: {
		Stop:           alethv1.ApertureSetting_F_4,
		MaxHops:        2,
		MaxEntities:    60,
		DepthPerEntity: 2,
		Label:          "f/4",
		Semantics:      "中孔径：平衡 —— 常规漏洞分析",
	},
	alethv1.ApertureSetting_F_16: {
		Stop:           alethv1.ApertureSetting_F_16,
		MaxHops:        3,
		MaxEntities:    10,
		DepthPerEntity: 5,
		Label:          "f/16",
		Semantics:      "小孔径：窄而深 —— 单点利用、PoC 编写",
	},
}

// DefaultStop 是未指定档位时的默认值（M3 的常规分析场景）。
const DefaultStop = alethv1.ApertureSetting_F_4

// ProfileFor 返回档位参数。未指定档位时返回默认档。
func ProfileFor(stop alethv1.ApertureSetting_Stop) StopProfile {
	if p, ok := profiles[stop]; ok {
		return p
	}
	return profiles[DefaultStop]
}

// SettingFor 构造契约的 ApertureSetting。
func SettingFor(stop alethv1.ApertureSetting_Stop) *alethv1.ApertureSetting {
	p := ProfileFor(stop)
	return &alethv1.ApertureSetting{
		Stop:           p.Stop,
		MaxHops:        p.MaxHops,
		MaxEntities:    p.MaxEntities,
		DepthPerEntity: p.DepthPerEntity,
	}
}

// NarrowerThan 报告 a 是否比 b 更"小孔径"（更窄更深）。
//
// 降档方向：f/1.4 → f/4 → f/16（实体更少、跳数更多、每实体更深）。
// 超预算时按此方向降档重试（M3 §5 T3.7）。
func NarrowerThan(a, b alethv1.ApertureSetting_Stop) bool {
	return stopOrder(a) > stopOrder(b)
}

// stopOrder 给出档位在"由宽到窄"轴上的序号。
func stopOrder(s alethv1.ApertureSetting_Stop) int {
	switch s {
	case alethv1.ApertureSetting_F_1_4:
		return 1
	case alethv1.ApertureSetting_F_4:
		return 2
	case alethv1.ApertureSetting_F_16:
		return 3
	default:
		return 2 // 未指定按默认档
	}
}

// narrowerStop 返回下一档更小的光圈；已是最小档时返回 false。
//
// 降档顺序刻意是 f/1.4 → f/4 → f/16：档位越小，**实体数上限越低**，
// 因此装配的 token 量单调下降。这是降档重试能收敛的原因。
func narrowerStop(s alethv1.ApertureSetting_Stop) (alethv1.ApertureSetting_Stop, bool) {
	switch s {
	case alethv1.ApertureSetting_F_1_4:
		return alethv1.ApertureSetting_F_4, true
	case alethv1.ApertureSetting_F_4:
		return alethv1.ApertureSetting_F_16, true
	default:
		return s, false
	}
}

// ---- Token 估算（M3 §4.5）----

// 估算系数。全部取自 M3 §4.5 的表格，**不做"优化"**。
const (
	// charsPerToken 是字符→token 的保守换算系数。
	// 规格原文 3.5（保守）。保守方向是"宁可低估预算也不可超支"。
	charsPerToken = 3.5

	// overheadPerEntity 是每实体的结构开销（JSON 键名、括号、分隔符）。
	overheadPerEntity = 8

	// overheadPerRelation 是每关系的固定开销。
	overheadPerRelation = 12

	// overheadPerEvidence 是证据摘要的固定开销（不含断言文本）。
	overheadPerEvidence = 30

	// budgetSafetyRatio 是装配阈值：累加到这里就停（M3 §4.2 步骤 5
	// 的 "budget × 0.95"）。留 5% 余量吸收估算偏差。
	budgetSafetyRatio = 0.95
)

// EstimateEntityTokens 估算单个实体的 token 数。
//
// depth 是允许展开的属性个数（depth_per_entity）。属性按 key 排序后
// 取前 depth 个 —— 排序保证确定性（P-5：相同输入必得相同估算）。
func EstimateEntityTokens(e *alethv1.Entity, depth uint32) uint32 {
	if e == nil {
		return 0
	}
	chars := 0
	// 实体 ID 本身要进上下文（引用关系需要它）。
	chars += len(e.GetEntityId())
	keys := sortedKeys(e.GetAttributes())
	for i, k := range keys {
		if depth > 0 && uint32(i) >= depth {
			break
		}
		chars += len(k) + len(e.GetAttributes()[k])
	}
	tokens := uint32(float64(chars)/charsPerToken) + overheadPerEntity
	return tokens
}

// EstimateRelationTokens 估算单条关系的 token 数（M3 §4.5：固定 12）。
func EstimateRelationTokens(_ *alethv1.Relation) uint32 { return overheadPerRelation }

// EstimateEvidenceTokens 估算一条证据摘要（固定 30 + 断言文本长度）。
func EstimateEvidenceTokens(assertionText string) uint32 {
	return overheadPerEvidence + uint32(float64(len(assertionText))/charsPerToken)
}

// EstimateBundleTokens 估算一个装配结果的 token 总量。
//
// 这是**唯一的**预算判据入口：装配、降档重试、二次校验都用它，
// 保证"估算"只有一份实现（两份实现必然漂移）。
func EstimateBundleTokens(ents []*alethv1.Entity, rels []*alethv1.Relation, depth uint32) uint32 {
	var total uint32
	for _, e := range ents {
		total += EstimateEntityTokens(e, depth)
	}
	for _, r := range rels {
		total += EstimateRelationTokens(r)
	}
	return total
}

// ---- 预算约束（M3 §4.1 恒定曝光）----

// ErrOverBudget 表示装配结果超出预算（M3 §5 T3.7）。
//
// 契约映射：APERTURE_OVER_BUDGET（05 §1.3）。**这是显式失败，不是
// 降级返回** —— 调用方必须降档重试或提高预算，绝不能拿一个被截断的包。
type OverBudgetError struct {
	Estimated uint32
	Budget    uint32
	Stop      alethv1.ApertureSetting_Stop
	// MinPossible 是"连最小可行实体集都装不下"时的下界，
	// 用于区分"降档就能解决"与"预算根本不够"。
	MinPossible uint32
}

func (e *OverBudgetError) Error() string {
	return fmt.Sprintf(
		"aperture over budget: estimated %d > budget %d at %s "+
			"(no truncation path exists — narrow the aperture or raise the budget)",
		e.Estimated, e.Budget, ProfileFor(e.Stop).Label)
}

// fitsBudget 判定估算是否在预算的安全线内（budget × 0.95）。
func fitsBudget(estimated, budget uint32) bool {
	if budget == 0 {
		return false // 零预算 = 不可装配（fail-closed）
	}
	return float64(estimated) <= float64(budget)*budgetSafetyRatio
}

// sortedKeys 返回按字典序排序的 map 键（确定性）。
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// 插入排序：属性表通常很小（< 20），避免引入 sort 依赖的开销。
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
