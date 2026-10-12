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

// ---- 连续调节（M3 §7 DoD："三档光圈 + 连续调节可用"）----

// Overrides 是光圈参数的连续调节层（M3 §4.1 的三个轴）。
//
// # 为什么"连续调节"是必要的，而不只是锦上添花
//
// 三档之间的跨度很大 —— f/1.4 是 200 实体/1 跳，f/16 是 10 实体/3 跳。
// 一个任务常常落在两档之间：需要 3 跳但不需要 10 个实体的深度，
// 或者需要 40 个实体但只需要 1 跳。
//
// 若只有三档，调用方只能"向上取档"（浪费预算）或"向下取档"（丢信息）。
// M3 §4.1 把"恒定曝光"定为**硬约束**（不是优化目标），
// 而硬约束下的最优解往往不在档位点上 —— 因此需要连续轴。
//
// # 语义：覆盖而非替代
//
// zero value（全部字段为 0）表示"不覆盖"，沿用档位值。
// 这与 protobuf 的"未设置 = 默认值"惯例一致，也让"三档"仍是主入口。
//
// # 边界：三条轴必须单调
//
// 调节**必须保持光圈的物理语义**：开大孔径 = 宽而浅。
// 因此不允许"max_entities 调到 200 同时 max_hops 调到 3"这类
// 破坏语义的组合 —— 那会让"恒定曝光"的预算约束失效。
// `Normalize` 负责校验并拒绝这类组合。
type Overrides struct {
	// MaxHops 覆盖图遍历跳数（0 = 不覆盖）。
	MaxHops uint32
	// MaxEntities 覆盖实体数上限（0 = 不覆盖）。
	MaxEntities uint32
	// DepthPerEntity 覆盖每实体属性深度（0 = 不覆盖）。
	DepthPerEntity uint32
}

// IsZero 报告是否未设置任何覆盖。
func (o Overrides) IsZero() bool {
	return o.MaxHops == 0 && o.MaxEntities == 0 && o.DepthPerEntity == 0
}

// Apply 把覆盖应用到档位参数上，并返回结果。
//
// 违反物理语义时返回错误（**不静默接受**）—— 见 Overrides 的说明。
func (o Overrides) Apply(base StopProfile) (StopProfile, error) {
	if o.IsZero() {
		return base, nil
	}
	out := base
	if o.MaxHops > 0 {
		out.MaxHops = o.MaxHops
	}
	if o.MaxEntities > 0 {
		out.MaxEntities = o.MaxEntities
	}
	if o.DepthPerEntity > 0 {
		out.DepthPerEntity = o.DepthPerEntity
	}
	if err := validateApertureSemantics(out); err != nil {
		return base, err
	}
	// 标记为"已调节"，让审计能区分"用了档位值"与"连续调节过"。
	out.Label = fmt.Sprintf("%s~（连续调节）", base.Label)
	out.Semantics = base.Semantics + "；参数经连续调节"
	return out, nil
}

// validateApertureSemantics 校验调节后的参数是否仍满足光圈的物理语义。
//
// 判据取自 M3 §4.1 表格的三档数据 —— 它们界定了合法区域的顶点：
//
//	宽而浅：max_hops 小 ↔ max_entities 大
//	窄而深：max_hops 大 ↔ max_entities 小
//
// 因此"深且宽"（hops 大 且 entities 大）是非法的：它同时要覆盖广度与
// 深度，会突破"恒定曝光"的硬预算约束（M3 §4.1 原文：
// "光圈开大必须别处关小"）。
//
// 具体阈值：以档位表的最大乘积为界。最宽的组合是 f/1.4
// （1×200=200），最常见的组合是 f/4（2×60=120）。这里取
// `max_hops × max_entities ≤ 200` 作为恒曝光上界 —— 它是表格里
// 三档的**最大值**，因此不会拒绝任何原有档位。
func validateApertureSemantics(p StopProfile) error {
	const exposureLimit = 200 // f/1.4 的 1×200，三档中的最大值
	if p.MaxHops == 0 || p.MaxEntities == 0 {
		return fmt.Errorf(
			"aperture: max_hops and max_entities must be non-zero (got hops=%d entities=%d)",
			p.MaxHops, p.MaxEntities)
	}
	if product := p.MaxHops * p.MaxEntities; product > exposureLimit {
		return fmt.Errorf(
			"aperture: max_hops(%d) × max_entities(%d) = %d exceeds the constant-exposure "+
				"limit %d — widening the aperture must narrow something else (M3 §4.1)",
			p.MaxHops, p.MaxEntities, product, exposureLimit)
	}
	if p.DepthPerEntity == 0 {
		return fmt.Errorf("aperture: depth_per_entity must be non-zero")
	}
	return nil
}

// Interpolate 在相邻两档之间线性插值（连续调节的便捷入口）。
//
// `t` ∈ [0,1]：0 = 取 `from` 档，1 = 取 `to` 档。
//
// # 为什么是"相邻两档"而不是任意档位
//
// 光圈是从大到小的**有序**序列；在 f/1.4 与 f/16 之间插值会跳过 f/4
// 的语义。要求相邻可让调用方的意图明确（"比 f/4 再收一点"），
// 也让插值结果始终落在合法区域内。
//
// 非相邻档位返回错误 —— 与"不静默接受非法输入"一致。
func Interpolate(from, to alethv1.ApertureSetting_Stop, t float64) (Overrides, error) {
	if t < 0 || t > 1 {
		return Overrides{}, fmt.Errorf("aperture: interpolation t must be in [0,1], got %v", t)
	}
	a, b := ProfileFor(from), ProfileFor(to)
	// 相邻判定：档位序号相差 1（stopOrder 是内部有序函数）。
	if d := stopOrder(a.Stop) - stopOrder(b.Stop); d != 1 && d != -1 {
		return Overrides{}, fmt.Errorf(
			"aperture: interpolation requires adjacent stops, got %s and %s "+
				"(interpolating across a stop would skip its semantics)",
			a.Label, b.Label)
	}
	lerp := func(x, y uint32) uint32 {
		v := float64(x) + (float64(y)-float64(x))*t
		// **四舍五入而非截断**：截断会让 t<1 的中点在多数情况下等于
		// `from` 档（如 hops 2→3 时 t=0.5 得 2.5，截断成 2），
		// 于是"连续调节"在小跨度轴上退化成"只有档位值"。
		// 四舍五入保证 t≥0.5 时至少走到 y 的方向。
		out := uint32(v + 0.5)
		if out < 1 {
			return 1 // 不允许归零（归零即"无上下文"，会被校验拒绝）
		}
		return out
	}
	return Overrides{
		MaxHops:        lerp(a.MaxHops, b.MaxHops),
		MaxEntities:    lerp(a.MaxEntities, b.MaxEntities),
		DepthPerEntity: lerp(a.DepthPerEntity, b.DepthPerEntity),
	}, nil
}

// ProfileFor 返回档位参数。未指定档位时返回默认档。
func ProfileFor(stop alethv1.ApertureSetting_Stop) StopProfile {
	if p, ok := profiles[stop]; ok {
		return p
	}
	return profiles[DefaultStop]
}

// SettingFor 构造契约的 ApertureSetting。
func SettingFor(stop alethv1.ApertureSetting_Stop) *alethv1.ApertureSetting {
	return settingFromProfile(ProfileFor(stop))
}

// settingFromProfile 把**已解析的**档位参数转成契约消息。
//
// 与 `SettingFor` 的区别：后者总是从档位名重新解析档案，因此**无法表达
// 连续调节后的参数**。装配路径必须用本函数 —— 否则
// `bundle.aperture` 会记成档位原值，而实际装配用的是调节后的值，
// 审计信息就是错的（"审计说 A、实际做 B"）。
func settingFromProfile(p StopProfile) *alethv1.ApertureSetting {
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
