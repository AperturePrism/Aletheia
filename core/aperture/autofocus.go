package aperture

import (
	"strings"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// 本文件实现 M3 §4.2 Autofocus（T3.2）与 §4.3 关系权重（T3.3）。
//
// # 为什么 Autofocus 是本模块最脆弱的一环
//
// 它依赖"任务描述里命名了实体"。M3 §8 的风险栏明确指出缓解方式是
// 「要求 Planner（M5）在生成任务时输出结构化 target_entity_hints，
// 而非仅自然语言」。本实现同时支持两条入口：
//
//  1. 结构化 hints（首选，来自 M5 的 target_entity_hints）；
//  2. 从自然语言 objective/hypothesis 里抽取（兜底，能力有限且诚实标注）。
//
// 第二条的抽取能力刻意**保守**：宁可少抽（漏掉焦点导致投影偏小，
// 由 relation 游走部分补偿）也不误抽（错误的焦点会让整个上下文跑偏）。

// RelationWeights 是 M3 §4.3 的关系权重表。
//
// 数值直接取自规格，不做"优化" —— 它们编码了领域知识：
// 凭据链（AUTHENTICATES_TO 0.9）与冲突（CONTRADICTS 0.85）之所以权重高，
// 是因为前者直击 D6 跨阶段传递失败、后者是本项目"冲突矩阵"的价值来源。
var RelationWeights = map[alethv1.RelationType]float64{
	alethv1.RelationType_EXPLOITED_BY:     1.0,
	alethv1.RelationType_AUTHENTICATES_TO: 0.9,
	alethv1.RelationType_CONTRADICTS:      0.85,
	alethv1.RelationType_REQUIRES:         0.8,
	alethv1.RelationType_ENABLES:          0.8,
	alethv1.RelationType_EXPOSES:          0.7,
	alethv1.RelationType_CORROBORATES:     0.6,
	alethv1.RelationType_RUNS_ON:          0.5,
	alethv1.RelationType_RESOLVES_TO:      0.5,
	alethv1.RelationType_BELONGS_TO:       0.4,
	alethv1.RelationType_PRECEDED_BY:      0.3,
}

// RelationWeight 返回关系类型的权重；未登记类型给保守的最低权重。
//
// 为什么给最低而非 0：未登记的关系类型仍可能承载信息（如 INVOKES、
// LOCATED_IN、HAS_PRIVILEGE）。给 0 会让它们完全无法把实体带进上下文，
// 而 M3 的核心目标是**召回**——漏掉线索的代价远高于多带几个实体。
func RelationWeight(rt alethv1.RelationType) float64 {
	if w, ok := RelationWeights[rt]; ok {
		return w
	}
	return 0.25
}

// ScoreWeights 是 M3 §4.2 步骤 3 的打分权重。
type ScoreWeights struct {
	DirectRef   float64 // w_ref
	HopDecay    float64 // w_hop
	RelStrength float64 // w_rel
	Confidence  float64 // w_conf
	Recency     float64 // w_rec
	Conflict    float64 // w_conflict
}

// DefaultWeights 是 M3 §4.2 的默认权重（原文数值）。
func DefaultWeights() ScoreWeights {
	return ScoreWeights{
		DirectRef:   1.0,
		HopDecay:    0.5,
		RelStrength: 0.3,
		Confidence:  0.4,
		Recency:     0.2,
		Conflict:    0.6,
	}
}

// conflictCap 是冲突实体的注入数量上限（M3 §8 风险缓解：
// 「冲突实体设数量上限（默认 5），超出部分只给 ID 摘要」）。
const conflictCap = 5

// scoreCandidate 是打分过程中的一个候选实体及其依据。
type scoreCandidate struct {
	entity *alethv1.Entity
	score  float64
	// hop 是距种子实体的跳数（0 = 直接引用）。
	hop int
	// reasons 记录打分依据（M3 §3.1 R5 可审计性要求）。
	reasons []string
}

// scoreEntities 对候选实体打分（M3 §4.2 步骤 3）。
//
// score(e) = w_ref·is_direct_ref
//
//   - w_hop·hop_decay(distance)
//   - w_rel·max(relation_weight(path))
//   - w_conf·confidence
//   - w_rec·recency
//   - w_conflict·is_in_conflict
//
// 所有输入都来自已排序的切片，因此结果确定（P-5 / Q6）。
func scoreEntities(
	cands []*candidateEntity, seeds map[string]bool, conflictSet map[string]bool,
	now int64, w ScoreWeights,
) []scoreCandidate {
	out := make([]scoreCandidate, 0, len(cands))
	for _, c := range cands {
		var (
			score   float64
			reasons []string
		)
		if seeds[c.entity.GetEntityId()] {
			score += w.DirectRef
			reasons = append(reasons, "direct reference in task objective/hypothesis")
		}
		// hop_decay：线性衰减（距离 0 → 1.0，越远越小，下限 0）。
		decay := 1.0 - float64(c.hop)/4.0
		if decay < 0 {
			decay = 0
		}
		score += w.HopDecay * decay
		if c.hop > 0 {
			reasons = append(reasons, "reachable within aperture hops")
		}
		score += w.RelStrength * c.maxRelationWeight
		if c.maxRelationWeight > 0 {
			reasons = append(reasons, "linked via weighted relation")
		}
		score += w.Confidence * c.entity.GetConfidence()
		// recency：越新越高。用 1/(1+小时数) 而非线性 ——
		// 线性会让 1 小时与 100 小时的差别压过其他维度。
		score += w.Recency * recencyFactor(c.latestObservedAt, now)
		if conflictSet[c.entity.GetEntityId()] {
			score += w.Conflict
			reasons = append(reasons, "entity has conflicting versions (high-value signal)")
		}
		out = append(out, scoreCandidate{entity: c.entity, score: score, hop: c.hop, reasons: reasons})
	}
	return out
}

// recencyFactor 把观测时间折算为 0..1 的新鲜度。
func recencyFactor(observedAt, now int64) float64 {
	if observedAt == 0 || now == 0 {
		return 0
	}
	hours := float64(now-observedAt) / 3.6e12 // 纳秒 → 小时
	if hours <= 0 {
		return 1.0
	}
	return 1.0 / (1.0 + hours)
}

// candidateEntity 是游走收集到的候选。
type candidateEntity struct {
	entity            *alethv1.Entity
	hop               int
	maxRelationWeight float64
	latestObservedAt  int64
}

// ExtractEntityHints 从自然语言中抽取可能的实体引用（M3 §4.2 步骤 1 的兜底）。
//
// 抽取目标（沿用解析器实际产出的属性形态）：
//   - IPv4 地址与 CIDR
//   - 域名 / 主机名
//   - URL
//   - 端口（形如 8080/tcp 或 :8080）
//
// **刻意保守**：宁可少抽也不误抽。误抽的焦点会让整个上下文跑偏，
// 而少抽只让投影偏小（relation 游走会带回邻域）。
//
// 返回去重后的 token 集合（小写），供与实体属性做包含匹配。
func ExtractEntityHints(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.Trim(s, ".,;:()[]{}<>\"'`")
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	for _, field := range strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ',' || r == ';'
	}) {
		tok := strings.Trim(field, ".,;:()[]{}<>\"'`")
		if tok == "" {
			continue
		}
		// URL：取 host（与 scopekernel/ingest 的取法一致 —— userinfo 不参与）。
		if strings.Contains(tok, "://") {
			add(tok)
			if h := hostOfToken(tok); h != "" {
				add(h)
			}
			continue
		}
		// CIDR：形如 10.40.23.0/24 —— 前缀合法时**整体**作为提示。
		// 不能只取 "/" 之前的部分：那会让提示退化为单个 IP，匹配不到
		// 以 CIDR 为属性的实体，反而引入假阳性。
		if i := strings.Index(tok, "/"); i > 0 {
			prefix, mask := tok[:i], tok[i+1:]
			if allDigits(mask) && looksLikeIP(prefix) {
				add(tok) // CIDR 整体
				continue
			}
			// 形如 8080/tcp：端口号本身作为提示。
			if allDigits(prefix) {
				add(prefix)
				continue
			}
		}
		if looksLikeHostOrIP(tok) {
			add(tok)
		}
		if h, _, ok := splitHostPort(tok); ok {
			add(h)
		}
	}
	return out
}

// looksLikeIP 判定字符串是否为点分十进制 IPv4 形态。
func looksLikeIP(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 || !allDigits(p) {
			return false
		}
	}
	return true
}

// looksLikeHostOrIP 判定 token 是否像主机名/IP（不是任意英文单词）。
// 判定标准：含点且点两侧非空、或全为数字（十进制 IP 形态）。
// 单标签主机名（如 "localhost"）刻意不抽 —— 误抽率太高。
func looksLikeHostOrIP(tok string) bool {
	if tok == "" {
		return false
	}
	if allDigitsOrDots(tok) && strings.Contains(tok, ".") {
		return true
	}
	// 域名：至少一个点，且点两侧是字母数字/连字符。
	idx := strings.IndexByte(tok, '.')
	if idx <= 0 || idx == len(tok)-1 {
		return false
	}
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		ok := c == '.' || c == '-' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// hostOfToken 从 URL token 取 host。
func hostOfToken(tok string) string {
	s := tok
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if h, _, ok := splitHostPort(s); ok {
		return h
	}
	return s
}

// splitHostPort 拆分 host:port（与 scopekernel 的语义一致：最后一段是数字才是端口）。
func splitHostPort(s string) (host, port string, ok bool) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, "", false
	}
	candidate := s[i+1:]
	if candidate == "" || !allDigits(candidate) {
		return s, "", false
	}
	return s[:i], candidate, true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func allDigitsOrDots(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && s[i] != '.' {
			return false
		}
	}
	return true
}

// entityMatchesHint 判定实体是否匹配某个 hint。
//
// 匹配面覆盖实体属性的常见标识字段（addr/url/host/ip/port/service/
// identifier），与 core/prism 的 identityKey 使用同一组字段名 ——
// 两侧字段名不一致会让 Autofocus 永远匹配不到实体（静默失效）。
func entityMatchesHint(e *alethv1.Entity, hints []string) bool {
	if len(hints) == 0 {
		return false
	}
	attrs := e.GetAttributes()
	// 收集该实体的可匹配文本。
	var fields []string
	for _, k := range []string{"addr", "address", "host", "ip", "url", "endpoint",
		"service", "identifier", "username", "port", "defect_type", "path", "template_id"} {
		if v, ok := attrs[k]; ok && v != "" {
			fields = append(fields, strings.ToLower(v))
		}
	}
	// 实体 ID 也参与（允许任务直接引用 ID）。
	fields = append(fields, strings.ToLower(e.GetEntityId()))

	for _, h := range hints {
		for _, f := range fields {
			if f == h {
				return true
			}
			// 包含匹配：URL 里含 host、host 含端口等形式。
			if strings.Contains(f, h) || strings.Contains(h, f) {
				return true
			}
		}
	}
	return false
}
