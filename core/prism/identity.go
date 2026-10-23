package prism

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// 本文件实现 M2 §2.1 R1：光谱 → 实体/关系的分解（T2.2）。
//
// # 设计原则
//
// 分解是**纯函数**（无 IO、无时间、无随机）—— 相同光谱必得相同实体集。
// 时间戳由 Store 在写入时统一赋值（M2 §8：禁止应用层自行生成时间戳），
// 因此分解产出的 Entity 不带 valid_from。
//
// # 实体身份（entity_id）的确定
//
// entity_id 必须**确定性**且**跨来源稳定** —— 同一台主机由 nmap 和 httpx
// 分别发现时必须落到同一个 entity_id，否则多源关联（M2 §4.3）无从谈起。
//
// 采用「kind + 规范业务键」派生：`<kind前缀>_<sha256(canonical-key)[:16]>`。
// 不采用「自增 ID」或「随机 UUID」：前者跨进程不稳定，后者让同一实体在
// 两次分解中得到不同 ID，破坏幂等与回放。
//
// 规范业务键按实体类型定义（见 identityKey）：
//
//	ASSET    → addr（归一化后的 IP/网段/域名）
//	SERVICE  → asset + protocol + port
//	ENDPOINT → url
//	IDENTITY → identifier（用户名/凭据标识）
//	DEFECT   → asset/service + defect_type + location
//	PATH     → 有序跳序列
//	TIMELINE → event time + actor + action

// 实体 ID 前缀（05 §1.1 的标识约定风格：类型前缀 + 稳定派生）。
const (
	prefixAsset    = "as_"
	prefixService  = "sv_"
	prefixIdentity = "id_"
	prefixEndpoint = "ep_"
	prefixDefect   = "df_"
	prefixPath     = "pa_"
	prefixTimeline = "tl_"
	prefixRelation = "rl_"
)

// kindPrefix 返回实体类型对应的 ID 前缀。
func kindPrefix(kind alethv1.EntityKind) string {
	switch kind {
	case alethv1.EntityKind_ASSET:
		return prefixAsset
	case alethv1.EntityKind_SERVICE:
		return prefixService
	case alethv1.EntityKind_IDENTITY:
		return prefixIdentity
	case alethv1.EntityKind_ENDPOINT:
		return prefixEndpoint
	case alethv1.EntityKind_DEFECT:
		return prefixDefect
	case alethv1.EntityKind_PATH:
		return prefixPath
	case alethv1.EntityKind_TIMELINE:
		return prefixTimeline
	default:
		return "xx_"
	}
}

// identityKey 从草稿属性导出「规范业务键」。
//
// 返回空串表示该草稿**缺少构成身份的必要属性** —— 此时拒绝入库并计入
// 分解警告，而不是用随机值兜底（那会让同一实体每次得到不同 ID）。
func identityKey(kind alethv1.EntityKind, attrs map[string]string) string {
	get := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := attrs[k]; ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	switch kind {
	case alethv1.EntityKind_ASSET:
		// nmap 用 addr；httpx 的 A 记录草稿也用 addr。
		return strings.ToLower(get("addr", "address", "host", "ip"))
	case alethv1.EntityKind_SERVICE:
		asset := strings.ToLower(get("addr", "address", "host", "ip", "asset"))
		port := get("port", "portid")
		proto := strings.ToLower(get("protocol", "proto"))
		if asset == "" || port == "" {
			return ""
		}
		return asset + "|" + proto + "|" + port
	case alethv1.EntityKind_ENDPOINT:
		return strings.ToLower(get("url", "path", "endpoint"))
	case alethv1.EntityKind_IDENTITY:
		return strings.ToLower(get("identifier", "username", "user", "principal", "credential_ref"))
	case alethv1.EntityKind_DEFECT:
		// 缺陷身份 = 载体 + 类型 + 位置。载体可为 asset 或 service。
		carrier := strings.ToLower(get("addr", "host", "url", "asset"))
		dtype := get("defect_type", "template_id", "type", "id")
		loc := get("matched", "location", "port", "path")
		if carrier == "" || dtype == "" {
			return ""
		}
		return carrier + "|" + dtype + "|" + loc
	case alethv1.EntityKind_PATH:
		hops := get("hops", "path")
		if hops == "" {
			return ""
		}
		return hops
	case alethv1.EntityKind_TIMELINE:
		// 事件身份 = 时间 + 主体 + 动作。
		ts := get("at", "timestamp", "time")
		actor := strings.ToLower(get("actor", "host", "addr"))
		action := get("action", "event")
		if ts == "" || action == "" {
			return ""
		}
		return ts + "|" + actor + "|" + action
	}
	return ""
}

// EntityID 由 (kind, 规范业务键) 确定性派生实体 ID。
//
// 同一台主机被 nmap 与 httpx 分别发现时，两者的 ASSET 草稿都给出
// addr=10.40.23.5 → identityKey 相同 → entity_id 相同 → 多源写入
// 落到同一实体的不同版本（M2 §4.3）。这是"多源冗余消解级联失败"的前提。
//
// 第二个返回值 ok=false 表示草稿缺少构成身份的必要属性，调用方
// 应拒绝入库并记警告（不得用随机值兜底）。
func EntityID(kind alethv1.EntityKind, attrs map[string]string) (string, bool) {
	key := identityKey(kind, attrs)
	if key == "" {
		return "", false
	}
	return kindPrefix(kind) + shortHash(kind.String()+"\x00"+key), true
}

// RelationID 由 (类型, from, to, 限定属性) 确定性派生关系 ID。
//
// 关系也必须去重：同一路径被两次扫描同时发现时不应产生两条关系。
// 把 attributes 纳入派生键是为了让"同一对端点上的不同关系属性"
// 保持区分（如 BELONGS_TO 带不同 method）。
func RelationID(rt alethv1.RelationType, from, to string, attrs map[string]string) string {
	return prefixRelation + shortHash(
		rt.String()+"\x00"+from+"\x00"+to+"\x00"+canonicalAttrs(attrs))
}

// shortHash 取规范输入的 sha256 前 8 字节（16 hex 字符）。
// 长度足以在实际规模下避免碰撞，且 ID 保持可读（类型前缀 + 16 字符）。
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// ---- 分解器（T2.2）----

// DecomposeResult 是一次分解的产物与统计。
type DecomposeResult struct {
	// Entities 是分解出的实体（已按 kind 派生确定性 ID）。
	Entities []*alethv1.Entity
	// Relations 是分解出的关系（CONTRADICTS 之外的结构关系）。
	Relations []*alethv1.Relation
	// Skipped 记录因缺少必要属性而无法定身份的草稿数（可审计，不静默丢弃）。
	SkippedDrafts int
	// Warnings 是分解过程中的显式告警。
	Warnings []string
}

// Decompose 把一条光谱分解为实体与关系（M2 §2.1 R1，纯函数）。
//
// 确定性保证：相同光谱（含相同 spectrum_id / exec_id / observed_at）
// 必得字节级相同的 Entities/Relations 序列。实现上：
//   - 输入草稿按派生 ID 排序（不依赖 proto 里的顺序）；
//   - 属性的规范化在 EntityID / canonicalAttrs 中完成；
//   - 不读取任何时钟或随机源。
//
// 关系抽取（当前覆盖解析器实际产出的结构）：
//
//	SERVICE  → RUNS_ON       → ASSET（由 SERVICE 的 addr 属性定位宿主）
//	ENDPOINT → BELONGS_TO    → ASSET/SERVICE（由 url 的 host/port 定位）
//	DEFECT   → LOCATED_IN    → ASSET/SERVICE（由载体属性定位）
//	ASSET    → RESOLVES_TO   → ASSET（域名的 A 记录地址）
//
// 关系目标不存在时**不臆造实体**：只保留关系意图为警告，因为
// "没有证据支撑的实体"正是本项目要防的幻觉（M3 §4 / 05 §0 C2）。
func Decompose(sp *alethv1.EvidenceSpectrum) DecomposeResult {
	var res DecomposeResult
	if sp == nil {
		res.Warnings = append(res.Warnings, "nil spectrum; nothing to decompose")
		return res
	}

	// 第一步：草稿 → 实体（按派生 ID 去重，保留首个；同源重复草稿无意义）。
	byID := make(map[string]*alethv1.Entity)
	for _, d := range sp.GetEntities() {
		if d.GetKind() == alethv1.EntityKind_ENTITY_KIND_UNSPECIFIED {
			res.SkippedDrafts++
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("draft at line %d has unspecified kind; skipped", d.GetSourceLine()))
			continue
		}
		id, ok := EntityID(d.GetKind(), d.GetAttributes())
		if !ok {
			res.SkippedDrafts++
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"draft %s at line %d lacks identity attributes; skipped (no fabricated ID)",
				d.GetKind(), d.GetSourceLine()))
			continue
		}
		if _, dup := byID[id]; dup {
			continue // 同一条光谱内的重复观测不产生第二份实体
		}
		byID[id] = &alethv1.Entity{
			EntityId:   id,
			Kind:       d.GetKind(),
			Attributes: d.GetAttributes(),
			Confidence: d.GetParserConfidence(),
			// 时间与版本由 Store 赋值（M2 §8）。
			Sources: []*alethv1.Provenance{{
				SourceKind: alethv1.SourceKind_ACTIVE_SCAN,
				EvidenceId: sp.GetSpectrumId(),
				ExecId:     sp.GetExecId(),
				ObservedAt: sp.GetObservedAt(),
			}},
		}
	}

	// 第二步：抽取关系。需要「属性 → 实体 ID」索引来定位端点。
	index := newEntityIndex(byID)

	for _, e := range byID {
		switch e.GetKind() {
		case alethv1.EntityKind_SERVICE:
			if host := assetIDFor(e.GetAttributes(), index); host != "" && host != e.GetEntityId() {
				res.Relations = append(res.Relations, newRelation(
					alethv1.RelationType_RUNS_ON, e.GetEntityId(), host, e, nil))
			}
		case alethv1.EntityKind_ENDPOINT:
			if host := assetIDFor(e.GetAttributes(), index); host != "" && host != e.GetEntityId() {
				res.Relations = append(res.Relations, newRelation(
					alethv1.RelationType_BELONGS_TO, e.GetEntityId(), host, e, nil))
			}
		case alethv1.EntityKind_DEFECT:
			if host := assetIDFor(e.GetAttributes(), index); host != "" && host != e.GetEntityId() {
				res.Relations = append(res.Relations, newRelation(
					alethv1.RelationType_LOCATED_IN, e.GetEntityId(), host, e, nil))
			}
		case alethv1.EntityKind_ASSET:
			// 域名资产解析到 IP 资产（httpx 的 a 记录草稿）。
			if resolved := resolvedAssetID(e.GetAttributes(), index); resolved != "" {
				res.Relations = append(res.Relations, newRelation(
					alethv1.RelationType_RESOLVES_TO, e.GetEntityId(), resolved, e, nil))
			}
		}
	}

	// 第三步：确定性排序（不依赖 map 迭代顺序 —— 这是 Q6/P-5 的要求）。
	res.Entities = sortedEntities(byID)
	sort.Slice(res.Relations, func(i, j int) bool {
		if res.Relations[i].GetRelationId() != res.Relations[j].GetRelationId() {
			return res.Relations[i].GetRelationId() < res.Relations[j].GetRelationId()
		}
		return res.Relations[i].GetType() < res.Relations[j].GetType()
	})
	return res
}

// newRelation 构造带确定性 ID 的关系。
func newRelation(
	rt alethv1.RelationType, from, to string, src *alethv1.Entity, attrs map[string]string,
) *alethv1.Relation {
	return &alethv1.Relation{
		RelationId: RelationID(rt, from, to, attrs),
		FromEntity: from,
		ToEntity:   to,
		Type:       rt,
		Attributes: attrs,
		Confidence: src.GetConfidence(),
		EvidenceId: firstEvidenceID(src),
		ValidFrom:  src.GetValidFrom(), // 由 Store 在写入时统一赋值
	}
}

// firstEvidenceID 取实体的第一条来源证据 ID。
func firstEvidenceID(e *alethv1.Entity) string {
	if srcs := e.GetSources(); len(srcs) > 0 {
		return srcs[0].GetEvidenceId()
	}
	return ""
}

// sortedEntities 按 entity_id 排序实体（确定性输出顺序）。
func sortedEntities(m map[string]*alethv1.Entity) []*alethv1.Entity {
	out := make([]*alethv1.Entity, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetEntityId() < out[j].GetEntityId() })
	return out
}

// entityIndex 支持「按属性值反查已存在的实体」。
type entityIndex struct {
	byKindAddr map[string]string // kind|addr → entity_id
}

func newEntityIndex(byID map[string]*alethv1.Entity) *entityIndex {
	ix := &entityIndex{byKindAddr: make(map[string]string)}
	for _, e := range byID {
		for _, key := range []string{"addr", "address", "host", "ip"} {
			if v := e.GetAttributes()[key]; v != "" {
				ix.byKindAddr[fmt.Sprintf("%d|%s", e.GetKind(), strings.ToLower(v))] = e.GetEntityId()
			}
		}
		if u := e.GetAttributes()["url"]; u != "" {
			// 端点也登记其 host，供 DEFECT/ENDPOINT 定位载体。
			if h := hostOf(u); h != "" {
				ix.byKindAddr[fmt.Sprintf("%d|%s", e.GetKind(), h)] = e.GetEntityId()
			}
		}
	}
	return ix
}

// assetIDFor 找到该实体的宿主资产 ID。
//
// 查找顺序（从具体到一般）：
//  1. 属性里的 addr/host 直接命中 ASSET/SERVICE；
//  2. url 属性里的 host 命中；
//  3. 兜底：用 (ASSET, addr) 重新派生 ID（宿主可能未被本条光谱写入 ——
//     此时仍然给出确定性 ID，让跨光谱的关系得以在写入时连上）。
func assetIDFor(attrs map[string]string, ix *entityIndex) string {
	for _, key := range []string{"addr", "address", "host", "ip", "asset"} {
		if v := attrs[key]; v != "" {
			v = strings.ToLower(strings.TrimSpace(v))
			for _, kind := range []alethv1.EntityKind{
				alethv1.EntityKind_ASSET, alethv1.EntityKind_SERVICE} {
				if id, ok := ix.byKindAddr[fmt.Sprintf("%d|%s", kind, v)]; ok {
					return id
				}
			}
			if id, ok := EntityID(alethv1.EntityKind_ASSET, map[string]string{"addr": v}); ok {
				return id
			}
		}
	}
	for _, key := range []string{"url", "endpoint"} {
		if v := attrs[key]; v != "" {
			if h := hostOf(v); h != "" {
				if id, ok := EntityID(alethv1.EntityKind_ASSET, map[string]string{"addr": h}); ok {
					return id
				}
			}
		}
	}
	return ""
}

// resolvedAssetID 找到域名资产解析到的 IP 资产。
func resolvedAssetID(attrs map[string]string, ix *entityIndex) string {
	ip := strings.ToLower(strings.TrimSpace(attrs["resolved_to"]))
	if ip == "" {
		return ""
	}
	if id, ok := ix.byKindAddr[fmt.Sprintf("%d|%s", alethv1.EntityKind_ASSET, ip)]; ok {
		return id
	}
	if id, ok := EntityID(alethv1.EntityKind_ASSET, map[string]string{"addr": ip}); ok {
		return id
	}
	return ""
}

// hostOf 从 URL 里取 host（不引入 net/url 依赖的轻量实现，
// 且必须与 scopekernel 的取法一致：userinfo 不参与）。
func hostOf(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:] // 剥离 userinfo
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s[i+1:], "]") {
		if _, err := strconv.Atoi(s[i+1:]); err == nil {
			s = s[:i]
		}
	}
	return strings.ToLower(strings.Trim(s, "[]"))
}
