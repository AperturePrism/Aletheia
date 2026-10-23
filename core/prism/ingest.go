// Spectrum → 实体/关系的分解与多源写入（modules/M2 §4.3，T2.2/T2.3）。
//
// 分解规则（契约依据 05 §3.2 各实体必填属性 + M1 草稿键约定，
// 见 docs/iterations/I1-交接.md §3.4）：
//
//	nmap 产出的 SERVICE 草稿带 host_addr —— 推导 RUNS_ON 关系指向同
//	光谱内的 ASSET（addr == host_addr）。
//	去重：同 (kind, 全属性) 的实体复用既有 entity_id（新增 provenance，
//	不新增实体）——「多源冗余天然消解级联失败」（M2 §4.3）。
package prism

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// IngestResult 是一次摄入的结论（05 §3.3 IngestResult）。
type IngestResult struct {
	CreatedEntityIDs  []string
	UpdatedEntityIDs  []string // 既有实体新增版本（属性变化）
	ConflictEntityIDs []string
	ConflictTypes     map[string]string
}

// Ingest 把一份光谱分解写入地图（05 §3.3 PrismService.Ingest）。
//
// 幂等（M2 §6）：相同 spectrum_id 重复摄入直接返回空结果，无副作用。
// 多源（M2 §4.3）：同 kind 且「身份属性」相同 → 同一实体；属性值冲突 →
// 新增版本 + Conflict 记录（VALUE_MISMATCH），不覆盖不合并。
func (s *Store) Ingest(spectrum *alethv1.EvidenceSpectrum) (*IngestResult, error) {
	if spectrum == nil {
		return nil, fmt.Errorf("nil spectrum")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.spectrums[spectrum.SpectrumId] {
		return &IngestResult{}, nil // 幂等：重复摄入无副作用
	}
	s.spectrums[spectrum.SpectrumId] = true

	result := &IngestResult{ConflictTypes: map[string]string{}}
	now := s.clock.Now()

	// ---- 第一遍：ASSET（addr 是身份属性）----
	assets := map[string]string{} // addr → entity_id
	for _, d := range spectrum.Entities {
		if d.Kind != alethv1.EntityKind_ASSET {
			continue
		}
		addr := d.Attributes["addr"]
		if addr == "" {
			continue // 必填属性缺失：草稿不可转正（05 §3.2），跳过而非造残实体
		}
		// 全量草稿属性入图：addr 是身份键（identityKeys），os 等是内容键
		// —— 内容变化在同一实体上新增版本（M2 §4.3）。
		id := s.upsertEntity(d.Kind, draftAttrs(d.Attributes),
			d.ParserConfidence, spectrum, now, &result.CreatedEntityIDs, &result.UpdatedEntityIDs, &result.ConflictEntityIDs, result.ConflictTypes)
		assets[addr] = id
	}

	// ---- 第二遍：SERVICE（host_addr + port + protocol 是身份属性）----
	for _, d := range spectrum.Entities {
		if d.Kind != alethv1.EntityKind_SERVICE {
			continue
		}
		ident := serviceIdentity(d.Attributes)
		if ident == "" {
			continue // 缺身份键：草稿不完整，跳过
		}
		attrs := draftAttrs(d.Attributes, "host_addr", "port", "protocol")
		id := s.upsertEntity(d.Kind, attrs,
			d.ParserConfidence, spectrum, now, &result.CreatedEntityIDs, &result.UpdatedEntityIDs, &result.ConflictEntityIDs, result.ConflictTypes)
		// RUNS_ON 关系：host_addr 指向同光谱 ASSET（M2 R1 的关系推导）。
		if assetID, ok := assets[d.Attributes["host_addr"]]; ok && assetID != "" {
			s.linkRelation(assetID, id, "RUNS_ON", now)
		}
		_ = ident
	}
	return result, nil
}

// serviceIdentity 生成 SERVICE 实体的身份键（host_addr|port|protocol）。
func serviceIdentity(attrs map[string]string) string {
	parts := []string{attrs["host_addr"], attrs["port"], attrs["protocol"]}
	if anyEmpty(parts) {
		return ""
	}
	return strings.Join(parts, "|")
}

func anyEmpty(ss []string) bool {
	for _, s := range ss {
		if s == "" {
			return true
		}
	}
	return false
}

// draftAttrs 复制草稿属性（排除身份键本身由调用方决定是否写入——
// I4 保留全量草稿键，M2 §6 凭据安全扫描（Q5）在实体层同样适用）。
func draftAttrs(src map[string]string, _ ...string) map[string]string {
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// upsertEntity 是多源写入的核心（M2 §4.3）：
//   - 无既有实体 → 新建（version 1）
//   - 有既有实体且身份属性相同 → 属性一致则只加 provenance；冲突则新增版本
//   - Conflict（VALUE_MISMATCH），绝不覆盖
func (s *Store) upsertEntity(
	kind alethv1.EntityKind,
	attrs map[string]string,
	confidence float64,
	spectrum *alethv1.EvidenceSpectrum,
	now time.Time,
	created, updated, conflicted *[]string,
	conflictTypes map[string]string,
) string {
	id := entityIdentityID(kind, attrs)

	prov := provRec{SourceKind: sourceKindOf(spectrum).String()}
	if spectrum.Tool != nil {
		prov.EvidenceID = spectrum.SpectrumId
		prov.ExecID = spectrum.ExecId
	}
	prov.ObservedAt = now

	chain := s.versions[id]
	if len(chain) == 0 {
		s.versions[id] = []entityVersion{{
			attrs: attrs, kind: kind,
			validFrom: now, version: 1,
			confidence: confidence, branchID: "main",
		}}
		s.provenance[id] = append(s.provenance[id], prov)
		*created = append(*created, id)
		return id
	}

	// 多源写入：与当前版本比对属性。
	tail := chain[len(chain)-1]
	if sameAttrs(tail.attrs, attrs) {
		s.provenance[id] = append(s.provenance[id], prov) // 只加来源，不新增版本
		return id
	}

	// 属性冲突 → 新版本 + Conflict（不覆盖不合并，M2 §4.3）。
	version := tail.version + 1
	s.versions[id] = append(chain, entityVersion{
		attrs: attrs, kind: kind,
		validFrom: now, version: version,
		confidence: confidence, branchID: "main",
	})
	s.provenance[id] = append(s.provenance[id], prov)
	s.conflicts[id] = append(s.conflicts[id], Conflict{
		EntityID:         id,
		ConflictType:     "VALUE_MISMATCH",
		CompetingSources: s.provenance[id],
	})
	*updated = append(*updated, id)
	*conflicted = append(*conflicted, id)
	conflictTypes[id] = "VALUE_MISMATCH"
	return id
}

// linkRelation 建立（或复用）from --type--> to 的关系。
func (s *Store) linkRelation(from, to, relType string, now time.Time) {
	id := relationIdentityID(from, to, relType)
	for _, rv := range s.relations[id] {
		if rv.validTo == nil {
			return // 已存在且有效：复用
		}
	}
	s.relations[id] = append(s.relations[id], relationVersion{
		from: from, to: to, relType: relType, validFrom: now,
	})
}

// identityKeys 按 05 §3.2 的「必填属性」界定各类实体的**身份属性子集**：
// 身份属性参与实体 ID（同一身份 → 同一实体）；其余为内容属性，
// 内容变化在同一实体上新增版本（M2 §4.3 多源写入的语义基础）。
//
//	ASSET      → addr（主机身份）
//	SERVICE    → host_addr + port + protocol（服务端点身份）
//	IDENTITY   → kind(user/credential/…) + username
//	ENDPOINT   → url + method
//	DEFECT     → defect_type + location
//	其余 kind   → 全属性（I4 范围内未消费）
func identityKeys(kind alethv1.EntityKind) []string {
	switch kind {
	case alethv1.EntityKind_ASSET:
		return []string{"addr"}
	case alethv1.EntityKind_SERVICE:
		return []string{"host_addr", "port", "protocol"}
	case alethv1.EntityKind_IDENTITY:
		return []string{"kind", "username"}
	case alethv1.EntityKind_ENDPOINT:
		return []string{"url", "method"}
	case alethv1.EntityKind_DEFECT:
		return []string{"defect_type", "location"}
	default:
		return nil // nil = 全属性参与身份
	}
}

// entityIdentityID 由 (kind, 身份属性子集) 派生确定性实体 ID。
//
// 与 uuid7 契约（05 §1.1）的差异在此显式声明：多源写入要求
// 「同一身份属性 → 同一实体」的**内容寻址** ID —— 随机 uuid7 会把
// 两次独立扫描发现同一服务记成两个实体，破坏 M2 §4.3 的多源语义。
// map/ 迁移的 entity_id 列为 TEXT，两种形态均兼容。
func entityIdentityID(kind alethv1.EntityKind, attrs map[string]string) string {
	keys := identityKeys(kind)
	if keys == nil {
		keys = make([]string, 0, len(attrs))
		for k := range attrs {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "%d", int(kind))
	for _, k := range keys {
		fmt.Fprintf(&b, "|%s=%s", k, attrs[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "ent_" + hex.EncodeToString(sum[:12])
}

func relationIdentityID(from, to, relType string) string {
	sum := sha256.Sum256([]byte(relType + "|" + from + "|" + to))
	return "rel_" + hex.EncodeToString(sum[:12])
}

func sameAttrs(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// sourceKindOf 由光谱来源推导 provenance 的 SourceKind。
// I2 的光谱全部来自主动扫描工具（L0 Ingest）；被动流量/白盒/二进制
// 来源在 M7/I8 接入时扩展此映射。
func sourceKindOf(*alethv1.EvidenceSpectrum) alethv1.SourceKind {
	return alethv1.SourceKind_ACTIVE_SCAN
}
