package spectrum

import (
	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// Record 是折叠前的一条语义行记录：解析器对每条可识别的输出单元产出一条，
// OrigLineStart/End 回指原始输出的物理行号区间（05 §2.1 可追溯性要求）。
type Record struct {
	OrigLineStart uint32
	OrigLineEnd   uint32
	Template      string            // 折叠模板（如 "port {port}/{proto} {state}"）
	Vars          map[string]string // 模板变量
	FoldCount     uint32            // 被折叠的记录条数（1 = 未折叠，05 §2.1）
}

// varSep 是折叠组内多个取值的有序分隔符（ASCII 单元分隔符 0x1F）。
// 取值本身含 0x1F 的记录不参与折叠 —— 无损优先于压缩率。
const varSep = "\x1f"

// Fold 把**相邻**且满足以下全部条件的记录折叠为一条（M1 §4.4 无损折叠）：
//
//  1. Template 相同；
//  2. 行号连续（前一条 End+1 == 后一条 Start）—— 保证折叠后 [Start,End] 区间
//     与组内成员一一对应，可完整恢复；
//  3. 跨行宽度（span）相同 —— 同上，恢复行号需要等差结构；
//  4. 所有变量取值不含 varSep。
//
// 折叠结果：FoldCount = 组内条数；Vars 每键为按行序以 varSep 连接的取值列表。
// 不满足条件的记录原样保留（FoldCount=1）。
//
// 确定性（P-5）：顺序遍历 + 稳定分组，相同输入必得相同输出；不排序、不并行。
func Fold(recs []Record) []Record {
	out := make([]Record, 0, len(recs))
	// cur 是当前未 flush 的折叠组；nil 表示无未决组。
	var group []*Record
	flush := func() {
		if len(group) == 0 {
			return
		}
		merged := Record{
			OrigLineStart: group[0].OrigLineStart,
			OrigLineEnd:   group[len(group)-1].OrigLineEnd,
			Template:      group[0].Template,
			FoldCount:     uint32(len(group)),
		}
		if len(group) == 1 {
			merged.Vars = group[0].Vars
		} else if len(group[0].Vars) > 0 {
			vars := make(map[string]string, len(group[0].Vars))
			for k := range group[0].Vars {
				joined := make([]byte, 0, 64)
				for i, r := range group {
					if i > 0 {
						joined = append(joined, varSep...)
					}
					joined = append(joined, r.Vars[k]...)
				}
				vars[k] = string(joined)
			}
			merged.Vars = vars
		}
		out = append(out, merged)
		group = nil
	}
	foldable := func(a, b *Record) bool {
		if a.Template != b.Template ||
			a.OrigLineEnd+1 != b.OrigLineStart ||
			span(a) != span(b) ||
			len(a.Vars) != len(b.Vars) {
			return false
		}
		for k, v := range b.Vars {
			if _, ok := a.Vars[k]; !ok {
				return false
			}
			if containsUnitSep(v) {
				return false
			}
		}
		return true
	}
	for i := range recs {
		r := &recs[i]
		switch {
		case r.FoldCount > 1 || anySepIn(r.Vars):
			// 已折叠的记录不再参与二次折叠；取值含分隔符的记录永不入组
			//（无损优先：无法安全拆分的值链拒绝折叠）。
			flush()
			out = append(out, *r)
		case len(group) > 0 && foldable(group[len(group)-1], r):
			group = append(group, r)
		default:
			flush()
			group = []*Record{r}
		}
	}
	flush()
	return out
}

// ExpandFolded 把 Fold 的输出还原为未折叠记录序列。
//
// 这是无损性的直接证据：ExpandFolded(Fold(x)) 与 x 逐条相等（fold_test.go
// 的 round-trip 测试）。恢复依赖 Fold 的三个不变量：行号连续、组内 span 相同、
// Vars 取值列表长度 == FoldCount。
func ExpandFolded(folded []Record) []Record {
	out := make([]Record, 0, len(folded))
	for _, r := range folded {
		if r.FoldCount <= 1 {
			r.FoldCount = 1
			out = append(out, r)
			continue
		}
		total := span(&r)
		if total%int(r.FoldCount) != 0 { // 不变量被破坏：按契约 fail-closed，不做 best effort
			panic("spectrum: folded record violates fold invariants (span not divisible by fold_count)")
		}
		sp := total / int(r.FoldCount)
		for k := 0; k < int(r.FoldCount); k++ {
			m := Record{
				OrigLineStart: r.OrigLineStart + uint32(k*sp),
				OrigLineEnd:   r.OrigLineStart + uint32(k*sp+sp-1),
				Template:      r.Template,
				FoldCount:     1,
			}
			if len(r.Vars) > 0 {
				vars := make(map[string]string, len(r.Vars))
				for key, joined := range r.Vars {
					parts := splitVarList(joined)
					if len(parts) != int(r.FoldCount) {
						panic("spectrum: folded record violates fold invariants (var list length != fold_count)")
					}
					vars[key] = parts[k]
				}
				m.Vars = vars
			}
			out = append(out, m)
		}
	}
	return out
}

// LinesContaining 对「哪些原始行包含 X」给出行号区间列表（M1 §4.4 的
// 语义可查询性）。折叠前与折叠后的 Record 序列对同一查询必须给出相同结果 ——
// 该等价性由 fold_test.go 的语义等价测试在 10⁴ 行规模上验证（04 §I1 DoD③）。
func LinesContaining(recs []Record, key, value string) [][2]uint32 {
	var hits [][2]uint32
	for _, r := range recs {
		if r.FoldCount <= 1 {
			if r.Vars[key] == value {
				hits = append(hits, [2]uint32{r.OrigLineStart, r.OrigLineEnd})
			}
			continue
		}
		joined, ok := r.Vars[key]
		if !ok {
			continue
		}
		parts := splitVarList(joined)
		sp := span(&r) / int(r.FoldCount)
		for k, v := range parts {
			if v == value {
				hits = append(hits, [2]uint32{
					r.OrigLineStart + uint32(k*sp),
					r.OrigLineStart + uint32(k*sp+sp-1),
				})
			}
		}
	}
	return hits
}

// RecordsToLines 把记录转为 proto SpectrumLine（05 §2.1）。
// 未折叠记录的 FoldCount 显式补 1（proto 零值语义是 0，契约规定 1 = 未折叠）。
func RecordsToLines(recs []Record) []*alethv1.SpectrumLine {
	lines := make([]*alethv1.SpectrumLine, 0, len(recs))
	for _, r := range recs {
		fc := r.FoldCount
		if fc < 1 {
			fc = 1
		}
		lines = append(lines, &alethv1.SpectrumLine{
			OrigLineStart: r.OrigLineStart,
			OrigLineEnd:   r.OrigLineEnd,
			FoldCount:     fc,
			Template:      r.Template,
			Vars:          r.Vars,
		})
	}
	return lines
}

// LinesToRecords 是 RecordsToLines 的逆映射（Service 的 fold=off 调试开关用：
// 把已折叠的 SpectrumLine 还原为 Record，再走 ExpandFolded 展开）。
func LinesToRecords(lines []*alethv1.SpectrumLine) []Record {
	recs := make([]Record, 0, len(lines))
	for _, ln := range lines {
		if ln == nil {
			continue
		}
		recs = append(recs, Record{
			OrigLineStart: ln.GetOrigLineStart(),
			OrigLineEnd:   ln.GetOrigLineEnd(),
			Template:      ln.GetTemplate(),
			Vars:          ln.GetVars(),
			FoldCount:     ln.GetFoldCount(),
		})
	}
	return recs
}

func span(r *Record) int {
	if r.OrigLineEnd < r.OrigLineStart {
		return 0
	}
	return int(r.OrigLineEnd - r.OrigLineStart + 1)
}

func containsUnitSep(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1f {
			return true
		}
	}
	return false
}

func anySepIn(vars map[string]string) bool {
	for _, v := range vars {
		if containsUnitSep(v) {
			return true
		}
	}
	return false
}

func splitVarList(joined string) []string {
	if joined == "" {
		return nil
	}
	var parts []string
	start := 0
	for i := 0; i < len(joined); i++ {
		if joined[i] == 0x1f {
			parts = append(parts, joined[start:i])
			start = i + 1
		}
	}
	parts = append(parts, joined[start:])
	return parts
}
