package spectrum

import (
	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
	"math/rand"
	"reflect"
	"testing"
)

func rec(start, end uint32, template string, vars map[string]string) Record {
	return Record{OrigLineStart: start, OrigLineEnd: end, Template: template, Vars: vars, FoldCount: 1}
}

func TestFoldAdjacentSameTemplate(t *testing.T) {
	in := []Record{
		rec(1, 1, "port {port}/{proto} {state}", map[string]string{"port": "80", "proto": "tcp", "state": "open"}),
		rec(2, 2, "port {port}/{proto} {state}", map[string]string{"port": "443", "proto": "tcp", "state": "open"}),
		rec(3, 3, "port {port}/{proto} {state}", map[string]string{"port": "8080", "proto": "tcp", "state": "open"}),
		rec(4, 4, "host {addr} up", map[string]string{"addr": "192.0.2.1"}),
	}
	got := Fold(in)
	if len(got) != 2 {
		t.Fatalf("Fold produced %d records, want 2: %#v", len(got), got)
	}
	first := got[0]
	if first.FoldCount != 3 || first.OrigLineStart != 1 || first.OrigLineEnd != 3 {
		t.Fatalf("folded record = %#v, want fold_count=3 lines 1..3", first)
	}
	// 折叠不丢信息：取值按行序拼接（无损性的存储形态）。
	if first.Vars["port"] != "80\x1f443\x1f8080" {
		t.Fatalf("folded port var = %q", first.Vars["port"])
	}
	if got[1].FoldCount != 1 {
		t.Fatalf("trailing record fold_count = %d, want 1", got[1].FoldCount)
	}
}

func TestFoldBreakConditions(t *testing.T) {
	t.Run("template change breaks group", func(t *testing.T) {
		got := Fold([]Record{rec(1, 1, "a", nil), rec(2, 2, "b", nil)})
		if got[0].FoldCount != 1 || got[1].FoldCount != 1 {
			t.Fatalf("unexpected fold: %#v", got)
		}
	})
	t.Run("line gap breaks group", func(t *testing.T) {
		got := Fold([]Record{rec(1, 1, "a", nil), rec(3, 3, "a", nil)})
		if got[0].FoldCount != 1 {
			t.Fatalf("gap must not fold: %#v", got)
		}
	})
	t.Run("different span breaks group", func(t *testing.T) {
		got := Fold([]Record{rec(1, 1, "a", nil), rec(2, 3, "a", nil)})
		if got[0].FoldCount != 1 {
			t.Fatalf("span change must not fold: %#v", got)
		}
	})
	t.Run("different var keys breaks group", func(t *testing.T) {
		got := Fold([]Record{rec(1, 1, "a", map[string]string{"x": "1"}), rec(2, 2, "a", map[string]string{"y": "1"})})
		if got[0].FoldCount != 1 {
			t.Fatalf("key mismatch must not fold: %#v", got)
		}
	})
	t.Run("value containing unit separator never folds", func(t *testing.T) {
		in := []Record{
			rec(1, 1, "a", map[string]string{"x": "bad\x1fvalue"}),
			rec(2, 2, "a", map[string]string{"x": "ok"}),
		}
		got := Fold(in)
		if len(got) != 2 || got[0].FoldCount != 1 || got[1].FoldCount != 1 {
			t.Fatalf("sep-containing record must stay alone: %#v", got)
		}
	})
}

func TestExpandRoundTrip(t *testing.T) {
	// 10⁴ 行规模的无损往返（04 §I1 DoD③ 的机制基础）。
	in := make([]Record, 0, 10_000)
	for i := 0; i < 10_000; i++ {
		line := uint32(i + 1)
		switch i % 4 {
		case 0, 1: // 可折叠：同模板相邻
			in = append(in, rec(line, line, "port {port}/{proto} {state}",
				map[string]string{"port": itoa(80 + i%50), "proto": "tcp", "state": "open"}))
		case 2: // 多行记录（XML 元素跨两行）
			in = append(in, rec(line, line+1, "host {addr}", map[string]string{"addr": itoa(100 + i)}))
			i++ // 占两行，跳过下一行号
		default: // 噪声行（unparsed 保留形态）
			in = append(in, rec(line, line, "RAW "+itoa(i), nil))
		}
	}
	folded := Fold(in)
	expanded := ExpandFolded(folded)
	if len(expanded) != len(in) {
		t.Fatalf("round-trip length = %d, want %d", len(expanded), len(in))
	}
	for i := range in {
		if !reflect.DeepEqual(in[i], expanded[i]) {
			t.Fatalf("record %d differs:\n got %#v\nwant %#v", i, expanded[i], in[i])
		}
	}
}

func TestFoldSemanticEquivalence10k(t *testing.T) {
	// 04 §I1 DoD③：10⁴ 行输入折叠后语义可查询性无损失。
	// 折叠前后对同一组查询（端口/主机/状态）必须给出完全相同的行号区间。
	in := make([]Record, 0, 10_000)
	wantPorts := map[uint32]string{} // 行号 → 该行携带的 port 值
	lineNo := uint32(0)
	for i := 0; i < 10_000; i++ {
		lineNo++
		port := itoa(80 + i%50)
		switch i % 5 {
		case 3:
			in = append(in, rec(lineNo, lineNo, "banner "+itoa(i), nil))
		default:
			in = append(in, rec(lineNo, lineNo, "port {port}/{proto} {state}",
				map[string]string{"port": port, "proto": "tcp", "state": "open"}))
			wantPorts[lineNo] = port
		}
	}
	folded := Fold(in)
	if len(folded) >= len(in) {
		t.Fatalf("fold made no progress: %d -> %d", len(in), len(folded))
	}
	// 查询集：每个 port 值 + 一个不存在的值。
	queries := map[string]bool{"80": false, "81": false, "9999": false}
	for p := range queries {
		before := LinesContaining(in, "port", p)
		after := LinesContaining(folded, "port", p)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("query port=%s differs before/after fold", p)
		}
		// 与构造时的 ground truth 对照。
		if len(before) != countValue(wantPorts, p) {
			t.Fatalf("query port=%s: %d hits, want %d", p, len(before), countValue(wantPorts, p))
		}
	}
}

func TestFoldDeterministic(t *testing.T) {
	// Q6 确定性：同输入多次折叠，输出逐字节等价。
	rng := rand.New(rand.NewSource(42)) // 种子固定（P-5）
	in := make([]Record, 0, 500)
	for i := 0; i < 500; i++ {
		in = append(in, rec(uint32(i+1), uint32(i+1), "evt {n}", map[string]string{"n": itoa(rng.Intn(7))}))
	}
	want := Fold(in)
	for run := 0; run < 3; run++ {
		got := Fold(in)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d differs", run)
		}
	}
}

func TestRecordsToLines(t *testing.T) {
	recs := []Record{
		rec(1, 1, "a {x}", map[string]string{"x": "1"}),
		{OrigLineStart: 2, OrigLineEnd: 2, Template: "b", FoldCount: 0}, // 零值 fold_count → 1
	}
	lines := RecordsToLines(recs)
	if lines[0].FoldCount != 1 || lines[0].Vars["x"] != "1" {
		t.Fatalf("line 0 = %#v", lines[0])
	}
	if lines[1].FoldCount != 1 || lines[1].Template != "b" {
		t.Fatalf("line 1 = %#v", lines[1])
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func countValue(m map[uint32]string, v string) int {
	n := 0
	for _, x := range m {
		if x == v {
			n++
		}
	}
	return n
}

func TestLinesToRecordsDirect(t *testing.T) {
	// fold=off 调试开关的反向转换（Service 层使用）；nil 元素安全跳过。
	lines := []*alethv1.SpectrumLine{
		{OrigLineStart: 3, OrigLineEnd: 4, FoldCount: 2, Template: "t", Vars: map[string]string{"k": "a\x1fb"}},
		nil,
	}
	recs := LinesToRecords(lines)
	if len(recs) != 1 || recs[0].OrigLineStart != 3 || recs[0].FoldCount != 2 {
		t.Fatalf("records = %#v", recs)
	}
}

func TestSpanDegenerate(t *testing.T) {
	// End < Start 的退化记录：span 记 0，折叠自然拒绝（不产生错误区间）。
	r := Record{OrigLineStart: 5, OrigLineEnd: 4, Template: "x", FoldCount: 1}
	if span(&r) != 0 {
		t.Fatalf("span = %d, want 0", span(&r))
	}
}
