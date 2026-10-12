package aperture

// 光圈**连续调节**的测试（M3 §7 DoD："三档光圈 + 连续调节可用"）。
//
// # 为什么这组测试重要
//
// 此前实现只有三档（f/1.4 / f/4 / f/16）—— DoD 的后半句"连续调节"
// 未被实现，而它并非锦上添花：三档之间跨度很大（f/1.4 是 200 实体/1 跳，
// f/16 是 10 实体/3 跳），许多任务落在两档之间。
//
// 本组测试同时守护**物理语义**：连续调节不得破坏"开大孔径必须别处关小"
// （M3 §4.1 的恒定曝光硬约束）—— 否则连续轴就成了绕过预算约束的后门。

import (
	"context"
	"fmt"
	"strings"
	"testing"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// newTestAssembler 构造一个带 50 个实体的测试装配器。
//
// 复用 recall_test.go 的测试替身（fakeGraph / entity / fixedClock），
// 保持与既有用例同一套夹具 —— 新增夹具会让"同一输入"在不同用例里
// 含义不同。
func newTestAssembler(t *testing.T) *Assembler {
	t.Helper()
	g := newFakeGraph()
	for i := 0; i < 50; i++ {
		g.add(entity(fmt.Sprintf("as_%03d", i), alethv1.EntityKind_ASSET,
			map[string]string{
				"addr": fmt.Sprintf("10.1.%d.%d", i/250, i%250+1),
				"os":   "linux", "vendor": "acme",
			}, 0.9))
	}
	// 让实体之间有关系，否则 max_hops 的调节无法被观察到。
	for i := 0; i+1 < 50; i++ {
		g.link(fmt.Sprintf("as_%03d", i), fmt.Sprintf("as_%03d", i+1),
			alethv1.RelationType_RUNS_ON)
	}
	a, err := New(Options{Graph: g, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestOverridesZeroIsNoop(t *testing.T) {
	// zero value = 不覆盖（与 protobuf 的未设置惯例一致），
	// 因此"三档"仍是主入口，连续调节是可选层。
	base := ProfileFor(alethv1.ApertureSetting_F_4)
	got, err := Overrides{}.Apply(base)
	if err != nil {
		t.Fatal(err)
	}
	if got != base {
		t.Fatalf("zero overrides must be a no-op: got %+v want %+v", got, base)
	}
}

func TestOverridesApplySingleAxis(t *testing.T) {
	base := ProfileFor(alethv1.ApertureSetting_F_4) // hops=2 entities=60 depth=2
	got, err := Overrides{MaxHops: 3, MaxEntities: 40}.Apply(base)
	if err != nil {
		t.Fatal(err)
	}
	if got.MaxHops != 3 || got.MaxEntities != 40 {
		t.Fatalf("overrides not applied: %+v", got)
	}
	if got.DepthPerEntity != base.DepthPerEntity {
		t.Fatalf("unset axis must keep the profile value: %+v", got)
	}
	if got.Stop != base.Stop {
		t.Fatalf("the base stop must be preserved for audit: %+v", got)
	}
	if !strings.Contains(got.Label, "连续调节") {
		// 审计要能区分"用了档位值"与"连续调节过"。
		t.Fatalf("label must mark continuous adjustment: %q", got.Label)
	}
}

func TestOverridesRejectWideAndDeep(t *testing.T) {
	// ★ 物理语义：不允许"深且宽"。
	//
	// M3 §4.1 的恒定曝光是硬约束："光圈开大必须别处关小"。
	// 若允许 hops=3 且 entities=200，连续调节就成了绕过预算约束的后门。
	base := ProfileFor(alethv1.ApertureSetting_F_4)
	_, err := Overrides{MaxHops: 3, MaxEntities: 200}.Apply(base)
	if err == nil {
		t.Fatal("wide AND deep must be rejected: it violates constant exposure (M3 §4.1)")
	}
	if !strings.Contains(err.Error(), "constant-exposure") {
		t.Fatalf("the error must name the violated constraint: %v", err)
	}
}

func TestOverridesRejectZeroAxes(t *testing.T) {
	// 显式把某轴设为 0 会被"未设置"吞掉 —— 因此必须走校验路径拒绝，
	// 而不是静默用回档位值（那会让调用方以为设成了 0）。
	base := ProfileFor(alethv1.ApertureSetting_F_4)
	bad := StopProfile{Stop: base.Stop, MaxHops: 0, MaxEntities: 60, DepthPerEntity: 2}
	if err := validateApertureSemantics(bad); err == nil {
		t.Fatal("zero max_hops must be rejected")
	}
	bad2 := StopProfile{Stop: base.Stop, MaxHops: 2, MaxEntities: 0, DepthPerEntity: 2}
	if err := validateApertureSemantics(bad2); err == nil {
		t.Fatal("zero max_entities must be rejected")
	}
	bad3 := StopProfile{Stop: base.Stop, MaxHops: 2, MaxEntities: 60, DepthPerEntity: 0}
	if err := validateApertureSemantics(bad3); err == nil {
		t.Fatal("zero depth_per_entity must be rejected")
	}
}

func TestAllProfileStopsSatisfyExposureLimit(t *testing.T) {
	// 三档本身必须在恒曝光上界之内 —— 否则 validateApertureSemantics
	// 会拒绝合法的档位（回归护栏：改上界时这条会立刻失败）。
	for _, stop := range []alethv1.ApertureSetting_Stop{
		alethv1.ApertureSetting_F_1_4,
		alethv1.ApertureSetting_F_4,
		alethv1.ApertureSetting_F_16,
	} {
		p := ProfileFor(stop)
		if err := validateApertureSemantics(p); err != nil {
			t.Errorf("profile %s must satisfy the exposure limit: %v", p.Label, err)
		}
	}
}

// ---- Interpolate ----

func TestInterpolateEndpointsHitTheStops(t *testing.T) {
	// t=0 取 from、t=1 取 to —— 插值必须与档位值一致（否则"连续"与
	// "离散"两套语义会对不上）。
	from, to := ProfileFor(alethv1.ApertureSetting_F_4), ProfileFor(alethv1.ApertureSetting_F_16)

	ov0, err := Interpolate(alethv1.ApertureSetting_F_4, alethv1.ApertureSetting_F_16, 0)
	if err != nil {
		t.Fatal(err)
	}
	p0, err := ov0.Apply(from)
	if err != nil {
		t.Fatal(err)
	}
	if p0.MaxHops != from.MaxHops || p0.MaxEntities != from.MaxEntities {
		t.Fatalf("t=0 must equal the from-stop: %+v vs %+v", p0, from)
	}

	ov1, err := Interpolate(alethv1.ApertureSetting_F_4, alethv1.ApertureSetting_F_16, 1)
	if err != nil {
		t.Fatal(err)
	}
	p1, err := ov1.Apply(to)
	if err != nil {
		t.Fatal(err)
	}
	if p1.MaxHops != to.MaxHops || p1.MaxEntities != to.MaxEntities {
		t.Fatalf("t=1 must equal the to-stop: %+v vs %+v", p1, to)
	}
}

func TestInterpolateMidpointIsBetweenStops(t *testing.T) {
	// 中点必须落在两档之间 —— 这正是"连续调节"要解决的问题：
	// 任务常落在两档之间，只取档位点会浪费预算或丢信息。
	//
	// ★ 注意 `max_hops` 是**小整数轴**（2→3）：中点 2.5 无论四舍五入
	// 还是截断都只能取 2 或 3，不存在"严格介于"的整数。
	// 因此该轴的断言是**闭区间**，只有大跨度轴（max_entities 60→10）
	// 才断言严格介于。
	ov, err := Interpolate(alethv1.ApertureSetting_F_4, alethv1.ApertureSetting_F_16, 0.5)
	if err != nil {
		t.Fatal(err)
	}
	a, b := ProfileFor(alethv1.ApertureSetting_F_4), ProfileFor(alethv1.ApertureSetting_F_16)

	// 大跨度轴：严格介于。
	if !(ov.MaxEntities < a.MaxEntities && ov.MaxEntities > b.MaxEntities) {
		t.Fatalf("midpoint max_entities should be strictly between %d and %d, got %d",
			b.MaxEntities, a.MaxEntities, ov.MaxEntities)
	}
	// 小整数轴：落在闭区间内。
	if ov.MaxHops < a.MaxHops || ov.MaxHops > b.MaxHops {
		t.Fatalf("midpoint max_hops should be within [%d,%d], got %d",
			a.MaxHops, b.MaxHops, ov.MaxHops)
	}
	if ov.DepthPerEntity < a.DepthPerEntity || ov.DepthPerEntity > b.DepthPerEntity {
		t.Fatalf("midpoint depth should be within [%d,%d], got %d",
			a.DepthPerEntity, b.DepthPerEntity, ov.DepthPerEntity)
	}
}

func TestInterpolateRoundsRatherThanTruncates(t *testing.T) {
	// ★ 为什么用**四舍五入**而非截断：
	//
	// 小整数轴上截断会让 t<1 的多数取值等于 from 档
	// （hops 2→3 时 t=0.5 得 2.5，截断成 2），
	// 于是"连续调节"在该轴上退化成"只有档位值"。
	//
	// 四舍五入保证 t≥0.5 时至少走到 to 的方向。
	for _, tc := range []struct {
		t        float64
		wantHops uint32
	}{
		{0.0, 2}, {0.4, 2}, {0.5, 3}, {1.0, 3},
	} {
		ov, err := Interpolate(alethv1.ApertureSetting_F_4, alethv1.ApertureSetting_F_16, tc.t)
		if err != nil {
			t.Fatalf("t=%v: %v", tc.t, err)
		}
		if ov.MaxHops != tc.wantHops {
			t.Errorf("t=%v: max_hops = %d, want %d (round, not truncate)",
				tc.t, ov.MaxHops, tc.wantHops)
		}
	}
}

func TestInterpolateRejectsNonAdjacentStops(t *testing.T) {
	// 在 f/1.4 与 f/16 之间插值会**跳过 f/4 的语义** —— 拒绝而不是
	// 静默给出一个中间值。
	_, err := Interpolate(alethv1.ApertureSetting_F_1_4, alethv1.ApertureSetting_F_16, 0.5)
	if err == nil {
		t.Fatal("interpolating across a stop must be rejected")
	}
	if !strings.Contains(err.Error(), "adjacent") {
		t.Fatalf("the error should explain the adjacency requirement: %v", err)
	}
}

func TestInterpolateRejectsOutOfRangeT(t *testing.T) {
	for _, bad := range []float64{-0.1, 1.1} {
		if _, err := Interpolate(
			alethv1.ApertureSetting_F_4, alethv1.ApertureSetting_F_16, bad); err == nil {
			t.Fatalf("t=%v must be rejected", bad)
		}
	}
}

func TestInterpolateNeverYieldsZeroAxes(t *testing.T) {
	// 插值不得把任何轴归零 —— 归零即"无上下文"，
	// 而 validateApertureSemantics 会拒绝它。因此在钳制到 ≥1。
	for _, t01 := range []float64{0, 0.01, 0.5, 0.99, 1} {
		ov, err := Interpolate(alethv1.ApertureSetting_F_1_4, alethv1.ApertureSetting_F_4, t01)
		if err != nil {
			t.Fatalf("t=%v: %v", t01, err)
		}
		if ov.MaxHops == 0 || ov.MaxEntities == 0 || ov.DepthPerEntity == 0 {
			t.Fatalf("t=%v produced a zero axis: %+v", t01, ov)
		}
	}
}

// ---- AssembleWithOverrides ----

func TestAssembleWithOverridesUsesAdjustedParams(t *testing.T) {
	a := newTestAssembler(t)
	req := &alethv1.AssembleRequest{
		TaskId:        "t1",
		SessionId:     "s1",
		BudgetTokens:  100_000,
		PreferredStop: alethv1.ApertureSetting_F_4,
	}
	bundle, err := a.AssembleWithOverrides(context.Background(), req,
		Overrides{MaxHops: 1, MaxEntities: 30})
	if err != nil {
		t.Fatal(err)
	}
	// 调节后的参数必须写进 bundle.aperture（审计依据）。
	ap := bundle.GetAperture()
	if ap.GetMaxHops() != 1 || ap.GetMaxEntities() != 30 {
		t.Fatalf("bundle must record the adjusted params: hops=%d entities=%d",
			ap.GetMaxHops(), ap.GetMaxEntities())
	}
	if ap.GetStop() != alethv1.ApertureSetting_F_4 {
		t.Fatalf("the base stop must be preserved: %v", ap.GetStop())
	}
}

func TestAssembleWithOverridesRejectsIllegalCombo(t *testing.T) {
	a := newTestAssembler(t)
	req := &alethv1.AssembleRequest{
		TaskId: "t1", SessionId: "s1", BudgetTokens: 100_000,
		PreferredStop: alethv1.ApertureSetting_F_4,
	}
	_, err := a.AssembleWithOverrides(context.Background(), req,
		Overrides{MaxHops: 3, MaxEntities: 200})
	if err == nil {
		t.Fatal("an illegal wide-and-deep combination must be rejected before assembly")
	}
}

func TestAssembleWithOverridesRequiresBudget(t *testing.T) {
	// 与 Assemble 同一约束：无预算的会话没有曝光约束（M3 §4.1）。
	a := newTestAssembler(t)
	_, err := a.AssembleWithOverrides(context.Background(),
		&alethv1.AssembleRequest{TaskId: "t1", SessionId: "s1"},
		Overrides{MaxHops: 1})
	if err == nil {
		t.Fatal("budget is required")
	}
	if !strings.Contains(err.Error(), "budget_tokens is required") {
		t.Fatalf("the error should name the missing field: %v", err)
	}
}

func TestAssembleWithOverridesIsDeterministic(t *testing.T) {
	// P-5：相同输入必得相同输出。
	a := newTestAssembler(t)
	req := &alethv1.AssembleRequest{
		TaskId: "t1", SessionId: "s1", BudgetTokens: 100_000,
		PreferredStop: alethv1.ApertureSetting_F_4,
	}
	ov := Overrides{MaxHops: 2, MaxEntities: 45}
	first, err := a.AssembleWithOverrides(context.Background(), req, ov)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := a.AssembleWithOverrides(context.Background(), req, ov)
		if err != nil {
			t.Fatal(err)
		}
		if again.GetBundleId() != first.GetBundleId() {
			t.Fatalf("non-deterministic bundle id: %q vs %q",
				again.GetBundleId(), first.GetBundleId())
		}
		if len(again.GetEntities()) != len(first.GetEntities()) {
			t.Fatalf("non-deterministic entity count")
		}
	}
}

func TestZeroOverridesMatchesPlainAssemble(t *testing.T) {
	// 空覆盖必须与普通 Assemble **完全一致** ——
	// 否则连续调节层就成了一个悄悄改变行为的旁路。
	a := newTestAssembler(t)
	req := &alethv1.AssembleRequest{
		TaskId: "t1", SessionId: "s1", BudgetTokens: 100_000,
		PreferredStop: alethv1.ApertureSetting_F_4,
	}
	plain, err := a.Assemble(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	withZero, err := a.AssembleWithOverrides(context.Background(), req, Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if plain.GetBundleId() != withZero.GetBundleId() {
		t.Fatalf("zero overrides changed the result: %q vs %q",
			plain.GetBundleId(), withZero.GetBundleId())
	}
	// 契约的 ApertureSetting 无 Label 字段，因此用三个参数轴判定
	// "未被调节"：零覆盖必须原样保留档位值。
	pa, wa := plain.GetAperture(), withZero.GetAperture()
	if pa.GetMaxHops() != wa.GetMaxHops() ||
		pa.GetMaxEntities() != wa.GetMaxEntities() ||
		pa.GetDepthPerEntity() != wa.GetDepthPerEntity() {
		t.Fatalf("zero overrides must not change the aperture params: %+v vs %+v", pa, wa)
	}
	if wa.GetMaxEntities() == 0 {
		t.Fatal("zero overrides must keep the profile values, not zero them")
	}
}
