package aperture

// `contract:2026-11-02`：AssembleRequest 的覆盖字段是否真的被读取。
//
// # 为什么这组测试重要
//
// 加字段本身不产生任何行为。真正要防的是"字段加了、proto 有了、文档写了，
// 但服务端根本没读它"—— 那正是本项目反复踩过的那类坑
// （`docs/10` §0："用绿灯替换有效性"）。
//
// 因此这里走**gRPC 入口** `Assemble`（而不是内部 `AssembleWithOverrides`），
// 断言覆盖值一路到达 `bundle.aperture` —— 可审计参数就是这个字段，
// 它不对就说明链路断了。

import (
	"context"
	"testing"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

func TestAssembleReadsOverrideFieldsFromRequest(t *testing.T) {
	a := newTestAssembler(t)
	req := &alethv1.AssembleRequest{
		TaskId:         "t1",
		SessionId:      "s1",
		BudgetTokens:   100_000,
		PreferredStop:  alethv1.ApertureSetting_F_4,
		MaxHops:        1,
		MaxEntities:    30,
		DepthPerEntity: 2,
	}

	bundle, err := a.Assemble(context.Background(), req)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	ap := bundle.GetAperture()
	if ap.GetMaxHops() != 1 || ap.GetMaxEntities() != 30 || ap.GetDepthPerEntity() != 2 {
		t.Fatalf("bundle.aperture 未反映请求里的覆盖参数：hops=%d entities=%d depth=%d",
			ap.GetMaxHops(), ap.GetMaxEntities(), ap.GetDepthPerEntity())
	}
}

func TestAssembleWithoutOverridesKeepsProfileParams(t *testing.T) {
	// 向后兼容：旧客户端不发送这些字段（=0）时，行为必须与此前一致。
	a := newTestAssembler(t)
	req := &alethv1.AssembleRequest{
		TaskId:        "t1",
		SessionId:     "s1",
		BudgetTokens:  100_000,
		PreferredStop: alethv1.ApertureSetting_F_4,
	}
	bundle, err := a.Assemble(context.Background(), req)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	want := ProfileFor(alethv1.ApertureSetting_F_4)
	ap := bundle.GetAperture()
	if ap.GetMaxHops() != want.MaxHops || ap.GetMaxEntities() != want.MaxEntities {
		t.Fatalf("未传覆盖时应沿用档位参数：got hops=%d entities=%d, want %d/%d",
			ap.GetMaxHops(), ap.GetMaxEntities(), want.MaxHops, want.MaxEntities)
	}
}

func TestAssembleRejectsInvalidOverrideCombination(t *testing.T) {
	// ★ 覆盖不得绕过物理语义校验（曝光上限 / 禁止又宽又深）。
	// 若这里静默接受，装配会产出一份远超设计越界面的上下文。
	a := newTestAssembler(t)
	req := &alethv1.AssembleRequest{
		TaskId:         "t1",
		SessionId:      "s1",
		BudgetTokens:   100_000,
		PreferredStop:  alethv1.ApertureSetting_F_4,
		MaxHops:        9,   // 很宽
		MaxEntities:    200, // 又很宽
		DepthPerEntity: 5,   // 又很深 → "又宽又深"，必须拒绝
	}
	if _, err := a.Assemble(context.Background(), req); err == nil {
		t.Fatal("又宽又深的覆盖组合必须被拒绝（不得静默接受）")
	}
}

func TestAssembleSingleAxisOverrideWorks(t *testing.T) {
	// 只覆盖一个轴是连续调节的常态（例如"只收窄实体数"）。
	a := newTestAssembler(t)
	req := &alethv1.AssembleRequest{
		TaskId:        "t1",
		SessionId:     "s1",
		BudgetTokens:  100_000,
		PreferredStop: alethv1.ApertureSetting_F_4,
		MaxEntities:   12,
	}
	bundle, err := a.Assemble(context.Background(), req)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if got := bundle.GetAperture().GetMaxEntities(); got != 12 {
		t.Fatalf("max_entities = %d, want 12", got)
	}
	// 其余轴沿用档位。
	if got, want := bundle.GetAperture().GetMaxHops(), ProfileFor(alethv1.ApertureSetting_F_4).MaxHops; got != want {
		t.Fatalf("未覆盖的轴被改动了：hops=%d, want %d", got, want)
	}
}
