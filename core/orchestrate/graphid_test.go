package orchestrate

// 确定性 graph_id 的测试（修复：Plan 此前不生成 graph_id）。

import (
	"context"
	"testing"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

func planWith(t *testing.T, s *Server, sessionID string, tasks ...*alethv1.Task) *alethv1.TaskGraph {
	t.Helper()
	g, err := s.Plan(context.Background(), &alethv1.PlanRequest{
		SessionId:     sessionID,
		ProposedGraph: &alethv1.TaskGraph{SessionId: sessionID, Tasks: tasks},
		BudgetTokens:  10_000,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return g
}

func mkTask(id string, role alethv1.AgentRole, budget uint32, deps ...string) *alethv1.Task {
	return &alethv1.Task{
		TaskId:       id,
		Title:        "T " + id,
		Objective:    "O " + id,
		RequiredRole: role,
		BudgetTokens: budget,
		DependsOn:    deps,
	}
}

func TestPlanDerivesGraphIDWhenAbsent(t *testing.T) {
	// ★ 回归：Plan 此前原样保留空 graph_id，导致下游（NextReady /
	// GetGraph / Python 执行侧）在第一步就失败。
	s := NewServer()
	g := planWith(t, s, "sess_1", mkTask("t1", alethv1.AgentRole_RECON, 512))
	if g.GetGraphId() == "" {
		t.Fatal("Plan 必须为缺失的 graph_id 派生一个值")
	}
}

func TestDerivedGraphIDIsStableAcrossServers(t *testing.T) {
	// P-5：同一份计划在不同进程里必须得到同一个 ID，
	// 否则检查点 / rewind / fork 无法判断"是不是同一张图"。
	mk := func() string {
		s := NewServer()
		return planWith(t, s, "sess_1",
			mkTask("t2", alethv1.AgentRole_SCANNER, 512, "t1"),
			mkTask("t1", alethv1.AgentRole_RECON, 512),
		).GetGraphId()
	}
	a, b := mk(), mk()
	if a != b {
		t.Fatalf("同一计划得到不同 ID：%s vs %s（破坏可复现性）", a, b)
	}
}

func TestDerivedGraphIDIgnoresTaskDeclarationOrder(t *testing.T) {
	// 哈希按 id 排序后计算 —— 否则 Go map 遍历的随机顺序会让
	// 同一张图每次得到不同 ID。
	s1 := NewServer()
	a := planWith(t, s1, "sess_1",
		mkTask("t1", alethv1.AgentRole_RECON, 512),
		mkTask("t2", alethv1.AgentRole_SCANNER, 512, "t1"),
	).GetGraphId()

	s2 := NewServer()
	b := planWith(t, s2, "sess_1",
		mkTask("t2", alethv1.AgentRole_SCANNER, 512, "t1"),
		mkTask("t1", alethv1.AgentRole_RECON, 512),
	).GetGraphId()

	if a != b {
		t.Fatalf("声明顺序改变了 ID：%s vs %s", a, b)
	}
}

func TestDerivedGraphIDChangesWhenStructureChanges(t *testing.T) {
	s1 := NewServer()
	a := planWith(t, s1, "sess_1", mkTask("t1", alethv1.AgentRole_RECON, 512)).GetGraphId()

	s2 := NewServer()
	b := planWith(t, s2, "sess_1", mkTask("t1", alethv1.AgentRole_SCANNER, 512)).GetGraphId()

	if a == b {
		t.Fatal("角色变了 ID 必须变（否则改写前后的图无法区分）")
	}
}

func TestDerivedGraphIDIgnoresCosmeticTextChanges(t *testing.T) {
	// 标题/目标的措辞变化不应改变图身份 —— 否则改一个错别字
	// 就会让已有检查点失联。
	s1 := NewServer()
	a := planWith(t, s1, "sess_1", mkTask("t1", alethv1.AgentRole_RECON, 512)).GetGraphId()

	s2 := NewServer()
	renamed := mkTask("t1", alethv1.AgentRole_RECON, 512)
	renamed.Title = "完全不同的标题"
	renamed.Objective = "完全不同的目标"
	b := planWith(t, s2, "sess_1", renamed).GetGraphId()

	if a != b {
		t.Fatalf("仅措辞变化不应改变 ID：%s vs %s", a, b)
	}
}

func TestCallerSuppliedGraphIDIsPreserved(t *testing.T) {
	// 调用方显式给了 ID 就不覆盖 —— 外部系统可能已经在引用它。
	s := NewServer()
	g, err := s.Plan(context.Background(), &alethv1.PlanRequest{
		SessionId: "sess_1",
		ProposedGraph: &alethv1.TaskGraph{
			SessionId: "sess_1",
			GraphId:   "caller-chosen-id",
			Tasks:     []*alethv1.Task{mkTask("t1", alethv1.AgentRole_RECON, 512)},
		},
		BudgetTokens: 10_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if g.GetGraphId() != "caller-chosen-id" {
		t.Fatalf("graph_id = %q，调用方指定的值被覆盖了", g.GetGraphId())
	}
}

func TestDerivedGraphIDIsDistinctPerSession(t *testing.T) {
	s := NewServer()
	a := planWith(t, s, "sess_a", mkTask("t1", alethv1.AgentRole_RECON, 512)).GetGraphId()
	b := planWith(t, s, "sess_b", mkTask("t1", alethv1.AgentRole_RECON, 512)).GetGraphId()
	if a == b {
		t.Fatal("不同会话的图 ID 不得相同（会互相覆盖）")
	}
}
