package orchestrate

// GetGraph / ListSessions 的测试（`contract:2026-11-02`）。
//
// # 为什么这两个只读 RPC 需要专门测试
//
// 它们存在的理由就是"让 UI 显示真实数据"。因此最容易出的错不是 panic，
// 而是**显示一份看起来合理、实际不对的数据**：
//
//   · GetGraph 在 graph_id 不匹配时返回当前图 —— 页面拿历史版本的名义
//     渲染了另一个版本，用户会对着错的数据做决策；
//   · ListSessions 在来源缺失时把成本填 0 —— 与"真的花了 0"无法区分。
//
// 所以本文件的断言大量集中在"不该返回什么"，而不是"能返回什么"。

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// newPlannedServer 返回一个已为 sessionID 规划好图的 Server。
func newPlannedServer(t *testing.T, sessionID string, taskIDs ...string) *Server {
	t.Helper()
	s := NewServer()
	tasks := make([]*alethv1.Task, 0, len(taskIDs))
	for _, id := range taskIDs {
		tasks = append(tasks, &alethv1.Task{
			TaskId:       id,
			Title:        "任务 " + id,
			Objective:    "完成 " + id,
			RequiredRole: alethv1.AgentRole_RECON,
			BudgetTokens: 512,
		})
	}
	if _, err := s.Plan(context.Background(), &alethv1.PlanRequest{
		SessionId:     sessionID,
		ProposedGraph: &alethv1.TaskGraph{SessionId: sessionID, Tasks: tasks},
		BudgetTokens:  10_000,
	}); err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return s
}

// ---- GetGraph ----

func TestGetGraphReturnsPlannedGraph(t *testing.T) {
	s := newPlannedServer(t, "sess_a", "t1", "t2")

	got, err := s.GetGraph(context.Background(), &alethv1.GetGraphRequest{
		SessionId: "sess_a",
	})
	if err != nil {
		t.Fatalf("GetGraph: %v", err)
	}
	if got.GetSessionId() != "sess_a" {
		t.Fatalf("session_id = %q", got.GetSessionId())
	}
	if n := len(got.GetTasks()); n != 2 {
		t.Fatalf("tasks = %d, want 2", n)
	}
	if got.GetGraphId() == "" {
		t.Fatal("graph_id 不应为空（页面要靠它做后续请求）")
	}
}

func TestGetGraphRequiresSessionID(t *testing.T) {
	s := NewServer()
	_, err := s.GetGraph(context.Background(), &alethv1.GetGraphRequest{})
	assertCode(t, err, codes.InvalidArgument)
}

func TestGetGraphUnknownSessionIsNotFound(t *testing.T) {
	s := NewServer()
	_, err := s.GetGraph(context.Background(), &alethv1.GetGraphRequest{
		SessionId: "nope",
	})
	assertCode(t, err, codes.NotFound)
}

func TestGetGraphRefusesMismatchedGraphID(t *testing.T) {
	// ★ 页面请求的是历史版本时，不能"返回当前图当没事" ——
	// 那会让用户对着错的数据做决策。
	s := newPlannedServer(t, "sess_a", "t1")

	_, err := s.GetGraph(context.Background(), &alethv1.GetGraphRequest{
		SessionId: "sess_a",
		GraphId:   "some-other-graph",
	})
	assertCode(t, err, codes.NotFound)
	if msg := status.Convert(err).Message(); !contains(msg, "refusing") {
		t.Errorf("错误信息应说明拒绝理由，实际：%s", msg)
	}
}

func TestGetGraphAcceptsMatchingGraphID(t *testing.T) {
	s := newPlannedServer(t, "sess_a", "t1")
	first, err := s.GetGraph(context.Background(), &alethv1.GetGraphRequest{SessionId: "sess_a"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.GetGraph(context.Background(), &alethv1.GetGraphRequest{
		SessionId: "sess_a",
		GraphId:   first.GetGraphId(),
	})
	if err != nil {
		t.Fatalf("匹配的 graph_id 应被接受: %v", err)
	}
	if again.GetGraphId() != first.GetGraphId() {
		t.Fatal("两次读取的 graph_id 不一致")
	}
}

func TestGetGraphIsIdempotent(t *testing.T) {
	// 只读接口：多次调用不得改变图（否则页面刷新会"改"数据）。
	s := newPlannedServer(t, "sess_a", "t1", "t2")
	a, err := s.GetGraph(context.Background(), &alethv1.GetGraphRequest{SessionId: "sess_a"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		b, err := s.GetGraph(context.Background(), &alethv1.GetGraphRequest{SessionId: "sess_a"})
		if err != nil {
			t.Fatal(err)
		}
		if len(a.GetTasks()) != len(b.GetTasks()) {
			t.Fatal("重复读取返回了不同的任务数")
		}
		for j := range a.GetTasks() {
			if a.GetTasks()[j].GetStatus() != b.GetTasks()[j].GetStatus() {
				t.Fatal("重复读取改变了任务状态 —— GetGraph 不得有副作用")
			}
		}
	}
}

// ---- ListSessions ----

func TestListSessionsEmpty(t *testing.T) {
	s := NewServer()
	resp, err := s.ListSessions(context.Background(), &alethv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(resp.GetSessions()) != 0 {
		t.Fatalf("空服务应返回 0 个会话，实际 %d", len(resp.GetSessions()))
	}
	if resp.GetNextCursor() != "" {
		t.Fatal("没有更多数据时 next_cursor 应为空")
	}
}

func TestListSessionsEnumeratesAll(t *testing.T) {
	s := NewServer()
	for _, id := range []string{"sess_b", "sess_a", "sess_c"} {
		newPlannedServerOn(s, id, "t1")
	}

	resp, err := s.ListSessions(context.Background(), &alethv1.ListSessionsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(resp.GetSessions()); n != 3 {
		t.Fatalf("sessions = %d, want 3", n)
	}
	// 排序必须是 session_id 升序（稳定、可复现；不用本地时钟）。
	want := []string{"sess_a", "sess_b", "sess_c"}
	for i, w := range want {
		if got := resp.GetSessions()[i].GetSessionId(); got != w {
			t.Fatalf("顺序错误：第 %d 个是 %q，应为 %q", i, got, w)
		}
	}
}

func TestListSessionsReportsTaskCountsAndStatus(t *testing.T) {
	s := newPlannedServer(t, "sess_x", "t1", "t2")
	// 把 t1 标为完成。
	g, err := s.graphFor("sess_x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReportTaskResult(context.Background(), &alethv1.ReportTaskResultRequest{
		SessionId: "sess_x",
		TaskId:    "t1",
		Status:    alethv1.TaskStatus_DONE,
	}); err != nil {
		t.Fatalf("ReportTaskResult: %v", err)
	}
	_ = g

	resp, err := s.ListSessions(context.Background(), &alethv1.ListSessionsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetSessions()) != 1 {
		t.Fatalf("sessions = %d", len(resp.GetSessions()))
	}
	sum := resp.GetSessions()[0]
	if sum.GetTaskTotal() != 2 || sum.GetTaskDone() != 1 {
		t.Fatalf("task_total=%d task_done=%d, want 2/1",
			sum.GetTaskTotal(), sum.GetTaskDone())
	}
	if sum.GetStatus() != "RUNNING" {
		t.Fatalf("status = %q, want RUNNING（未全部完成）", sum.GetStatus())
	}
}

func TestListSessionsStatusDoneWhenAllComplete(t *testing.T) {
	s := newPlannedServer(t, "sess_d", "t1")
	if _, err := s.ReportTaskResult(context.Background(), &alethv1.ReportTaskResultRequest{
		SessionId: "sess_d",
		TaskId:    "t1",
		Status:    alethv1.TaskStatus_DONE,
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ListSessions(context.Background(), &alethv1.ListSessionsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.GetSessions()[0].GetStatus(); got != "DONE" {
		t.Fatalf("status = %q, want DONE", got)
	}
}

func TestListSessionsHonoursLimit(t *testing.T) {
	s := NewServer()
	for _, id := range []string{"s1", "s2", "s3", "s4", "s5"} {
		newPlannedServerOn(s, id, "t1")
	}
	resp, err := s.ListSessions(context.Background(), &alethv1.ListSessionsRequest{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(resp.GetSessions()); n != 2 {
		t.Fatalf("limit=2 应返回 2 个，实际 %d", n)
	}
	if resp.GetNextCursor() == "" {
		t.Fatal("还有更多数据时 next_cursor 不得为空（否则调用方会漏读）")
	}
}

func TestListSessionsCursorPaginationIsComplete(t *testing.T) {
	// 逐页读完全部会话，结果必须与一次读全一致（不重不漏）。
	s := NewServer()
	for _, id := range []string{"a1", "a2", "a3", "a4", "a5"} {
		newPlannedServerOn(s, id, "t1")
	}
	seen := []string{}
	cursor := ""
	for i := 0; i < 10; i++ {
		resp, err := s.ListSessions(context.Background(), &alethv1.ListSessionsRequest{
			Limit:  2,
			Cursor: cursor,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, sum := range resp.GetSessions() {
			seen = append(seen, sum.GetSessionId())
		}
		cursor = resp.GetNextCursor()
		if cursor == "" {
			break
		}
	}
	if len(seen) != 5 {
		t.Fatalf("分页共读到 %d 个，want 5（重复=%v）", len(seen), seen)
	}
	for i, want := range []string{"a1", "a2", "a3", "a4", "a5"} {
		if seen[i] != want {
			t.Fatalf("第 %d 个是 %q，应为 %q", i, seen[i], want)
		}
	}
}

func TestListSessionsLeavesBudgetEmptyWithoutSource(t *testing.T) {
	// ★ 来源缺失时**留空**（=0 但语义是"未知"），而不是编造成本。
	//
	// 这里断言的是契约层面的行为：字段为 0 且没有来源。
	// 真正的区分在页面上（空 vs 0），因此适配器返回 provided=false。
	s := newPlannedServer(t, "sess_n", "t1")
	resp, err := s.ListSessions(context.Background(), &alethv1.ListSessionsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	sum := resp.GetSessions()[0]
	if sum.GetBudgetTotalTokens() != 0 || sum.GetBudgetConsumedTokens() != 0 {
		t.Fatal("无来源时预算字段应为 0（并由适配器标记为未提供）")
	}
}

func TestListSessionsUsesSessionSource(t *testing.T) {
	s := newPlannedServer(t, "sess_w", "t1")
	s.SetSessionSource(fakeSessionSource{
		budget:      SessionBudget{TotalTokens: 5000, Consumed: 1200, CircuitOpen: true},
		hasBudget:   true,
		findings:    SessionFindings{Candidate: 3, Confirmed: 1},
		hasFindings: true,
	})

	resp, err := s.ListSessions(context.Background(), &alethv1.ListSessionsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	sum := resp.GetSessions()[0]
	if sum.GetBudgetTotalTokens() != 5000 || sum.GetBudgetConsumedTokens() != 1200 {
		t.Fatalf("预算未接入：%d/%d", sum.GetBudgetConsumedTokens(), sum.GetBudgetTotalTokens())
	}
	if !sum.GetBudgetCircuitOpen() {
		t.Fatal("熔断状态未接入")
	}
	if sum.GetFindingsCandidate() != 3 || sum.GetFindingsConfirmed() != 1 {
		t.Fatalf("finding 计数未接入：%d/%d",
			sum.GetFindingsCandidate(), sum.GetFindingsConfirmed())
	}
}

func TestListSessionsPropagatesSourceError(t *testing.T) {
	// 来源故障必须上报，不能静默降级成"没有预算信息"——
	// 那会让一个坏掉的接线看起来像"这个会话没有预算"。
	s := newPlannedServer(t, "sess_e", "t1")
	s.SetSessionSource(failingSessionSource{})

	_, err := s.ListSessions(context.Background(), &alethv1.ListSessionsRequest{})
	assertCode(t, err, codes.Unavailable)
}

// ---- 辅助 ----

func newPlannedServerOn(s *Server, sessionID string, taskIDs ...string) {
	tasks := make([]*alethv1.Task, 0, len(taskIDs))
	for _, id := range taskIDs {
		tasks = append(tasks, &alethv1.Task{
			TaskId:       id,
			Title:        "任务 " + id,
			Objective:    "完成 " + id,
			RequiredRole: alethv1.AgentRole_RECON,
			BudgetTokens: 512,
		})
	}
	_, _ = s.Plan(context.Background(), &alethv1.PlanRequest{
		SessionId:     sessionID,
		ProposedGraph: &alethv1.TaskGraph{SessionId: sessionID, Tasks: tasks},
		BudgetTokens:  10_000,
	})
}

type fakeSessionSource struct {
	budget      SessionBudget
	hasBudget   bool
	findings    SessionFindings
	hasFindings bool
}

func (f fakeSessionSource) SessionBudget(context.Context, string) (SessionBudget, bool, error) {
	return f.budget, f.hasBudget, nil
}

func (f fakeSessionSource) SessionFindings(context.Context, string) (SessionFindings, bool, error) {
	return f.findings, f.hasFindings, nil
}

type failingSessionSource struct{}

func (failingSessionSource) SessionBudget(context.Context, string) (SessionBudget, bool, error) {
	return SessionBudget{}, false, status.Error(codes.Unavailable, "governor down")
}

func (failingSessionSource) SessionFindings(context.Context, string) (SessionFindings, bool, error) {
	return SessionFindings{}, false, nil
}

func assertCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("期望错误 %v，实际 nil", want)
	}
	if got := status.Code(err); got != want {
		t.Fatalf("错误码 = %v, want %v（err: %v）", got, want, err)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
