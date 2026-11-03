// OrchestratorService 的两个只读接口：GetGraph / ListSessions。
//
// # 为什么在 2026-11-02 才补
//
// 这两个 RPC 是 `contract:2026-11-02` 新增的（见 `05` §6.2 与 CHANGELOG）。
// 补之前，契约只有"写"（Plan / ReportTaskResult）与"按 NextReady 查就绪集"
// —— 于是：
//
//   · 决策队列（`06` 页面 7）无法渲染 `06` §7.1 的四要素卡片，只能消费
//     `blocked_reasons`；
//   · 会话总览（`06` 页面 1）无法枚举会话 —— 全契约唯一带 List 语义的
//     方法是 `ListAdapters`，与会话无关。
//
// 两个缺口都被实现侧如实标注为"未知字段留空并说明"，没有编造。
// 现在补齐，是为了让页面能显示真实数据，而不是"看起来有数据"。
//
// # 为什么 ListSessions 需要外部数据源
//
// 编排层自己只知道"有哪些任务图"，不知道成本（在 Governor）、
// 也不知道 finding 计数（在 Ledger）。若在这里直接去查询那两个模块，
// 就把编排层变成了聚合层，且引出了循环依赖的可能。
//
// 因此本文件定义 `SessionSource`（与既有的 `SnapshotSource` 同款模式：
// 接口在这里，实现在 `cmd/alethd` 的装配层）。**来源缺失时如实退化为
// 仅有编排层已知的字段**（任务计数），而不是编造成本为 0
// —— 假的 0 与真的 0 在页面上无法区分，那正是 `docs/10` §0 反对的。

package orchestrate

import (
	"context"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	alethv1 "github.com/AperturePrism/aleth/core/api/aleth/v1"
)

// SessionBudget 是 `SessionSource` 返回的预算摘要（与 `05` §6.3 同口径）。
type SessionBudget struct {
	TotalTokens uint32
	Consumed    uint32
	CircuitOpen bool
}

// SessionFindings 是 finding 计数摘要（只放计数，不含内容）。
type SessionFindings struct {
	Candidate uint32
	Confirmed uint32
}

// SessionSource 为 `ListSessions` 提供编排层之外的状态。
//
// 第二个返回值表示"该来源是否提供了数据"。为 false 时，
// `ListSessions` 会把这些字段**留空**而不是填 0 —— 见文件头说明。
type SessionSource interface {
	// SessionBudget 返回会话的预算摘要。
	SessionBudget(ctx context.Context, sessionID string) (SessionBudget, bool, error)
	// SessionFindings 返回会话的 finding 计数。
	SessionFindings(ctx context.Context, sessionID string) (SessionFindings, bool, error)
}

// SetSessionSource 注入跨模块数据源（可为 nil）。
//
// 在 `NewServer` 之后调用，与 `SetSnapshots` 的用法一致 ——
// 这样既保持 `NewServer()` 的无参签名（既有测试不必改），
// 又不会让编排层在构造期就依赖外部模块。
func (s *Server) SetSessionSource(src SessionSource) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = src
}

// 默认分页大小。契约要求 limit=0 时取默认值，**不得返回全部**
// （会话数无上界；一次返回全部会让 UI 在长期部署后卡死）。
const defaultSessionLimit = 50

// maxSessionLimit 是客户端可请求的上限。超过则截断到上限而不是报错 ——
// 截断是常见的分页语义，但必须通过 `next_cursor` 让调用方知道还有更多。
const maxSessionLimit = 200

// GetGraph 返回会话的任务图（只读、幂等、无副作用）。
//
// `graph_id` 留空表示"当前计划"。显式给出时必须与当前图匹配 ——
// 若不匹配则返回 NotFound，而不是"返回当前图当没事"：
// 页面要渲染的可能是历史版本，静默返回别的图会让用户对着错的数据做决策。
func (s *Server) GetGraph(
	ctx context.Context, req *alethv1.GetGraphRequest,
) (*alethv1.TaskGraph, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	g, err := s.graphFor(req.GetSessionId())
	if err != nil {
		return nil, err
	}
	if want := req.GetGraphId(); want != "" && want != g.ID {
		return nil, status.Errorf(codes.NotFound,
			"session %q has graph %q, not %q (refusing to return a different graph)",
			req.GetSessionId(), g.ID, want)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return g.ToProto(), nil
}

// ListSessions 枚举会话（只读、幂等）。
//
// # 排序与分页
//
// 按 `session_id` 升序 —— 不用 `created_at`：编排层只知道"图何时被 Plan"，
// 而会话可能在此前就存在（例如只入了证据、还没规划）。用本地时钟排序会
// 让分页在多实例部署下不稳定（P-5 要求可复现）。`session_id` 是唯一
// 且稳定的排序键。
//
// `cursor` 是上一次返回的 `next_cursor`（即最后一个 session_id 之后的起点）。
//
// # 为什么返回的字段可能为空
//
// 见文件头：没有 `SessionSource` 时，成本与 finding 计数**留空**而非填 0。
// 任务计数来自编排层自身，始终准确。
func (s *Server) ListSessions(
	ctx context.Context, req *alethv1.ListSessionsRequest,
) (*alethv1.ListSessionsResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}

	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = defaultSessionLimit
	}
	if limit > maxSessionLimit {
		limit = maxSessionLimit
	}

	// 快照当前会话 id 集合（持锁时间尽量短：后续的跨模块查询
	// 可能很慢，不能占着锁）。
	s.mu.Lock()
	ids := make([]string, 0, len(s.graphs))
	for id := range s.graphs {
		ids = append(ids, id)
	}
	src := s.sessions
	s.mu.Unlock()

	sort.Strings(ids)

	// 游标：跳过 <= cursor 的 id。用"严格大于"而不是"找到 cursor 再 +1"，
	// 这样即便 cursor 指向的会话在两次调用之间被删除，分页也不会跳项。
	start := 0
	if cur := req.GetCursor(); cur != "" {
		start = sort.SearchStrings(ids, cur)
		for start < len(ids) && ids[start] <= cur {
			start++
		}
	}

	end := start + limit
	if end > len(ids) {
		end = len(ids)
	}

	out := &alethv1.ListSessionsResponse{}
	for _, id := range ids[start:end] {
		summary, err := s.sessionSummary(ctx, id, src)
		if err != nil {
			return nil, err
		}
		out.Sessions = append(out.Sessions, summary)
	}
	if end < len(ids) {
		out.NextCursor = ids[end-1]
	}
	return out, nil
}

// sessionSummary 组装一行会话摘要。
func (s *Server) sessionSummary(
	ctx context.Context, sessionID string, src SessionSource,
) (*alethv1.SessionSummary, error) {
	s.mu.Lock()
	g, ok := s.graphs[sessionID]
	var proto *alethv1.TaskGraph
	if ok {
		proto = g.ToProto()
	}
	s.mu.Unlock()

	sum := &alethv1.SessionSummary{SessionId: sessionID}

	if proto != nil {
		sum.TaskTotal = uint32(len(proto.GetTasks()))
		for _, t := range proto.GetTasks() {
			switch t.GetStatus() {
			case alethv1.TaskStatus_DONE:
				sum.TaskDone++
			case alethv1.TaskStatus_FAILED,
				alethv1.TaskStatus_CIRCUIT_BROKEN:
				sum.TaskFailed++
			}
		}
		// 状态：全部完成 → DONE；有失败 → FAILED；否则 RUNNING。
		//
		// 这里刻意不引入"进度百分比"之类的派生字段 —— 契约里没有，
		// 而由服务端自造语义会让前端与后端的口径分叉。
		switch {
		case sum.TaskTotal > 0 && sum.TaskDone == sum.TaskTotal:
			sum.Status = "DONE"
		case sum.TaskFailed > 0:
			sum.Status = "FAILED"
		default:
			sum.Status = "RUNNING"
		}
	} else {
		// 有会话但还没有任务图（例如只入过证据）。
		// 这不是错误 —— 如实表示为"尚未规划"。
		sum.Status = "UNPLANNED"
	}

	if src == nil {
		return sum, nil
	}

	if b, provided, err := src.SessionBudget(ctx, sessionID); err != nil {
		return nil, status.Errorf(codes.Unavailable,
			"session budget lookup failed for %q: %v", sessionID, err)
	} else if provided {
		sum.BudgetTotalTokens = b.TotalTokens
		sum.BudgetConsumedTokens = b.Consumed
		sum.BudgetCircuitOpen = b.CircuitOpen
	}

	if f, provided, err := src.SessionFindings(ctx, sessionID); err != nil {
		return nil, status.Errorf(codes.Unavailable,
			"session findings lookup failed for %q: %v", sessionID, err)
	} else if provided {
		sum.FindingsCandidate = f.Candidate
		sum.FindingsConfirmed = f.Confirmed
	}
	return sum, nil
}
