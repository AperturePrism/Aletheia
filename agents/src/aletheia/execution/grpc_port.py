"""把执行循环接到真实 daemon 上（gRPC 适配）。

# 为什么单独一个文件

`loop.py` 只依赖三个窄端口（plan / next_ready / report）。
把 gRPC 细节隔离在这里，好处有二：

1. 循环可以在**没有 daemon** 的情况下被完整测试（用假端口）；
2. 换传输（gRPC → gRPC-Web → 本地进程内）时不需要碰循环逻辑。

# 为什么走 gRPC 而不是直接 import Go 侧逻辑

Go 侧是独立进程，且闸门链（Scope → Gateway → Sandbox → Ledger）都在
`IngestService.Execute` 内部。**只有走服务接口才不可能绕过闸门** ——
`07` §T7 要求"MCP 路径与 CLI/WebUI 走同一套校验，不得有特权路径"，
Agent 池同理。若这里改成直接调用某个内部函数，就凭空造出了一条特权路径。

# proto 映射的注意点

`proto` 的 `Task.status` 用的是 `TaskStatus` 枚举，循环内部用字符串
（"DONE"/"FAILED"/"SKIPPED"）。映射集中在本文件，避免枚举字面量
散落到业务逻辑里 —— 那样 proto 一改就要全局搜索。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aletheia.execution.loop import TaskOutcome
from aletheia.execution.planner import PlanDraft


def _pb2() -> Any:
    """延迟导入生成的 protobuf 模块。

    延迟的理由：`tests/execution/` 里的纯逻辑测试不该因为
    protobuf 环境问题而整体失败（它们是两件事）。
    """
    from aletheia.gen.aleth.v1 import aletheia_pb2

    return aletheia_pb2


def _pb2_grpc() -> Any:
    from aletheia.gen.aleth.v1 import aletheia_pb2_grpc

    return aletheia_pb2_grpc


#: 循环内部状态 → proto 枚举名。
_STATUS_TO_PROTO: dict[str, str] = {
    "DONE": "DONE",
    "FAILED": "FAILED",
    "SKIPPED": "SKIPPED",
}


@dataclass
class GrpcOrchestratorPort:
    """`OrchestratorPort` 的 gRPC 实现。

    `stub` 由调用方传入（通常是 `OrchestratorServiceStub(channel)`），
    这样本类不负责连接生命周期 —— 连接的建立/关闭属于进程编排，
    混进来会让测试很难写。
    """

    stub: Any

    def plan(self, session_id: str, draft: PlanDraft, budget_tokens: int) -> str:
        pb2 = _pb2()
        graph = pb2.TaskGraph(
            session_id=session_id,
            plan_rationale=draft.rationale,
            tasks=[
                pb2.Task(
                    task_id=t.task_id,
                    title=t.title,
                    objective=t.objective,
                    required_role=_role_enum(t.role),
                    depends_on=list(t.depends_on),
                    budget_tokens=t.budget_tokens,
                )
                for t in draft.tasks
            ],
        )
        resp = self.stub.Plan(
            pb2.PlanRequest(
                session_id=session_id,
                proposed_graph=graph,
                budget_tokens=budget_tokens,
            )
        )
        return resp.graph_id

    def next_ready(self, session_id: str, graph_id: str, slots: int) -> list[str]:
        pb2 = _pb2()
        resp = self.stub.NextReady(
            pb2.NextReadyRequest(session_id=session_id, graph_id=graph_id, available_slots=slots)
        )
        return list(resp.ready_task_ids)

    def report(self, session_id: str, outcome: TaskOutcome) -> None:
        pb2 = _pb2()
        proto_status = _STATUS_TO_PROTO.get(outcome.status)
        if proto_status is None:
            # fail-closed：未知状态不得猜一个默认值写进账本。
            raise ValueError(f"未知任务状态 {outcome.status!r}；允许：{sorted(_STATUS_TO_PROTO)}")
        self.stub.ReportTaskResult(
            pb2.ReportTaskResultRequest(
                session_id=session_id,
                task_id=outcome.task_id,
                status=getattr(pb2.TaskStatus.Value(proto_status), "__int__", None)
                or pb2.TaskStatus.Value(proto_status),
                failures=[
                    pb2.FailureRecord(failure_type=f[0], detail=f[1], refiner_guidance=f[2])
                    for f in outcome.failures
                ],
                produced_evidence=list(outcome.produced_evidence),
            )
        )


def _role_enum(proto_name: str) -> int:
    """角色名 → proto `AgentRole` 枚举值。"""
    pb2 = _pb2()
    try:
        return pb2.AgentRole.Value(proto_name)
    except ValueError as exc:
        raise ValueError(f"未知 Agent 角色 {proto_name!r}") from exc
