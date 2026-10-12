// OrchestratorService 的 ServiceDefinition（手写，ts-proto 结构）。
//
// 与其他 definition 同一做法：ts-proto 只生成 *ServiceClient 接口，
// 不输出 definition 常量。请求/响应类型直接引用 @gen/ 生成物。
//
// 用途：人机协同决策队列（06 页面 7）需要读取任务图与失败记录 ——
// 决策项来自"任务处于 FAILED / 需要人工确认"的状态。

import type { TsProtoServiceDefinition } from "nice-grpc-web/lib/service-definitions/ts-proto";
import {
  CheckpointInfo,
  CheckpointRequest,
  ForkRequest,
  ForkResult,
  NextReadyRequest,
  NextReadyResponse,
  PlanRequest,
  RefineRequest,
  ReportTaskResultRequest,
  RewindRequest,
  RewindResult,
  TaskGraph,
  TaskUpdateResult,
} from "@gen/aleth/v1/aletheia";

export const OrchestratorServiceDefinition: TsProtoServiceDefinition = {
  name: "OrchestratorService",
  fullName: "aleth.v1.OrchestratorService",
  methods: {
    plan: {
      name: "Plan",
      requestType: PlanRequest,
      requestStream: false,
      responseType: TaskGraph,
      responseStream: false,
      options: {},
    },
    nextReady: {
      name: "NextReady",
      requestType: NextReadyRequest,
      requestStream: false,
      responseType: NextReadyResponse,
      responseStream: false,
      options: {},
    },
    reportTaskResult: {
      name: "ReportTaskResult",
      requestType: ReportTaskResultRequest,
      requestStream: false,
      responseType: TaskUpdateResult,
      responseStream: false,
      options: {},
    },
    refine: {
      name: "Refine",
      requestType: RefineRequest,
      requestStream: false,
      responseType: TaskGraph,
      responseStream: false,
      options: {},
    },
    checkpoint: {
      name: "Checkpoint",
      requestType: CheckpointRequest,
      requestStream: false,
      responseType: CheckpointInfo,
      responseStream: false,
      options: {},
    },
    rewind: {
      name: "Rewind",
      requestType: RewindRequest,
      requestStream: false,
      responseType: RewindResult,
      responseStream: false,
      options: {},
    },
    fork: {
      name: "Fork",
      requestType: ForkRequest,
      requestStream: false,
      responseType: ForkResult,
      responseStream: false,
      options: {},
    },
  },
};

const EXPECTED_METHODS = [
  "plan",
  "nextReady",
  "reportTaskResult",
  "refine",
  "checkpoint",
  "rewind",
  "fork",
] as const;

for (const m of EXPECTED_METHODS) {
  if (!(m in OrchestratorServiceDefinition.methods)) {
    throw new Error(`OrchestratorServiceDefinition missing method: ${m}`);
  }
}
