// PrismService 的 ServiceDefinition（手写，ts-proto 结构）。
//
// 与 ledgerDefinition.ts 同一做法与同一理由：ts-proto v2.12.4 的
// outputServices=nice-grpc 只生成 *ServiceClient 接口，不输出 definition
// 常量，而接口无法实例化。requestType/responseType 直接引用 @gen/ 生成物
// 的消息常量（nice-grpc-web 运行时从它们取 encode/decode），零手写序列化。
//
// Q14（前端 TS 类型由 Protobuf 生成）在此保持：本文件不含任何手写消息类型，
// 只声明方法名与消息常量的对应关系。

import type { TsProtoServiceDefinition } from "nice-grpc-web/lib/service-definitions/ts-proto";
import {
  EvidenceSpectrum,
  IngestResult,
  ProjectRequest,
  ProjectedSubgraph,
  SnapshotAtRequest,
  CreateBranchRequest,
  BranchInfo,
  RollbackBranchRequest,
  RollbackResult,
  MergeBranchRequest,
  MergeResult,
} from "@gen/aleth/v1/aletheia";

export const PrismServiceDefinition: TsProtoServiceDefinition = {
  name: "PrismService",
  fullName: "aleth.v1.PrismService",
  methods: {
    ingest: {
      name: "Ingest",
      requestType: EvidenceSpectrum,
      requestStream: false,
      responseType: IngestResult,
      responseStream: false,
      options: {},
    },
    project: {
      name: "Project",
      requestType: ProjectRequest,
      requestStream: false,
      responseType: ProjectedSubgraph,
      responseStream: false,
      options: {},
    },
    snapshotAt: {
      name: "SnapshotAt",
      requestType: SnapshotAtRequest,
      requestStream: false,
      responseType: ProjectedSubgraph,
      responseStream: false,
      options: {},
    },
    createBranch: {
      name: "CreateBranch",
      requestType: CreateBranchRequest,
      requestStream: false,
      responseType: BranchInfo,
      responseStream: false,
      options: {},
    },
    rollbackBranch: {
      name: "RollbackBranch",
      requestType: RollbackBranchRequest,
      requestStream: false,
      responseType: RollbackResult,
      responseStream: false,
      options: {},
    },
    mergeBranch: {
      name: "MergeBranch",
      requestType: MergeBranchRequest,
      requestStream: false,
      responseType: MergeResult,
      responseStream: false,
      options: {},
    },
  },
};

// 防呆断言：方法集合必须与契约一致（缺方法在加载期立即暴露，
// 而不是静默变成 UNIMPLEMENTED）。
const EXPECTED_METHODS = [
  "ingest",
  "project",
  "snapshotAt",
  "createBranch",
  "rollbackBranch",
  "mergeBranch",
] as const;

for (const m of EXPECTED_METHODS) {
  if (!(m in PrismServiceDefinition.methods)) {
    throw new Error(`PrismServiceDefinition missing method: ${m}`);
  }
}
