// LedgerService 的 ServiceDefinition（手写，ts-proto 结构）。
//
// 为什么手写（docs/09 §6 #4 的反向思考 + api.ts 记录的两条路之一）：
// ts-proto v2.12.4 的 outputServices=nice-grpc 只生成 *ServiceClient 接口，
// 不输出 definition 常量 —— 而接口本身无法实例化。
// 本文件的 requestType/responseType 直接引用 **@gen/ 生成物的消息常量**
//（nice-grpc-web 运行时从它们取 encode/decode），零手写序列化逻辑；
// 方法集合由 tests/test_contract_consistency.py 校验兜底，防止契约
// 演化时手写定义漂移。
//
// 只覆盖本迭代前端需要的服务（LedgerService，06 页面 4 的数据源）；
// 其余服务的 definition 待各自交付迭代按需添加。

import type { TsProtoServiceDefinition } from "nice-grpc-web/lib/service-definitions/ts-proto";
import {
  AppendEvidenceRequest,
  AppendEvidenceResult,
  RecordSideEffectRequest,
  RecordSideEffectResult,
  ReproduceRequest,
  ReproduceResult,
  ReportHallucinationRequest,
  HallucinationState,
  TraceFindingRequest,
  TracedEvidenceChain,
  ValidateAssertionRequest,
  ValidateAssertionResult,
} from "@gen/aleth/v1/aletheia";

export const LedgerServiceDefinition: TsProtoServiceDefinition = {
  name: "LedgerService",
  fullName: "aleth.v1.LedgerService",
  methods: {
    append: {
      name: "Append",
      requestType: AppendEvidenceRequest,
      requestStream: false,
      responseType: AppendEvidenceResult,
      responseStream: false,
      options: {},
    },
    validateAssertion: {
      name: "ValidateAssertion",
      requestType: ValidateAssertionRequest,
      requestStream: false,
      responseType: ValidateAssertionResult,
      responseStream: false,
      options: {},
    },
    recordSideEffect: {
      name: "RecordSideEffect",
      requestType: RecordSideEffectRequest,
      requestStream: false,
      responseType: RecordSideEffectResult,
      responseStream: false,
      options: {},
    },
    reproduce: {
      name: "Reproduce",
      requestType: ReproduceRequest,
      requestStream: false,
      responseType: ReproduceResult,
      responseStream: false,
      options: {},
    },
    traceFinding: {
      name: "TraceFinding",
      requestType: TraceFindingRequest,
      requestStream: false,
      responseType: TracedEvidenceChain,
      responseStream: false,
      options: {},
    },
    reportHallucination: {
      name: "ReportHallucination",
      requestType: ReportHallucinationRequest,
      requestStream: false,
      responseType: HallucinationState,
      responseStream: false,
      options: {},
    },
  },
};

// 防呆断言：方法集合必须与契约一致（缺方法在加载期立即暴露，
// 而不是静默变成 UNIMPLEMENTED）。
const EXPECTED_METHODS = [
  "append",
  "validateAssertion",
  "recordSideEffect",
  "reproduce",
  "traceFinding",
  "reportHallucination",
] as const;

for (const m of EXPECTED_METHODS) {
  if (!(m in LedgerServiceDefinition.methods)) {
    throw new Error(`LedgerServiceDefinition missing method: ${m}`);
  }
}
