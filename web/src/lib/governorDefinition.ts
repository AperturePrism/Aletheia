// GovernorService 的 ServiceDefinition（手写，ts-proto 结构）。
//
// 与 ledgerDefinition.ts / prismDefinition.ts / apertureDefinition.ts 同一
// 做法与同一理由：ts-proto v2.12.4 的 outputServices=nice-grpc 只生成
// *ServiceClient 接口，不输出 definition 常量。请求/响应类型直接引用
// @gen/ 生成物 —— **本文件零手写消息类型**（Q14 保持）。

import type { TsProtoServiceDefinition } from "nice-grpc-web/lib/service-definitions/ts-proto";
import {
  BudgetState,
  BudgetStateRequest,
  CircuitCheckRequest,
  CircuitState,
  ConsumeRequest,
  ReserveRequest,
  ReserveResult,
} from "@gen/aleth/v1/aletheia";

export const GovernorServiceDefinition: TsProtoServiceDefinition = {
  name: "GovernorService",
  fullName: "aleth.v1.GovernorService",
  methods: {
    reserve: {
      name: "Reserve",
      requestType: ReserveRequest,
      requestStream: false,
      responseType: ReserveResult,
      responseStream: false,
      options: {},
    },
    consume: {
      name: "Consume",
      requestType: ConsumeRequest,
      requestStream: false,
      responseType: BudgetState,
      responseStream: false,
      options: {},
    },
    state: {
      name: "State",
      requestType: BudgetStateRequest,
      requestStream: false,
      responseType: BudgetState,
      responseStream: false,
      options: {},
    },
    checkCircuit: {
      name: "CheckCircuit",
      requestType: CircuitCheckRequest,
      requestStream: false,
      responseType: CircuitState,
      responseStream: false,
      options: {},
    },
  },
};

const EXPECTED_METHODS = ["reserve", "consume", "state", "checkCircuit"] as const;

for (const m of EXPECTED_METHODS) {
  if (!(m in GovernorServiceDefinition.methods)) {
    throw new Error(`GovernorServiceDefinition missing method: ${m}`);
  }
}
