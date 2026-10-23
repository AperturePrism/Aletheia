// ApertureService 的 ServiceDefinition（手写，ts-proto 结构）。
//
// 与 ledgerDefinition.ts / prismDefinition.ts 同一做法与同一理由：
// ts-proto v2.12.4 的 outputServices=nice-grpc 只生成 *ServiceClient 接口，
// 不输出 definition 常量，而接口无法实例化。requestType/responseType 直接
// 引用 @gen/ 生成物的消息常量 —— **本文件零手写消息类型**（Q14 保持）。

import type { TsProtoServiceDefinition } from "nice-grpc-web/lib/service-definitions/ts-proto";
import {
  AssembleRequest,
  AutofocusRequest,
  AutofocusResult,
  ContextBundle,
} from "@gen/aleth/v1/aletheia";

export const ApertureServiceDefinition: TsProtoServiceDefinition = {
  name: "ApertureService",
  fullName: "aleth.v1.ApertureService",
  methods: {
    assemble: {
      name: "Assemble",
      requestType: AssembleRequest,
      requestStream: false,
      responseType: ContextBundle,
      responseStream: false,
      options: {},
    },
    autofocus: {
      name: "Autofocus",
      requestType: AutofocusRequest,
      requestStream: false,
      responseType: AutofocusResult,
      responseStream: false,
      options: {},
    },
  },
};

const EXPECTED_METHODS = ["assemble", "autofocus"] as const;

for (const m of EXPECTED_METHODS) {
  if (!(m in ApertureServiceDefinition.methods)) {
    throw new Error(`ApertureServiceDefinition missing method: ${m}`);
  }
}
