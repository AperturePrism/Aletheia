// 与 alethd 通信的客户端层。
//
// 三层职责，全部集中在此（单一入口）：
//
//  1. 传输 —— nice-grpc-web（WebSocket transport）。
//     依据 docs/06 §8：实时通信用 WebSocket（降级 SSE）。
//     gRPC-over-WebSocket 让前端直接按 05 契约调用服务，
//     不需要另拆一套 HTTP+JSON 接口（docs/04 §I0 关键决策①：
//     "推荐 gRPC（Protobuf 强类型，契约定死），但保留 HTTP+JSON 作为调试通道"）。
//
//  2. 脱敏断言 —— Q12 门禁：前端无法直接访问真实凭据。
//     凡是可能携带真实值的响应路径，都在这里做一次断言
//     （见 assertNoCredentialLeak）。这是"凭据不入前端"
//     （docs/02 §11.3 / docs/07 §T5.3）的执行点。
//
//  3. UNIMPLEMENTED 识别 —— I0 阶段大量服务返回 Unimplemented。
//     这里把它转成可判定的类型，让 UI 能区分
//     "该能力还没交付" 与 "该能力返回了空结果"。
//     不区分的话，未交付会被显示成"没有数据"——那是失真。
//
// 类型来源：web/src/gen/（proto/buf.gen.yaml 生成）。Q14 门禁要求
// 前端 TS 类型由 Protobuf 生成，禁止手工维护重复类型。

import { createChannel, createClientFactory } from "nice-grpc-web";
import type { ClientFactory } from "nice-grpc-web";
import type {
  IngestServiceClient,
  PrismServiceClient,
  ApertureServiceClient,
  LedgerServiceClient,
  TerminationServiceClient,
  OrchestratorServiceClient,
  ScopeServiceClient,
  GovernorServiceClient,
  SandboxServiceClient,
  GatewayServiceClient,
} from "@gen/aleth/v1/aletheia";

/** alethd 的 gRPC-Web 端点。 */
export const GRPC_ENDPOINT = `ws://${location.host}/grpc`;

export const channel = createChannel(GRPC_ENDPOINT);
export const clientFactory: ClientFactory = createClientFactory();

// 说明：05 契约当前只生成了 *ServiceClient / *ServiceImplementation 接口
// （ts-proto 的 outputServices=nice-grpc），没有生成 ServiceDefinition 常量，
// 而 nice-grpc-web 的 createClient() 需要它才能实例化客户端。
//
// 客户端实例化留到 I1 —— 那是第一次真正需要调用 IngestService 的迭代。
// 届时二选一（都不是现在凭猜测决定的事）：
//   a) 调整 buf.gen.yaml 让 ts-proto 同时输出 ServiceDefinition；
//   b) 在 web/src/lib 手写一份由生成类型约束的定义。
//
// 这里不预先写一个假的客户端工厂：那会在 I1 变成"看起来能调其实调不通"
// 的代码，正是 docs/09 §6 #4 反对的 mock。
//
// 2026-09-24 补充（I0 自检时发现）：生成的 *ServiceClient 接口已由
// nice-grpc-web 的 createClient() 消费，但其第一个参数
// （MethodDescriptor / ServiceDefinition）在生成产物中不存在。
// 因此 I0 只导出 channel 与 clientFactory，客户端实例化推迟到 I1。

/** 将来要实例化的客户端类型集合（提前登记，便于 I1 核对 10 个服务是否齐全）。 */
export type ServiceClients = {
  ingest: IngestServiceClient;
  prism: PrismServiceClient;
  aperture: ApertureServiceClient;
  ledger: LedgerServiceClient;
  termination: TerminationServiceClient;
  orchestrator: OrchestratorServiceClient;
  scope: ScopeServiceClient;
  governor: GovernorServiceClient;
  sandbox: SandboxServiceClient;
  gateway: GatewayServiceClient;
};


// ---------------------------------------------------------------------------
// UNIMPLEMENTED 识别
// ---------------------------------------------------------------------------

/** 标记"服务尚未交付"这一状态。 */
export class UnimplementedError extends Error {
  constructor(public readonly service: string) {
    super(`service ${service} is not implemented yet (see docs/04 §4 for the iteration that delivers it)`);
    this.name = "UnimplementedError";
  }
}

/** gRPC 状态码：UNIMPLEMENTED。 */
export const GRPC_CODE_UNIMPLEMENTED = 12;

/**
 * 把任意 RPC 错误分类为 UnimplementedError 或其他。
 *
 * 调用方据此显示"I2 交付"而不是"加载失败"——
 * 前者是诚实的状态，后者会让人误以为系统坏了。
 */
export function classifyError(service: string, err: unknown): unknown {
  const candidate = err as { code?: unknown } | null | undefined;
  if (
    candidate !== null &&
    typeof candidate === "object" &&
    candidate.code === GRPC_CODE_UNIMPLEMENTED
  ) {
    return new UnimplementedError(service);
  }
  return err;
}

// ---------------------------------------------------------------------------
// Q12 门禁：前端不得接触真实凭据
// ---------------------------------------------------------------------------

/**
 * 真实敏感值模式。
 *
 * 与 core/log 的 leakPatterns、modules/M6 §4.2 的 Python LEAK_PATTERNS
 * 同源同语义。三侧必须字面一致 —— 任一侧漏掉一类，
 * 就会出现"看起来脱敏了实际没脱敏"的漏洞。
 *
 * I3 起由 Privacy Gateway 在服务端阻断；这里是前端侧的兜底断言。
 */
const CREDENTIAL_PATTERNS: RegExp[] = [
  // 凭据键值。
  /(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S+/i,
  // 私有 IP（10/8、172.16/12、192.168/16）。
  /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/,
];

/**
 * 断言一段响应体不含真实凭据。
 *
 * 命中即抛错，而不是"记个日志继续"。
 *
 * 为什么客户端也要做：服务端阻断是主防线（modules/M6 §4.2），
 * 但 Q12 门禁要求"前端无法直接访问真实凭据"这一属性本身可验证。
 * 客户端断言让违规在开发期立刻暴露。
 */
export function assertNoCredentialLeak(context: string, text: string): void {
  CREDENTIAL_PATTERNS.forEach((re, i) => {
    if (re.test(text)) {
      throw new Error(
        `Q12 violation in ${context}: pattern #${i + 1} matched a real sensitive value. ` +
          `Credentials must never reach the frontend (docs/07 §T5.3).`,
      );
    }
  });
}
