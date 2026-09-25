import { useCallback, useEffect, useState } from "react";
import { EmptyState } from "../../components/EmptyState";

// 06 §6.1 页面 9 —— 范围与授权管理（I3 交付，最小可用版）。
//
// 页面职责（06 §6.1）：scope 摘要（include/exclude 规则、默认拒绝策略）、
// 授权凭证状态、越界拦截审计入口。
//
// I3 范围说明（06 §6.1 原文）：授权凭证录入走 CLI 而非 WebUI ——
// 避免用户在没有授权凭证时启动界面（08 §1.1 的授权锚定语义）。
// 本页面因此是**只读**的：录入/修改 scope 必须停止会话 → 改 roe.yaml →
// CLI 重新提交（08 §5.4，scope 不可热改）。

type ScopeInfoLite = {
  include: string[];
  exclude: string[];
  denialPolicy: string;
};

export function ScopeAuthorizationPage() {
  const [state, setState] = useState<
    { kind: "loading" } | { kind: "loaded"; info: ScopeInfoLite } | { kind: "unavailable"; detail: string }
  >({ kind: "loading" });

  const load = useCallback(() => {
    setState({ kind: "loading" });
    // I3 的 scope 摘要经 alethd 的 HTTP 调试通道或 CLI 导出获取；
    // gRPC LoadScope 需要 roe 路径（服务端已有），WebUI 侧在
    // api 通道就绪后接入。此处如实展示状态，不渲染假数据。
    setState({
      kind: "unavailable",
      detail:
        "范围摘要在 alethd 以 --authorization 启动后可用（CLI: aleth status）。" +
        "本页按 08 §5.4 只读呈现 —— scope 变更必须停止会话后改 roe.yaml 重新提交。",
    });
  }, []);

  useEffect(load, [load]);

  return (
    <section>
      <h1>范围与授权管理</h1>
      <p className="page-hint">
        授权是物理前置条件，边界是内核级约束 —— 本页只读展示，录入走 CLI。
      </p>

      {state.kind === "loading" && <p>加载中…</p>}
      {state.kind === "unavailable" && (
        <EmptyState title="范围摘要不可用" description={state.detail} />
      )}
      {state.kind === "loaded" && <ScopeView info={state.info} />}
    </section>
  );
}

function ScopeView({ info }: { info: ScopeInfoLite }) {
  return (
    <div className="scope-view">
      <div className="scope-policy">
        拒绝策略：{info.denialPolicy}（exclude 永远优先于 include）
      </div>
      <h2>包含目标（{info.include.length}）</h2>
      <ul>
        {info.include.map((r, i) => (
          <li key={i}>
            <code>{r}</code>
          </li>
        ))}
      </ul>
      <h2>排除目标（{info.exclude.length}）</h2>
      <ul>
        {info.exclude.map((r, i) => (
          <li key={i} className="scope-exclude">
            <code>{r}</code>
          </li>
        ))}
      </ul>
      <div className="scope-note">
        <h3>授权锚定（08 §1.1）</h3>
        <ul>
          <li>无凭证不启动 —— 拒绝启动而非警告（退出码 3）</li>
          <li>校验发生在绑定端口之前，不留“先跑起来再校验”的窗口</li>
          <li>scope 不可热改：停止会话 → 改 roe.yaml → CLI 重新提交</li>
        </ul>
      </div>
    </div>
  );
}
