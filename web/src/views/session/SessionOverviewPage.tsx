import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { DaemonStatusCard } from "../../components/DaemonStatusCard";
import { EmptyState } from "../../components/EmptyState";

// 06 §6.1 页面 1 —— 会话总览（I0 交付，最小可用版本）。
//
// 页面职责（06 §6.1）：会话列表、状态、成本、进度、风险摘要。
//
// I0 的范围说明：alethd 的 API 在 I0 全部是 UNIMPLEMENTED
// （core/api/server/registry.go），因此这里**没有假数据**。
// 用 EmptyState 明确告知"daemon 未连接"，而不是渲染一组看起来很正常的
// 假会话 —— 那正是本项目最反对的行为（docs/09 §6 #4：
// mock 会掩盖契约不一致，也让测试失去意义）。
//
// 此页面在 I0 的主要用途：确认 WebUI 产物可嵌入二进制并正常服务
// （Q11 门禁），以及为 P0 阶段的 24h 稳定性测试提供观察入口
// （docs/06 §10.1）。
export function SessionOverviewPage() {
  const [daemonReachable, setDaemonReachable] = useState<boolean | null>(null);

  useEffect(() => {
    // 探测 daemon 是否在监听。失败不等于错误 —— I0 阶段 daemon
    // 未启动是正常状态，因此只作为状态展示。
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);

    fetch("/api/health", { signal: controller.signal })
      .then((res) => setDaemonReachable(res.ok))
      .catch(() => setDaemonReachable(false))
      .finally(() => clearTimeout(timer));

    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, []);

  return (
    <section className="page">
      <header className="page-header">
        <h1>会话总览</h1>
        <p className="page-subtitle">
          06 §6.1 页面 1 ｜ 会话列表 · 状态 · 成本 · 进度 · 风险摘要
        </p>
      </header>

      <DaemonStatusCard reachable={daemonReachable} />

      {daemonReachable === false ? (
        <EmptyState
          title="未连接到 alethd"
          description={
            <>
              <p>
                alethd 尚未启动。会话列表、成本、进度、风险摘要都需要 daemon 提供数据 ——
                I0 阶段这些能力标注为 UNIMPLEMENTED，因此页面不会渲染任何示例数据。
              </p>
              <p className="mono-block">
                aleth daemon start --authorization roe.yaml
              </p>
              <p className="empty-hint">
                依据 <code>docs/08</code> §1：无授权凭证不启动（退出码 3）。
              </p>
            </>
          }
        />
      ) : (
        <EmptyState
          title="暂无会话"
          description="daemon 已连接，但没有会话记录。新会话由 WebUI 创建的能力在 I6（编排层）交付。"
        />
      )}

      <section className="page-section">
        <h2>P0 阶段要验证什么</h2>
        <p>
          当前迭代 <strong>I0 · 仓库骨架与抽象层</strong>。它的 DoD 是
          <code>make build &amp;&amp; make test &amp;&amp; make lint</code> 全绿，
          以及 <strong>WebUI 产物可嵌入单一二进制并正常服务</strong>
          （<code>docs/04</code> §I0 DoD）。
        </p>
        <ul>
          <li>
            观察 P0 的 24h 稳定性测试 → <Link to="/live">实时执行流</Link>（本迭代交付）
          </li>
          <li>
            证据链视图（I2）—— 验证"系统是否在幻觉"的唯一界面
          </li>
          <li>
            光圈上下文视图（I5）—— 诊断"系统是不是漏看了什么"的唯一界面
          </li>
          <li>
            冲突矩阵视图（I8）—— "打不通但有缺陷"这个最高价值象限的呈现方式
          </li>
        </ul>
        <p className="empty-hint">
          后三项是本项目的核心视图（<code>docs/09</code> R9：允许简化视觉细节，不允许省略功能与信息密度）。
        </p>
      </section>
    </section>
  );
}
