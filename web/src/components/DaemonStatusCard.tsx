// daemon 连接状态卡片。
//
// 这张卡片存在的原因：安全默认（D19 / Q13）要求 daemon 默认仅监听 127.0.0.1。
// 使用者第一眼就该看到"服务在哪、是否只监听本机"——
// 这是本项目"不泄漏"承诺的第一道可观察证据。
export interface DaemonStatusCardProps {
  /** null = 探测中；true/false = 探测结果。 */
  reachable?: boolean | null;
}

export function DaemonStatusCard(props: DaemonStatusCardProps) {
  const state =
    props.reachable === null ? "unknown" : props.reachable ? "up" : "down";
  const text =
    props.reachable === null ? "探测中…" : props.reachable ? "已连接" : "未连接";

  return (
    <div className={`status-card status-${state}`}>
      <div className="status-card-main">
        <span className={`status-dot status-dot-${state}`} aria-hidden="true" />
        <div>
          <div className="status-card-title">alethd 守护进程</div>
          <div className="status-card-sub mono-block">http://127.0.0.1:7723</div>
        </div>
      </div>

      <div className="status-card-facts">
        <span className={`badge badge-${state}`}>{text}</span>
        <span className="fact">
          监听 <strong>127.0.0.1</strong>（仅本机）
        </span>
        <span className="fact">
          Privacy Gateway <strong>默认开启</strong>
        </span>
        <span className="fact">
          遥测 <strong>零</strong>
        </span>
      </div>

      <p className="status-card-note">
        安全默认依据 <code>docs/02</code> §11.3（D19）与 <code>docs/06</code> §5.1；
        仅监听回环地址对应 CI 门禁 Q13。对外监听需显式配置并提供 TLS 证书 ——
        无证书时拒绝对外暴露，而非自签降级。
      </p>
    </div>
  );
}
