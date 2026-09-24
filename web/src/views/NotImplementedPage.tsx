import { Link } from "react-router-dom";

// "该页面在后续迭代交付" 的占位页。
//
// 为什么用占位页而不是不注册路由：
//   本项目的三个差异化能力（证据链 / 光圈上下文 / 冲突矩阵）是立项理由
//   （docs/02 §12「立得住的三个第一」）。把它们从导航里藏起来，
//   使用者会以为项目不包含这些能力 —— 那是更差的信号。
//
// 因此这里明确写出：属于哪个迭代、哪个模块、为什么重要。
// 这是诚实性的一部分，不是"UI 没做完"的遮羞布。
export interface NotImplementedPageProps {
  pageName: string;
  iteration: string;
  module?: string;
  /** 三个核心视图之一（docs/09 R9）。 */
  coreView?: boolean;
}

export function NotImplementedPage(props: NotImplementedPageProps) {
  return (
    <section className="page page-placeholder">
      <h1>
        {props.pageName}
        {props.coreView ? <span className="badge-core">核心视图</span> : null}
      </h1>

      <dl className="placeholder-meta">
        <div>
          <dt>交付迭代</dt>
          <dd>
            <strong>{props.iteration}</strong>
          </dd>
        </div>
        {props.module ? (
          <div>
            <dt>负责模块</dt>
            <dd>
              <strong>{props.module}</strong>
            </dd>
          </div>
        ) : null}
      </dl>

      {props.coreView ? (
        <div className="callout callout-core">
          <p>
            <strong>这是本项目的核心视图，不可省略（<code>docs/09</code> R9）。</strong>
          </p>
          <p>
            它承载的是本项目相对竞品的差异化能力 ——
            如果这个能力用户感知不到，项目会退化成一个普通的 CLI 渗透 agent，
            而那个赛道上已有 PentestGPT、Strix 等成熟产品
            （<code>docs/06</code> §2.3）。
          </p>
          <p>
            当前迭代是 <strong>I0（仓库骨架与抽象层）</strong>，
            契约已冻结（<code>docs/05</code>）、路由已就位，实现按{" "}
            <code>docs/04</code> §4 的迭代顺序推进。
          </p>
        </div>
      ) : (
        <div className="callout">
          <p>
            当前迭代是 <strong>I0（仓库骨架与抽象层）</strong>，
            本页面在 <strong>{props.iteration}</strong> 交付。
            路由已在 <code>web/src/main.tsx</code> 中登记，
            因此功能缺口是可见的，而不是被藏起来的。
          </p>
        </div>
      )}

      <p>
        <Link to="/">返回会话总览</Link>
      </p>
    </section>
  );
}
