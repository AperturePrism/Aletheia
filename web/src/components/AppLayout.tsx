import { NavLink, Outlet } from "react-router-dom";

// 应用外壳：侧边导航 + 内容区。
//
// 导航项与 docs/06 §6.1 的页面清单一一对应，顺序与编号一致 ——
// 便于逐项核对（10 §3 P10 交付物缺失检测的一个锚点）。
//
// 标记说明：
//   ★  本项目三个核心视图（docs/09 R9：不可省略）
//   I{n} 该页面的交付迭代
export function AppLayout() {
  return (
    <div className="app-shell">
      <aside className="app-nav">
        <div className="app-brand">
          <span className="app-brand-name">Aletheia</span>
          <span className="app-brand-team">AperturePrism</span>
        </div>

        <nav>
          <NavSection label="会话">
            <NavItem to="/" label="会话总览" iteration="I0" />
            <NavItem to="/live" label="实时执行流" iteration="I0" />
          </NavSection>

          <NavSection label="认知">
            <NavItem to="/map" label="心智地图浏览器" iteration="I4" module="M2" />
            <NavItem to="/aperture" label="光圈上下文视图" core iteration="I5" module="M3" />
          </NavSection>

          <NavSection label="可证明性">
            <NavItem to="/evidence" label="证据链视图" core iteration="I2" module="M4" />
          </NavSection>

          <NavSection label="融合与决策">
            <NavItem to="/conflicts" label="冲突矩阵视图" core iteration="I8" module="M7" />
            <NavItem to="/decisions" label="人机协同决策队列" iteration="I6" module="M5" />
          </NavSection>

          <NavSection label="治理">
            <NavItem to="/scope" label="范围与授权管理" iteration="I3" module="M6" />
            <NavItem to="/cost" label="成本与预算面板" iteration="I6" module="M6" />
            <NavItem to="/report" label="报告与导出" iteration="I11" module="M9" />
          </NavSection>
        </nav>

        <footer className="app-nav-footer">
          <p>
            I0 · 仓库骨架与抽象层
          </p>
          <p className="app-nav-hint">
            主界面是 WebUI（<code>docs/06</code> §3.3）；
            <code>aleth</code> CLI 是控制平面。
          </p>
        </footer>
      </aside>

      <main className="app-main">
        <Outlet />
      </main>
    </div>
  );
}

function NavSection(props: { label: string; children: React.ReactNode }) {
  return (
    <div className="nav-section">
      <div className="nav-section-label">{props.label}</div>
      {props.children}
    </div>
  );
}

interface NavItemProps {
  to: string;
  label: string;
  /** 交付迭代。UI 上显示出来，避免使用者误以为未列出的功能不存在。 */
  iteration: string;
  module?: string;
  /** 三个核心视图之一。 */
  core?: boolean;
}

function NavItem(props: NavItemProps) {
  return (
    <NavLink
      to={props.to}
      end={props.to === "/"}
      className={({ isActive }) => (isActive ? "nav-item nav-item-active" : "nav-item")}
    >
      <span className="nav-item-label">
        {props.core ? <span className="nav-star" aria-label="核心视图">★</span> : null}
        {props.label}
      </span>
      <span className="nav-item-iteration">{props.iteration}</span>
    </NavLink>
  );
}
