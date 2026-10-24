import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  IconAperture,
  IconChain,
  IconChecks,
  IconCrosshair,
  IconDoc,
  IconGauge,
  IconGraph,
  IconGrid,
  IconLogo,
  IconMatrix,
  IconPulse,
} from "./icons";
import { applyThemeChoice, readThemeChoice, watchThemeChange, type ThemeChoice } from "../lib/theme";

// 应用外壳：侧边导航 + 顶栏（面包屑 / daemon 状态 / 主题切换）+ 内容区。
//
// 导航项与 docs/06 §6.1 的页面清单一一对应，顺序与编号一致 ——
// 便于逐项核对（10 §3 P10 交付物缺失检测的一个锚点）。
//
// 标记说明：
//   ★  本项目三个核心视图（docs/09 R9：不可省略）
//   I{n} 该页面的交付迭代

interface NavEntry {
  to: string;
  label: string;
  icon: (p: { size?: number }) => React.JSX.Element;
  iteration: string;
  module?: string;
  core?: boolean;
}

const NAV_SECTIONS: { group: string; items: NavEntry[] }[] = [
  {
    group: "会话",
    items: [
      { to: "/", label: "会话总览", icon: IconGrid, iteration: "I0" },
      { to: "/live", label: "实时执行流", icon: IconPulse, iteration: "I0" },
    ],
  },
  {
    group: "认知",
    items: [
      { to: "/map", label: "心智地图浏览器", icon: IconGraph, iteration: "I4", module: "M2" },
      { to: "/aperture", label: "光圈上下文视图", icon: IconAperture, iteration: "I5", module: "M3", core: true },
    ],
  },
  {
    group: "可证明性",
    items: [
      { to: "/evidence", label: "证据链视图", icon: IconChain, iteration: "I2", module: "M4", core: true },
    ],
  },
  {
    group: "融合与决策",
    items: [
      { to: "/conflicts", label: "冲突矩阵视图", icon: IconMatrix, iteration: "I8", module: "M7", core: true },
      { to: "/decisions", label: "人机协同决策队列", icon: IconChecks, iteration: "I6", module: "M5" },
    ],
  },
  {
    group: "治理",
    items: [
      { to: "/scope", label: "范围与授权管理", icon: IconCrosshair, iteration: "I3", module: "M6" },
      { to: "/cost", label: "成本与预算面板", icon: IconGauge, iteration: "I6", module: "M6" },
      { to: "/report", label: "报告与导出", icon: IconDoc, iteration: "I11", module: "M9" },
    ],
  },
];

const ALL_NAV = NAV_SECTIONS.flatMap((s) => s.items.map((i) => ({ ...i, group: s.group })));

export function AppLayout() {
  const location = useLocation();

  // 面包屑：按当前路径匹配导航项。/evidence/:id 归并到证据链视图。
  const current =
    ALL_NAV.find((n) => n.to === location.pathname) ??
    ALL_NAV.find((n) => n.to !== "/" && location.pathname.startsWith(n.to));

  return (
    <div className="app-shell">
      <aside className="app-nav">
        <div className="app-brand">
          <span className="app-brand-mark">
            <IconLogo size={22} />
          </span>
          <div className="app-brand-text">
            <span className="app-brand-name">Aletheia</span>
            <span className="app-brand-team">AperturePrism</span>
          </div>
        </div>

        <nav>
          {NAV_SECTIONS.map((section) => (
            <div className="nav-section" key={section.group}>
              <div className="nav-section-label">{section.group}</div>
              {section.items.map((item) => (
                <NavItem key={item.to} {...item} />
              ))}
            </div>
          ))}
        </nav>

        <footer className="app-nav-footer">
          <p>
            结论只能由证据显现 —— <code>docs/09</code> R4
          </p>
          <p className="app-nav-hint">
            WebUI 是观察面；<code>aleth</code> CLI 是控制平面（<code>docs/06</code> §3.3）。
          </p>
        </footer>
      </aside>

      <div className="app-body">
        <header className="topbar">
          <div className="topbar-crumb">
            {current ? (
              <>
                <span className="topbar-crumb-group">{current.group}</span>
                <span className="topbar-crumb-sep" aria-hidden="true">/</span>
                <span className="topbar-crumb-page">{current.label}</span>
              </>
            ) : (
              <span className="topbar-crumb-page">{location.pathname}</span>
            )}
          </div>
          <div className="topbar-actions">
            <DaemonPill />
            <ThemeSwitch />
          </div>
        </header>

        <main className="app-main">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function NavItem(props: NavEntry) {
  const Icon = props.icon;
  return (
    <NavLink
      to={props.to}
      end={props.to === "/"}
      className={({ isActive }) => (isActive ? "nav-item nav-item-active" : "nav-item")}
    >
      <span className="nav-item-icon">
        <Icon />
      </span>
      <span className="nav-item-label">
        {props.core ? <span className="nav-star" aria-label="核心视图">★</span> : null}
        {props.label}
      </span>
      <span className="nav-item-iteration">{props.iteration}</span>
    </NavLink>
  );
}

/** 顶栏 daemon 探测：与 SessionOverviewPage 的探测相互独立（都是轻量 GET）。 */
function DaemonPill() {
  const [reachable, setReachable] = useState<boolean | null>(null);

  useEffect(() => {
    const probe = () => {
      fetch("/api/health")
        .then((res) => setReachable(res.ok))
        .catch(() => setReachable(false));
    };
    probe();
    // 回到页面时重探一次（长时间挂着观察 24h 测试的场景）。
    window.addEventListener("focus", probe);
    return () => window.removeEventListener("focus", probe);
  }, []);

  const state = reachable === null ? "unknown" : reachable ? "up" : "down";
  const label = reachable === null ? "探测中" : reachable ? "alethd 在线" : "alethd 未连接";

  return (
    <span className={`daemon-pill daemon-pill-${state}`} title="GET /api/health">
      <span className="daemon-pill-dot" aria-hidden="true" />
      {label}
    </span>
  );
}

/** 主题切换：深 / 浅 / 系统 三段。 */
function ThemeSwitch() {
  const [choice, setChoice] = useState<ThemeChoice>(() => readThemeChoice());

  useEffect(() => {
    if (choice !== "system") return;
    // 跟随系统时，系统偏好变化要实时反映。
    return watchThemeChange(() => applyThemeChoice("system"));
  }, [choice]);

  const pick = (c: ThemeChoice) => {
    setChoice(c);
    applyThemeChoice(c);
  };

  const options: { value: ThemeChoice; label: string }[] = [
    { value: "dark", label: "深" },
    { value: "light", label: "浅" },
    { value: "system", label: "自动" },
  ];

  return (
    <div className="theme-switch" role="group" aria-label="主题">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          className={`theme-option ${choice === o.value ? "theme-option-active" : ""}`}
          aria-pressed={choice === o.value}
          onClick={() => pick(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
