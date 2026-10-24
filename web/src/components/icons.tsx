// 内联 SVG 图标集。
//
// 约定：viewBox 24、stroke 1.7、round cap/join、currentColor ——
// 不引入图标库依赖（数据主权 G6：产物不向任何外部域发请求），
// 尺寸由使用处的 CSS 控制（默认 16px，见 app.css 的 .nav-item-icon）。

type IconProps = { size?: number; className?: string };

function svgProps(props: IconProps) {
  return {
    width: props.size ?? 16,
    height: props.size ?? 16,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.7,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
    className: props.className,
  };
}

/** 会话总览：四宫格。 */
export function IconGrid(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.8" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.8" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.8" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="1.8" />
    </svg>
  );
}

/** 实时执行流：脉冲。 */
export function IconPulse(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <path d="M2.5 12h4l2.5-6.5 4 13 2.5-6.5h6" />
    </svg>
  );
}

/** 心智地图：节点图。 */
export function IconGraph(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <circle cx="5.5" cy="6" r="2.4" />
      <circle cx="18.5" cy="5" r="2.4" />
      <circle cx="12" cy="18.5" r="2.6" />
      <path d="M7.6 7.2 10.6 16M16.6 6.6l-3.6 9.6M8 5.6h8" />
    </svg>
  );
}

/** 光圈上下文：对焦环。 */
export function IconAperture(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <circle cx="12" cy="12" r="8.5" />
      <circle cx="12" cy="12" r="3.4" />
      <path d="M12 1.8v3.4M12 18.8v3.4M1.8 12h3.4M18.8 12h3.4" />
    </svg>
  );
}

/** 证据链：链环。 */
export function IconChain(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <path d="M10 13.5a4.2 4.2 0 0 0 6 0l3-3a4.24 4.24 0 0 0-6-6l-1.5 1.5" />
      <path d="M14 10.5a4.2 4.2 0 0 0-6 0l-3 3a4.24 4.24 0 0 0 6 6l1.5-1.5" />
    </svg>
  );
}

/** 冲突矩阵：四象限（一格实心 = 最高价值象限）。 */
export function IconMatrix(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <rect x="3.5" y="3.5" width="7.5" height="7.5" rx="1.6" fill="currentColor" stroke="none" opacity="0.9" />
      <rect x="13" y="3.5" width="7.5" height="7.5" rx="1.6" />
      <rect x="3.5" y="13" width="7.5" height="7.5" rx="1.6" />
      <rect x="13" y="13" width="7.5" height="7.5" rx="1.6" />
    </svg>
  );
}

/** 决策队列：勾选清单。 */
export function IconChecks(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <path d="M3.5 6.2l2 2 3.2-3.4M3.5 16.2l2 2 3.2-3.4" />
      <path d="M12 6.5h8.5M12 16.5h8.5" />
    </svg>
  );
}

/** 范围与授权：靶心。 */
export function IconCrosshair(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <circle cx="12" cy="12" r="8" />
      <circle cx="12" cy="12" r="2.6" />
      <path d="M12 1.8V6M12 18v4.2M1.8 12H6M18 12h4.2" />
    </svg>
  );
}

/** 成本与预算：仪表盘。 */
export function IconGauge(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <path d="M4 17a8.5 8.5 0 1 1 16 0" />
      <path d="M12 17l4.2-4.8" />
      <circle cx="12" cy="17" r="1.4" fill="currentColor" stroke="none" />
    </svg>
  );
}

/** 报告与导出：文档。 */
export function IconDoc(props: IconProps) {
  return (
    <svg {...svgProps(props)}>
      <path d="M6 2.8h8.5L19.5 8v13.2H6z" />
      <path d="M14.5 2.8V8h5" />
      <path d="M9 12.5h7M9 16.5h7" />
    </svg>
  );
}

/** 品牌：棱镜折射（六边形 + 分光）。 */
export function IconLogo(props: IconProps) {
  return (
    <svg {...svgProps(props)} strokeWidth={1.9}>
      <path d="M12 2.6 20.2 7.3v9.4L12 21.4 3.8 16.7V7.3z" />
      <path d="M8.6 8.2 12 12l3.4 3.8M8.6 15.8 12 12l3.4-3.8" opacity="0.55" />
    </svg>
  );
}
