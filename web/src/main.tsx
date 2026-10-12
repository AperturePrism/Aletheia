import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { AppLayout } from "./components/AppLayout";
import { SessionOverviewPage } from "./views/session/SessionOverviewPage";
import { LiveExecutionPage } from "./views/live/LiveExecutionPage";
import { NotImplementedPage } from "./views/NotImplementedPage";
import { ScopeAuthorizationPage } from "./views/scope/ScopeAuthorizationPage";
import { EvidenceChainPage } from "./views/evidence/EvidenceChainPage";
import { MindMapPage } from "./views/map/MindMapPage";
import { ApertureContextPage } from "./views/aperture/ApertureContextPage";
import { DecisionQueuePage } from "./views/decision/DecisionQueuePage";
import { CostPanelPage } from "./views/cost/CostPanelPage";
import { ConflictMatrixPage } from "./views/conflict/ConflictMatrixPage";
import "./styles/app.css";

// Aletheia WebUI 入口。
//
// 页面清单对应 docs/06 §6.1。I0 只交付标注「P0」的两个页面
// （会话总览、实时执行流）的最小可用版本 —— 用于观察 P0 阶段的
// 24h 稳定性测试（docs/06 §10.1：没有 UI，观察成本极高）。
//
// 其余页面的路由已经登记，点击时显示"该迭代交付"：
// 这是有意为之 —— 让未交付的能力可见且可导航，
// 而不是从菜单里消失（消失会让使用者以为项目不包含这些能力，
// 而它们恰恰是本项目的差异化所在，docs/09 R9）。
const router = createBrowserRouter([
  {
    path: "/",
    element: <AppLayout />,
    children: [
      { index: true, element: <SessionOverviewPage /> },

      // 06 §6.1 页面 2 —— I0 交付
      { path: "live", element: <LiveExecutionPage /> },

      // 06 §6.1 页面 3 · 心智地图浏览器 —— I4 交付。
      // M2 是系统唯一真源；此页让"系统记住了什么"可见（含时间回放）。
      { path: "map", element: <MindMapPage /> },

      // 06 §6.1 页面 4 ★ 证据链视图 —— I2 交付（最小可用版）。
      // 本项目三个核心视图之一（docs/09 R9：不可省略）。
      { path: "evidence", element: <EvidenceChainPage /> },
      { path: "evidence/:findingId", element: <EvidenceChainPage /> },

      // 06 §6.1 页面 5 ★ 光圈上下文视图 —— I5 交付。
      // 本项目三个核心视图之一（docs/09 R9：不可省略）。
      // 它让「取舍」可见，同时是 M3 召回率问题的诊断工具。
      { path: "aperture", element: <ApertureContextPage /> },

      // 06 §6.1 页面 6 ★ 冲突矩阵视图 —— I8 交付。
      // 本项目三个核心视图的最后一个（docs/09 R9：不可省略）。
      // 「打不通但有缺陷」是最高价值象限，纯 CLI 输出会把它淹没。
      { path: "conflicts", element: <ConflictMatrixPage /> },

      // 06 §6.1 页面 7 · 人机协同决策队列 —— I6 交付。
      // 人类介入点是设计而非缺陷（全自主 21% vs 有人类提示 64%）。
      { path: "decisions", element: <DecisionQueuePage /> },

      // 06 §6.1 页面 8 · 报告与导出 —— I11
      {
        path: "report",
        element: <NotImplementedPage pageName="报告与导出" iteration="I11" module="M9" />,
      },

      // 06 §6.1 页面 9 · 范围与授权管理 —— I3
      // 注意：授权凭证录入走 CLI 而非 WebUI（docs/06 §3.3「不做首次配置向导」/
      // docs/04 I3「授权凭证录入走 CLI 而非 WebUI」）。此页面只展示
      // scope 与越界拦截审计视图。
      { path: "scope", element: <ScopeAuthorizationPage /> },

      // 06 §6.1 页面 10 · 成本与预算面板 —— I6 交付。
      // 预算与光圈是同一约束的两端（M3 §4.1 恒定曝光）。
      { path: "cost", element: <CostPanelPage /> },

      { path: "*", element: <NotImplementedPage pageName="未知页面" iteration="I0" /> },
    ],
  },
]);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
