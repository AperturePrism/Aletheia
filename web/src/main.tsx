import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { AppLayout } from "./components/AppLayout";
import { SessionOverviewPage } from "./views/session/SessionOverviewPage";
import { LiveExecutionPage } from "./views/live/LiveExecutionPage";
import { NotImplementedPage } from "./views/NotImplementedPage";
import { ScopeAuthorizationPage } from "./views/scope/ScopeAuthorizationPage";
import { EvidenceChainPage } from "./views/evidence/EvidenceChainPage";
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

      // 06 §6.1 页面 3 · 心智地图浏览器 —— I4
      {
        path: "map",
        element: <NotImplementedPage pageName="心智地图浏览器" iteration="I4" module="M2" />,
      },

      // 06 §6.1 页面 4 ★ 证据链视图 —— I2 交付（最小可用版）。
      // 本项目三个核心视图之一（docs/09 R9：不可省略）。
      { path: "evidence", element: <EvidenceChainPage /> },
      { path: "evidence/:findingId", element: <EvidenceChainPage /> },

      // 06 §6.1 页面 5 ★ 光圈上下文视图 —— I5
      {
        path: "aperture",
        element: <NotImplementedPage pageName="光圈上下文视图 ★" iteration="I5" module="M3" coreView />,
      },

      // 06 §6.1 页面 6 ★ 冲突矩阵视图 —— I8
      {
        path: "conflicts",
        element: <NotImplementedPage pageName="冲突矩阵视图 ★" iteration="I8" module="M7" coreView />,
      },

      // 06 §6.1 页面 7 · 人机协同决策队列 —— I6
      {
        path: "decisions",
        element: <NotImplementedPage pageName="人机协同决策队列" iteration="I6" module="M5" />,
      },

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

      // 06 §6.1 页面 10 · 成本与预算面板 —— I6
      {
        path: "cost",
        element: <NotImplementedPage pageName="成本与预算面板" iteration="I6" module="M6" />,
      },

      { path: "*", element: <NotImplementedPage pageName="未知页面" iteration="I0" /> },
    ],
  },
]);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
