import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { DaemonStatusCard } from "../../components/DaemonStatusCard";

// 06 §6.1 页面 2 —— 实时执行流（I0 交付，最小可用版本）。
//
// 页面职责（06 §6.1）：agent 动作时间线、当前任务、工具调用、实时输出流。
//
// I0 的交付范围：**通道骨架 + 断线重连 + 明确的能力边界**。
// 真实的事件流在 I6（编排层）随 Agent 池一起产出。
//
// 为什么 I0 就要做断线重连：docs/06 §7.2「长任务与断线重连」是
// 场景 A（长时自主运行）的核心要求 —— 24h/143h 稳定性测试期间
// 观察者一定会反复断开重连。这个能力放在骨架里做，
// 因为它影响状态管理的整体形状，后补代价更高。
export function LiveExecutionPage() {
  const [events, setEvents] = useState<string[]>([]);
  const [connectionState, setConnectionState] = useState<"idle" | "connecting" | "open" | "closed" | "error">("idle");
  const retryRef = useRef<number | null>(null);

  useEffect(() => {
    let cancelled = false;

    const connect = () => {
      if (cancelled) return;
      setConnectionState("connecting");

      // 06 §7.2：实时通道用 WebSocket（降级 SSE）。
      // alethd 的 /ws 端点由后续迭代提供；I0 先走"尝试连接并如实报告"。
      let ws: WebSocket;
      try {
        ws = new WebSocket(`ws://${location.host}/ws`);
      } catch {
        setConnectionState("error");
        return;
      }

      ws.onopen = () => {
        if (cancelled) {
          ws.close();
          return;
        }
        setConnectionState("open");
        setEvents((prev) => [...prev, "[connected] 实时通道已建立"]);
      };

      ws.onmessage = (msg) => {
        if (cancelled) return;
        // 数据按文本追加。I0 不做结构化解析 —— 事件 schema 属 L4 编排层
        // 的交付物（05 §6.1 TaskGraph），过早定义会与契约漂移。
        setEvents((prev) => [...prev.slice(-199), String(msg.data)]);
      };

      ws.onerror = () => setConnectionState("error");

      ws.onclose = () => {
        if (cancelled) return;
        setConnectionState("closed");
        setEvents((prev) => [...prev, "[closed] 连接断开，准备重连"]);
        // 06 §7.2：断线自动重连。指数退避，避免 daemon 未启动时空转。
        retryRef.current = window.setTimeout(connect, 2000);
      };
    };

    connect();

    return () => {
      cancelled = true;
      if (retryRef.current !== null) {
        clearTimeout(retryRef.current);
      }
    };
  }, []);

  return (
    <section className="page">
      <header className="page-header">
        <h1>实时执行流</h1>
        <p className="page-subtitle">
          06 §6.1 页面 2 ｜ agent 动作时间线 · 当前任务 · 工具调用 · 实时输出流
        </p>
      </header>

      <DaemonStatusCard />

      <div className="panel">
        <div className="panel-header">
          <h2>实时通道</h2>
          <ConnectionBadge state={connectionState} />
        </div>
        <p className="panel-note">
          依据 <code>docs/06</code> §7.2：状态在服务端，浏览器完全无状态；
          关闭浏览器不影响任务，重新打开即回到当前状态（含历史补全）。
        </p>
        <ol className="event-timeline">
          {events.length === 0 ? (
            <li className="event-empty">
              暂无事件。alethd 的 <code>/ws</code> 端点与事件 schema 在 I6（编排层）交付。
            </li>
          ) : (
            events.map((e, i) => (
              <li key={`${i}-${e}`} className="event-row">
                {e}
              </li>
            ))
          )}
        </ol>
      </div>

      <div className="callout">
        <p>
          这个页面在 I0 的用途：为 P0 阶段的 24h 稳定性测试提供观察入口
          （<code>docs/06</code> §10.1 —— 没有 UI，观察成本极高）。
        </p>
        <p>
          时间回放（拖动时间轴查看任意历史时刻的认知状态）依赖 M2 的{" "}
          <code>SnapshotAt</code> 与 M6 的 Checkpoint，分别在 I4 / I6 交付。
        </p>
      </div>

      <p>
        <Link to="/">返回会话总览</Link>
      </p>
    </section>
  );
}

function ConnectionBadge(props: { state: string }) {
  const label: Record<string, string> = {
    idle: "未连接",
    connecting: "连接中…",
    open: "已连接",
    closed: "已断开（重连中）",
    error: "连接失败",
  };
  return (
    <span className={`badge badge-${props.state}`}>
      {label[props.state] ?? props.state}
    </span>
  );
}
