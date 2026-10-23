import { useCallback, useEffect, useState } from "react";
import { EmptyState } from "../../components/EmptyState";
import { classifyError, governorClient } from "../../lib/api";
import type { BudgetState, CircuitState } from "@gen/aleth/v1/aletheia";
import "../../styles/cost.css";

// 06 §6.1 页面 10 —— 成本与预算面板（I6 交付）。
//
// 页面内容（06 §6.1 表格原文）：
//   实时消耗、按任务/agent 分布、**光圈档位与预算关系**、熔断阈值线
//
// # 为什么"光圈档位与预算关系"是这个页面的重点
//
// M3 §4.1 的「恒定曝光」是一条硬约束：光圈开大必须别处关小。
// 预算与光圈不是两个独立指标 —— 它们是同一约束的两端：
//
//   · 预算消耗 ≥ 80% → 光圈自动收窄（M6 §6 的 aperture_narrowed）
//   · 预算耗尽（100%）→ **硬熔断**，无逃逸路径
//
// 因此本页必须把两条阈值线（80% 收窄、100% 熔断）画出来，
// 让使用者看到"还剩多少余量才碰到硬约束"。

type LoadState =
  | { kind: "loading" }
  | { kind: "loaded"; budget: BudgetState; circuit: CircuitState }
  | { kind: "unavailable"; detail: string };

/** 熔断阈值（M6 §6 的双阈值，与 core/governor 的实现一致）。 */
const NARROW_THRESHOLD = 0.8;
const OPEN_THRESHOLD = 1.0;

export function CostPanelPage() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [sessionId, setSessionId] = useState("default");

  const load = useCallback(() => {
    setState({ kind: "loading" });
    Promise.all([
      governorClient.state({ sessionId }),
      governorClient.checkCircuit({ sessionId }),
    ])
      .then(([budget, circuit]) =>
        setState({ kind: "loaded", budget, circuit }),
      )
      .catch((err: unknown) => {
        const cls = classifyError("GovernorService", err);
        setState({
          kind: "unavailable",
          detail:
            cls instanceof Error && cls.name === "UnimplementedError"
              ? "GovernorService 尚未交付。"
              : err instanceof Error
                ? err.message
                : String(err),
        });
      });
  }, [sessionId]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <section>
      <h1>成本与预算面板</h1>
      <p className="page-hint">
        预算与光圈是同一约束的两端（M3 §4.1 恒定曝光）：光圈开大必须别处关小。
        这里显示实时消耗与两条硬阈值线。
      </p>

      <div className="cost-toolbar">
        <label className="cost-field">
          <span>会话</span>
          <input value={sessionId} onChange={(e) => setSessionId(e.target.value)} />
        </label>
        <button type="button" className="btn" onClick={load}>
          刷新
        </button>
      </div>

      {state.kind === "loading" && <p>加载中…</p>}
      {state.kind === "unavailable" && (
        <EmptyState title="预算状态不可用" description={state.detail} />
      )}
      {state.kind === "loaded" && <BudgetView budget={state.budget} circuit={state.circuit} />}
    </section>
  );
}

function BudgetView({ budget, circuit }: { budget: BudgetState; circuit: CircuitState }) {
  const total = budget.totalTokens ?? 0;
  const consumed = budget.consumedTokens ?? 0;
  const reserved = budget.reservedTokens ?? 0;
  const util = budget.utilization ?? 0;
  const pct = util * 100;

  // 未配置预算：这不是"消耗为 0"，而是"约束不存在"。
  // 后者更值得显式告知 —— 一个没有预算的会话永远不会熔断（M6 §6）。
  if (total === 0) {
    return (
      <EmptyState
        title="本会话未配置 token 预算"
        description={
          "budget.session_tokens = 0（未配置）。\n\n" +
          "这不是「消耗为 0」—— 而是「成本约束不存在」。一个没有预算的会话" +
          "是一个永不熔断的熔断器，因此 GovernorService 的 Reserve 会" +
          "fail-closed 拒绝执行（M6 §6）。\n\n" +
          "要启用预算，在配置文件中设置 budget.session_tokens 后重启 alethd。"
        }
      />
    );
  }

  const narrowed = budget.apertureNarrowed ?? false;
  const open = budget.circuitOpen ?? false;

  return (
    <>
      {open && (
        <div className="cost-banner cost-banner-open">
          <strong>已硬熔断</strong>
          <span>{circuit.triggerReason || "预算耗尽，全部调用方必须停止（无逃逸路径）"}</span>
        </div>
      )}
      {!open && narrowed && (
        <div className="cost-banner cost-banner-narrow">
          <strong>光圈已收窄</strong>
          <span>{circuit.triggerReason || "利用率 ≥ 80%，只应推进高价值任务"}</span>
        </div>
      )}

      {/* 主指标 */}
      <div className="cost-summary">
        <Metric label="预算总额" value={total.toLocaleString()} unit="token" />
        <Metric label="已消耗" value={consumed.toLocaleString()} unit="token" />
        <Metric label="预扣中" value={reserved.toLocaleString()} unit="token" />
        <Metric
          label="利用率"
          value={pct.toFixed(1)}
          unit="%"
          tone={open ? "danger" : narrowed ? "warn" : "ok"}
        />
      </div>

      {/* 阈值线图：让"还剩多少余量"可见 */}
      <div className="cost-gauge">
        <div className="cost-gauge-track">
          <div
            className={
              open ? "cost-gauge-fill cost-gauge-fill-open"
                : narrowed ? "cost-gauge-fill cost-gauge-fill-narrow"
                  : "cost-gauge-fill"
            }
            style={{ width: `${Math.min(pct, 100)}%` }}
          />
          {/* 80% 收窄线 */}
          <div className="cost-threshold cost-threshold-narrow" style={{ left: `${NARROW_THRESHOLD * 100}%` }}>
            <span>80% 收窄</span>
          </div>
          {/* 100% 熔断线 */}
          <div className="cost-threshold cost-threshold-open" style={{ left: `${OPEN_THRESHOLD * 100}%` }}>
            <span>100% 熔断</span>
          </div>
        </div>
        <div className="cost-gauge-axis">
          <span>0</span>
          <span>{(total * NARROW_THRESHOLD).toLocaleString()}</span>
          <span>{total.toLocaleString()}</span>
        </div>
      </div>

      {/* 剩余余量：直接给数字，不用换算 */}
      <div className="cost-headroom">
        <h2>剩余余量</h2>
        <ul>
          <li>
            到 <strong>80% 收窄线</strong>：
            <strong className="cost-mono">
              {Math.max(0, Math.floor(total * NARROW_THRESHOLD) - consumed - reserved).toLocaleString()}
            </strong>{" "}
            token
          </li>
          <li>
            到 <strong>100% 熔断线</strong>：
            <strong className="cost-mono">
              {Math.max(0, total - consumed - reserved).toLocaleString()}
            </strong>{" "}
            token
          </li>
        </ul>
      </div>

      {/* 与光圈档位的联动说明 */}
      <div className="cost-block">
        <h2>光圈档位与预算的关系</h2>
        <p className="cost-note">
          M3 的三档光圈决定单次装配的信息量上限，预算决定总量上限。
          二者由 M6 的 CostGovernor 联动：
        </p>
        <table className="cost-table">
          <thead>
            <tr>
              <th>利用率区间</th>
              <th>状态</th>
              <th>系统行为</th>
            </tr>
          </thead>
          <tbody>
            <tr className={util < NARROW_THRESHOLD ? "cost-row-active" : ""}>
              <td>&lt; 80%</td>
              <td>正常</td>
              <td>光圈可按任务需要自由选择档位</td>
            </tr>
            <tr className={narrowed && !open ? "cost-row-active" : ""}>
              <td>≥ 80%</td>
              <td>收窄</td>
              <td>
                <code>aperture_narrowed = true</code> —— 编排层应只保留高价值任务
              </td>
            </tr>
            <tr className={open ? "cost-row-active cost-row-danger" : ""}>
              <td>&ge; 100%</td>
              <td>硬熔断</td>
              <td>
                <code>circuit_open = true</code> —— 全部调用方必须停止，
                <strong>无逃逸路径</strong>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="cost-block">
        <h2>熔断状态</h2>
        <dl className="cost-dl">
          <dt>circuit_open</dt>
          <dd>{open ? "true" : "false"}</dd>
          <dt>aperture_narrowed</dt>
          <dd>{narrowed ? "true" : "false"}</dd>
          <dt>触发原因</dt>
          <dd>{circuit.triggerReason || "（无）"}</dd>
        </dl>
      </div>

      <div className="cost-footnote">
        按任务/agent 的消耗分布需要各任务在执行时上报 <code>Consume</code> ——
        该数据在接线 Agent 池后才有（I6 收口工作）。此处不渲染伪造的分布图。
      </div>
    </>
  );
}

function Metric({
  label,
  value,
  unit,
  tone,
}: {
  label: string;
  value: string;
  unit: string;
  tone?: "ok" | "warn" | "danger";
}) {
  return (
    <div className={`cost-metric${tone ? ` cost-metric-${tone}` : ""}`}>
      <div className="cost-metric-label">{label}</div>
      <div className="cost-metric-value">
        {value}
        <span className="cost-metric-unit">{unit}</span>
      </div>
    </div>
  );
}
