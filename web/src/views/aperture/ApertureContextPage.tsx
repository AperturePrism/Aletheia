import { useCallback, useEffect, useMemo, useState } from "react";
import { EmptyState } from "../../components/EmptyState";
import { apertureClient, classifyError } from "../../lib/api";
import type { ContextBundle, Entity } from "@gen/aleth/v1/aletheia";
import "../../styles/aperture.css";

// 06 §6.1 页面 5 —— 光圈上下文视图（I5 交付）★核心视图。
//
// 页面职责（06 §6.2「把'取舍'变成看得见的东西」）：
//
//	本次装配  f/4  ·  预算 8,000 token  ·  实际 7,412 (92.6%)
//	 ├─ 入选实体 (54)
//	 │   ├─ score 1.00  svc_018f..  443/tcp nginx 1.24.0
//	 ├─ ⚠ 因预算省略
//	 │   ├─ TIMELINE 全量（保留最近 3 条）
//	 └─ ℹ 未入选的高分实体 (12)
//
// **这一视图让用户能判断"系统是不是漏看了什么"。**
// 它同时是 M3 召回率问题的诊断工具 —— 因此"省略了什么"必须与
// "选了什么"同等显眼，不能折叠或弱化（否则就失去诊断价值）。
//
// R9 约束：本视图不可省略。省略它等于放弃本项目的差异化能力。

type LoadState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "loaded"; bundle: ContextBundle }
  | { kind: "overbudget"; detail: string }
  | { kind: "error"; detail: string };

/** 三档光圈的显示信息（与 core/aperture 的 profiles 一致）。 */
const STOP_META: Record<number, { label: string; semantics: string; hops: number; entities: number; depth: number }> = {
  1: { label: "f/1.4", semantics: "宽而浅 —— 攻击面总览", hops: 1, entities: 200, depth: 1 },
  2: { label: "f/4", semantics: "平衡 —— 常规漏洞分析", hops: 2, entities: 60, depth: 2 },
  3: { label: "f/16", semantics: "窄而深 —— 单点利用", hops: 3, entities: 10, depth: 5 },
};

const KIND_LABEL: Record<number, string> = {
  1: "资产", 2: "服务", 3: "身份", 4: "端点", 5: "缺陷", 6: "路径", 7: "事件",
};

export function ApertureContextPage() {
  const [state, setState] = useState<LoadState>({ kind: "idle" });
  const [focusHint, setFocusHint] = useState("");
  const [budget, setBudget] = useState(8000);
  const [stop, setStop] = useState(2); // 默认 f/4
  const [allowDowngrade, setAllowDowngrade] = useState(true);

  const assemble = useCallback(() => {
    setState({ kind: "loading" });
    apertureClient
      .assemble({
        taskId: "webui-manual",
        focusHint,
        budgetTokens: budget,
        preferredStop: stop,
        allowDowngrade,
      })
      .then((bundle: ContextBundle) => setState({ kind: "loaded", bundle }))
      .catch((err: unknown) => {
        const cls = classifyError("ApertureService", err);
        const msg = err instanceof Error ? err.message : String(err);
        // 超预算是**预期内的显式失败**（M3 §2.2 N4：不允许截断），
        // 与"服务不可用"必须区分 —— 前者提示用户调档/加预算即可。
        if (msg.includes("APERTURE_OVER_BUDGET") || msg.includes("over budget")) {
          setState({ kind: "overbudget", detail: msg });
        } else if (cls instanceof Error && cls.name === "UnimplementedError") {
          setState({ kind: "error", detail: "ApertureService 尚未交付（见 docs/04 §4）。" });
        } else {
          setState({ kind: "error", detail: msg });
        }
      });
  }, [focusHint, budget, stop, allowDowngrade]);

  useEffect(() => {
    assemble();
    // 首次进入自动装配一次；后续由"重新装配"按钮驱动。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <section>
      <h1>光圈上下文视图</h1>
      <p className="page-hint">
        记忆在图里，上下文只是焦点的投影。本页让「本次装配选了什么、省略了什么」可见
        —— 它同时是召回率问题的诊断工具。
      </p>

      <div className="ap-controls">
        <label className="ap-field ap-field-wide">
          <span>焦点提示（任务目标 / 假设）</span>
          <input
            value={focusHint}
            placeholder="如 app.example.test 或 http://app.example.test/api/v2 —— 留空 = 全景"
            onChange={(e) => setFocusHint(e.target.value)}
          />
        </label>

        <label className="ap-field">
          <span>光圈档位</span>
          <select value={stop} onChange={(e) => setStop(Number(e.target.value))}>
            {Object.entries(STOP_META).map(([k, m]) => (
              <option key={k} value={k}>
                {m.label} · {m.semantics}
              </option>
            ))}
          </select>
        </label>

        <label className="ap-field">
          <span>预算（token）</span>
          <input
            type="number"
            min={1}
            value={budget}
            onChange={(e) => setBudget(Math.max(1, Number(e.target.value) || 1))}
          />
        </label>

        <label className="ap-field ap-check">
          <input
            type="checkbox"
            checked={allowDowngrade}
            onChange={(e) => setAllowDowngrade(e.target.checked)}
          />
          <span>允许自动降档</span>
        </label>

        <button type="button" className="btn btn-primary" onClick={assemble}>
          重新装配
        </button>
      </div>

      <StopLadder current={stop} />

      {state.kind === "loading" && <p>装配中…</p>}
      {state.kind === "idle" && <EmptyState title="尚未装配" description="点击「重新装配」。" />}
      {state.kind === "overbudget" && (
        <EmptyState
          title="超出预算 —— 已拒绝装配（未截断）"
          description={
            `${state.detail}\n\n` +
            "这是预期行为：截断会产生「信息看起来完整但实际缺失」的静默错误。" +
            "请收窄光圈档位、缩小焦点，或提高预算。"
          }
        />
      )}
      {state.kind === "error" && (
        <EmptyState
          title="无法连接 ApertureService"
          description={
            `${state.detail}\n\n` +
            "常见原因：alethd 未运行，或前端构建产物与后端不是同一次构建（重新 make build）。"
          }
        />
      )}
      {state.kind === "loaded" && <BundleView bundle={state.bundle} />}
    </section>
  );
}

/** 档位阶梯：直观展示三档的信息密度差异（含当前档位高亮）。 */
function StopLadder({ current }: { current: number }) {
  const order = [1, 2, 3];
  return (
    <div className="ap-ladder">
      {order.map((k) => {
        const m = STOP_META[k];
        return (
          <div key={k} className={k === current ? "ap-rung ap-rung-active" : "ap-rung"}>
            <div className="ap-rung-label">{m.label}</div>
            <div className="ap-rung-detail">
              {m.hops} 跳 · {m.entities} 实体 · 深度 {m.depth}
            </div>
            <div className="ap-rung-sem">{m.semantics}</div>
          </div>
        );
      })}
    </div>
  );
}

function BundleView({ bundle }: { bundle: ContextBundle }) {
  const entities: Entity[] = useMemo(() => bundle.entities ?? [], [bundle]);
  const est = bundle.estimatedTokens ?? 0;
  const bud = bundle.budgetTokens ?? 0;
  const pct = bud > 0 ? (est / bud) * 100 : 0;

  const byKind = useMemo(() => {
    const m = new Map<number, number>();
    for (const e of entities) {
      const k = e.kind ?? 0;
      m.set(k, (m.get(k) ?? 0) + 1);
    }
    return [...m.entries()].sort((a, b) => a[0] - b[0]);
  }, [entities]);

  return (
    <>
      {/* 摘要区：档位 / 预算 / 实际 —— 06 §6.2 的首行 */}
      <div className="ap-summary">
        <div className="ap-summary-main">
          <span className="ap-stop-badge">
            {STOP_META[bundle.aperture?.stop ?? 2]?.label ?? "?"}
          </span>
          <span>
            预算 <strong>{bud.toLocaleString()}</strong> token
          </span>
          <span>
            实际 <strong>{est.toLocaleString()}</strong> token
          </span>
          <span className={pct > 95 ? "ap-usage ap-usage-high" : "ap-usage"}>
            {pct.toFixed(1)}%
          </span>
          <span className="ap-entity-count">入选实体 {entities.length}</span>
        </div>
        <div className="ap-usage-bar" aria-hidden="true">
          <div className="ap-usage-fill" style={{ width: `${Math.min(pct, 100)}%` }} />
        </div>
        {bundle.bundleId ? (
          <div className="ap-bundle-id">
            装配标识 <code>{bundle.bundleId}</code>
          </div>
        ) : null}
      </div>

      {/* 焦点声明（可审计） */}
      <div className="ap-block">
        <h2>焦点</h2>
        <p className="ap-focal">{bundle.focalPoint || "（未声明）"}</p>
      </div>

      {/* ★ 省略声明必须与"选了什么"同等显眼（诊断价值所在） */}
      <div className="ap-block ap-block-omitted">
        <h2>
          ⚠ 因预算省略
          <span className="ap-count">{bundle.truncatedDimensions?.length ?? 0}</span>
        </h2>
        {(bundle.truncatedDimensions?.length ?? 0) === 0 ? (
          <p className="ap-none">本次装配无省略 —— 全部候选都已注入。</p>
        ) : (
          <ul className="ap-omitted-list">
            {(bundle.truncatedDimensions ?? []).map((d, i) => (
              <li key={i}>{d}</li>
            ))}
          </ul>
        )}
      </div>

      {/* 入选实体 */}
      <div className="ap-block">
        <h2>
          入选实体
          <span className="ap-count">{entities.length}</span>
        </h2>
        <div className="ap-kind-bar">
          {byKind.map(([k, n]) => (
            <span key={k} className={`ap-kind-chip k-${k}`}>
              {KIND_LABEL[k] ?? `#${k}`} {n}
            </span>
          ))}
        </div>
        {entities.length === 0 ? (
          <EmptyState title="没有实体入选" description="图中没有匹配焦点的实体，或预算过低。" />
        ) : (
          <table className="ap-table">
            <thead>
              <tr>
                <th>实体</th>
                <th>类型</th>
                <th>置信度</th>
                <th>属性</th>
              </tr>
            </thead>
            <tbody>
              {entities.map((e) => (
                <tr key={e.entityId ?? Math.random()}>
                  <td>
                    <code className="ap-eid">{e.entityId}</code>
                  </td>
                  <td>{KIND_LABEL[e.kind ?? 0] ?? `#${e.kind}`}</td>
                  <td>
                    {(e.confidence ?? 0).toFixed(2)}
                    {e.isHypothesis ? <span className="ap-hyp">假设</span> : null}
                  </td>
                  <td>
                    <AttrList attrs={e.attributes ?? {}} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* 关系 */}
      <div className="ap-block">
        <h2>
          关系
          <span className="ap-count">{bundle.relations?.length ?? 0}</span>
        </h2>
        {(bundle.relations?.length ?? 0) === 0 ? (
          <p className="ap-none">本次装配未包含关系（两端不全在结果集内的关系会被排除）。</p>
        ) : (
          <ul className="ap-rel-list">
            {(bundle.relations ?? []).map((r, i) => (
              <li key={i}>
                <code>{r.fromEntity}</code>
                <span className="ap-arrow">—{relationLabel(r.type)}→</span>
                <code>{r.toEntity}</code>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* 可审计性（M3 §3.1 R5）：为什么选这些实体 */}
      <details className="ap-block ap-reasons">
        <summary>
          选取依据（selection_reasons）
          <span className="ap-count">{bundle.selectionReasons?.length ?? 0}</span>
        </summary>
        {(bundle.selectionReasons?.length ?? 0) === 0 ? (
          <p className="ap-none">无记录。</p>
        ) : (
          <ul>
            {(bundle.selectionReasons ?? []).map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        )}
      </details>
    </>
  );
}

function AttrList({ attrs }: { attrs: Record<string, string> }) {
  const keys = Object.keys(attrs).sort();
  if (keys.length === 0) return <span className="ap-none">—</span>;
  return (
    <span className="ap-attrs">
      {keys.map((k) => (
        <span key={k} className="ap-attr">
          <span className="ap-attr-key">{k}</span>
          <span className="ap-attr-val">{attrs[k]}</span>
        </span>
      ))}
    </span>
  );
}

/** 关系类型可读名（05 §3.1 RelationType）。 */
function relationLabel(t: number | undefined): string {
  const m: Record<number, string> = {
    1: "解析到", 2: "运行于", 3: "认证到", 4: "拥有权限", 5: "暴露",
    6: "属于", 7: "调用", 8: "位于", 9: "可被利用", 10: "使能",
    11: "依赖", 12: "先于", 13: "印证", 14: "矛盾",
  };
  return m[t ?? 0] ?? `关系#${t}`;
}
