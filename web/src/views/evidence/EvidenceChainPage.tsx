import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { EmptyState } from "../../components/EmptyState";
import { classifyError, ledgerClient } from "../../lib/api";
import type { TracedEvidenceChain } from "@gen/aleth/v1/aletheia";

// 06 §6.1 页面 4 —— 证据链视图（I2 交付，最小可用版本）★核心视图。
//
// 页面职责（06 §6.1）：这是用户验证「系统是否在幻觉」的唯一界面。
// 每个 Finding 的完整证据链在这里逐层展开：
//   finding → assertions（自然语言断言）→ evidence（执行证据 + argv）
//           → side effects（目标侧副作用观测 + 命中模式）
// R9 约束：树形结构与交叉引用不可省略 —— 断言上列出它引用的证据
// （反向：证据上列出引用它的断言），归因不一致必须显式呈现。
//
// I2 范围说明：focalplane server 未运行时显示不可用状态而非假数据
// （docs/09 §6 #4：不渲染看起来正常的空结果）。

type LoadState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "loaded"; chain: TracedEvidenceChain }
  | { kind: "unavailable"; detail: string }
  | { kind: "notfound"; detail: string };

export function EvidenceChainPage() {
  const params = useParams();
  const navigate = useNavigate();
  const [findingId, setFindingId] = useState<string>(params.findingId ?? "");
  const [state, setState] = useState<LoadState>({ kind: "idle" });

  const trace = useCallback((id: string) => {
    if (!id.trim()) return;
    setState({ kind: "loading" });
    ledgerClient
      .traceFinding({ findingId: id.trim() })
      .then((chain) => setState({ kind: "loaded", chain }))
      .catch((err: unknown) => {
        const cls = classifyError("LedgerService", err) as { kind?: string; detail?: string };
        if (cls?.kind === "unimplemented") {
          setState({ kind: "unavailable", detail: "focalplane（LedgerService）尚未运行" });
        } else {
          setState({ kind: "notfound", detail: String(cls?.detail ?? err) });
        }
      });
  }, []);

  useEffect(() => {
    if (params.findingId) trace(params.findingId);
  }, [params.findingId, trace]);

  return (
    <section>
      <h1>证据链视图</h1>
      <p className="page-hint">
        结论必须由证据显现，不可由模型声称 —— 在这里逐层核对任意 Finding。
      </p>

      <form
        className="evidence-lookup"
        onSubmit={(ev) => {
          ev.preventDefault();
          navigate(`/evidence/${encodeURIComponent(findingId.trim())}`);
        }}
      >
        <input
          value={findingId}
          onChange={(e) => setFindingId(e.target.value)}
          placeholder="find_…"
          aria-label="finding id"
        />
        <button type="submit">追溯证据链</button>
      </form>

      {state.kind === "loading" && <p>正在追溯…</p>}

      {state.kind === "unavailable" && (
        <EmptyState
          title="账本服务不可用"
          description={state.detail + "。启动方式：uv run python -m aletheia.focalplane.server --pubkey-hex <hex>（见 docs/iterations/I2-交接.md）。"}
        />
      )}

      {state.kind === "notfound" && <EmptyState title="未找到该 Finding" description={state.detail} />}

      {state.kind === "loaded" && <ChainView chain={state.chain} />}
    </section>
  );
}

function ChainView({ chain }: { chain: TracedEvidenceChain }) {
  return (
    <div className="evidence-chain">
      <div className={`attribution ${chain.attributionConsistent ? "ok" : "broken"}`}>
        归因校验：{chain.attributionConsistent ? "一致 ✓" : "不一致 ✗（P0）"}
        {(chain.attributionErrors ?? []).map((e, i) => (
          <div key={i} className="attribution-error">
            {e.message}
          </div>
        ))}
      </div>

      <h2>断言（{(chain.assertions ?? []).length}）</h2>
      {(chain.assertions ?? []).length === 0 && <p className="muted">该 finding 尚无断言。</p>}
      {(chain.assertions ?? []).map((a) => (
        <div className="assertion-card" key={a.assertionId}>
          <div className="assertion-id">{a.assertionId}</div>
          <div className="assertion-statement">{a.statement}</div>
          <dl>
            <dt>类型</dt>
            <dd>{a.type}</dd>
            <dt>目标实体</dt>
            <dd>{a.targetEntityId}</dd>
          </dl>
          {/* 交叉引用：断言 → 证据 */}
          <div className="cross-refs">
            支撑证据：
            {(a.supportingEvidenceIds ?? []).length === 0 && <span className="muted">（无 —— G-2 必拒）</span>}
            {(a.supportingEvidenceIds ?? []).map((rid) => (
              <code key={rid}>{rid}</code>
            ))}
          </div>
        </div>
      ))}

      <h2>证据（{(chain.evidence ?? []).length}）</h2>
      {(chain.evidence ?? []).map((e) => (
        <div className="evidence-card" key={e.evidenceId}>
          <div className="evidence-id">{e.evidenceId}</div>
          <dl>
            <dt>exec_id</dt>
            <dd>
              <code>{e.execId}</code>
            </dd>
            <dt>工具</dt>
            <dd>
              {e.tool?.toolName} {e.tool?.toolVersion}
            </dd>
            <dt>argv</dt>
            <dd>
              <code>{(e.tool?.argv ?? []).join(" ")}</code>
            </dd>
            <dt>argv_hash</dt>
            <dd>
              <code>{e.tool?.argvHash}</code>
            </dd>
            <dt>raw 哈希</dt>
            <dd>
              <code>{e.raw?.contentHash}</code>（{e.raw?.lineCount ?? 0} 行 /{" "}
              {e.raw?.sizeBytes ?? 0} 字节）
            </dd>
            <dt>账本哈希</dt>
            <dd>
              <code>{e.selfHash}</code>
            </dd>
          </dl>
          {/* 交叉引用：证据 → 断言 */}
          <div className="cross-refs">
            被断言引用：
            {(chain.assertions ?? [])
              .filter((a) => (a.supportingEvidenceIds ?? []).includes(e.evidenceId ?? ""))
              .map((a) => (
                <code key={a.assertionId}>{a.assertionId}</code>
              ))}
          </div>
          {(e.sideEffects ?? []).length > 0 && (
            <div className="side-effects">
              <h3>副作用观测（{(e.sideEffects ?? []).length}）</h3>
              {(e.sideEffects ?? []).map((s, i) => (
                <div key={i} className="side-effect">
                  <span className="side-effect-kind">{s.kind}</span>{" "}
                  <code className="side-effect-pattern">{s.matchedPattern}</code>
                  <pre className="side-effect-observation">{s.observation}</pre>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
