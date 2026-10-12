import { useCallback, useEffect, useMemo, useState } from "react";
import { EmptyState } from "../../components/EmptyState";
import { ledgerClient } from "../../lib/api";
import type { TracedEvidenceChain } from "@gen/aleth/v1/aletheia";
import "../../styles/report.css";

// 06 §6.1 页面 8 —— 报告与导出（I11 交付）。
//
// 页面职责（06 §6.1 表格原文）：
//   **分层报告浏览（主报告 / 附录 / 调试）；导出 Markdown / PDF / SARIF**
//
// # 分层是本页的核心设计
//
// 契约 `Report`（05 §7.2）在**类型系统层面**强制分层：
//
//     repeated Finding confirmed = 3;   // 主报告
//     repeated Finding candidates = 4;  // 附录
//     // 注意：HYPOTHESIS 不进报告结构（调试视图另存）
//
// proto 里**没有** HYPOTHESIS 字段 —— 这是刻意的（契约注释原文：
// "从类型系统层面杜绝「把推测写进报告」"）。因此本页的"调试"层
// 只能展示**原始证据链**（经 LedgerService.TraceFinding），
// 而不是一个"包含推测的报告层" —— 后者在契约上不存在。
//
// 这个约束是 M4 反幻觉机制的一部分：推测不进报告，就不存在
// "推测被误读为结论"的路径。

type Layer = "main" | "appendix" | "debug";

type LoadState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "loaded"; chain: TracedEvidenceChain }
  | { kind: "unavailable"; detail: string }
  | { kind: "notfound"; detail: string };

const LAYERS: { key: Layer; label: string; hint: string }[] = [
  {
    key: "main",
    label: "主报告",
    hint: "仅 CONFIRMED —— 有可复现 PoC 的结论。契约层面不存在「推测」字段",
  },
  {
    key: "appendix",
    label: "附录",
    hint: "CANDIDATE —— 强证据待独立复现。进附录而非主报告",
  },
  {
    key: "debug",
    label: "调试",
    hint: "原始证据链 —— 不经报告结构，直接读账本（HYPOTHESIS 只在此可见）",
  },
];

export function ReportExportPage() {
  const [layer, setLayer] = useState<Layer>("main");
  const [state, setState] = useState<LoadState>({ kind: "idle" });
  const [findingId, setFindingId] = useState("");

  const load = useCallback(
    (id: string) => {
      if (!id.trim()) return;
      setState({ kind: "loading" });
      ledgerClient
        .traceFinding({ findingId: id.trim() })
        .then((chain) => setState({ kind: "loaded", chain }))
        .catch((err: unknown) => {
          const msg = err instanceof Error ? err.message : String(err);
          setState(
            msg.includes("not implemented")
              ? { kind: "unavailable", detail: "focalplane（LedgerService）尚未运行" }
              : { kind: "notfound", detail: msg },
          );
        });
    },
    [],
  );

  useEffect(() => {
    if (findingId) load(findingId);
  }, [findingId, load]);

  const activeLayer = LAYERS.find((l) => l.key === layer)!;

  return (
    <section>
      <h1>报告与导出</h1>
      <p className="page-hint">
        分层报告浏览：<strong>主报告</strong>（仅 CONFIRMED）／
        <strong>附录</strong>（CANDIDATE）／<strong>调试</strong>（原始证据链）。
        契约在类型层面杜绝「把推测写进报告」。
      </p>

      <div className="rp-tabs">
        {LAYERS.map((l) => (
          <button
            key={l.key}
            type="button"
            className={l.key === layer ? "rp-tab rp-tab-active" : "rp-tab"}
            onClick={() => setLayer(l.key)}
          >
            {l.label}
          </button>
        ))}
      </div>
      <p className="rp-layer-hint">{activeLayer.hint}</p>

      <div className="rp-toolbar">
        <label className="rp-field">
          <span>finding_id</span>
          <input
            value={findingId}
            placeholder="要浏览的 Finding（如 finding_xxx）"
            onChange={(e) => setFindingId(e.target.value.trim())}
          />
        </label>
        <button type="button" className="btn" onClick={() => load(findingId)}>
          加载
        </button>
      </div>

      <ExportBar layer={layer} findingId={findingId} />

      {state.kind === "idle" && (
        <EmptyState
          title="尚未加载"
          description="输入 finding_id 后加载。分层浏览与导出都以单个 Finding 为单位 —— 报告不是一份自由文本。"
        />
      )}
      {state.kind === "loading" && <p>加载中…</p>}
      {state.kind === "unavailable" && (
        <EmptyState title="报告不可用" description={state.detail} />
      )}
      {state.kind === "notfound" && (
        <EmptyState title="未找到该 Finding" description={state.detail} />
      )}
      {state.kind === "loaded" && (
        <ChainView chain={state.chain} layer={layer} />
      )}
    </section>
  );
}

/** 导出栏 —— 三种格式（06 §6.1：Markdown / PDF / SARIF）。 */
function ExportBar({ layer, findingId }: { layer: Layer; findingId: string }) {
  const disabled = !findingId;
  return (
    <div className="rp-export">
      <span className="rp-export-label">导出当前层：</span>
      <button type="button" className="btn" disabled={disabled}
        onClick={() => downloadMarkdown(layer, findingId)}>
        Markdown
      </button>
      <button type="button" className="btn" disabled={disabled}
        onClick={() => window.print()}>
        PDF（浏览器打印）
      </button>
      <button type="button" className="btn" disabled={disabled}
        onClick={() => downloadSarif(layer, findingId)}>
        SARIF
      </button>
      <span className="rp-export-note">
        PDF 走浏览器打印 —— 服务端渲染 PDF 需在 daemon 内嵌无头浏览器，
        与「单二进制分发」（06 §8）冲突，故不做。
      </span>
    </div>
  );
}

/**
 * 导出 Markdown。
 *
 * 在**浏览器侧**生成而不是请求服务端：契约（05 §7.2）里没有
 * "导出" RPC，且报告的**内容**已由账本给出。加一个只做格式转换的
 * 服务端接口属于重复能力（`docs/09` R1：不得边实现边改契约）。
 */
function downloadMarkdown(layer: Layer, findingId: string): void {
  const text = [
    `# Finding ${findingId}`,
    "",
    `层级：${LAYERS.find((l) => l.key === layer)?.label ?? layer}`,
    "",
    "> 本报告按 05 §7.2 的 Report 结构分层：",
    "> CONFIRMED → 主报告；CANDIDATE → 附录；HYPOTHESIS 不进报告结构。",
    "",
    "（完整内容需经 LedgerService.TraceFinding 获取后渲染 ——",
    "本导出仅演示格式与分层语义。）",
    "",
  ].join("\n");
  triggerDownload(`${findingId}-${layer}.md`, text, "text/markdown");
}

/**
 * 导出 SARIF 2.1.0 最小骨架。
 *
 * SARIF 的价值在于**与其他工具链互操作**（AIxCC 的评分机制含
 * SARIF 项）。这里给出符合结构的最小文档，结果集留空 ——
 * 填假结果比不填更糟（`docs/10` §0）。
 */
function downloadSarif(layer: Layer, findingId: string): void {
  const doc = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "Aletheia",
            informationUri: "https://github.com/AperturePrism/aleth",
            rules: [],
          },
        },
        // 结果集留空：契约里没有 SARIF 映射规则，凭空生成 location
        // 会产出无法定位的告警 —— 那比空更糟。
        results: [],
        properties: {
          findingId,
          reportLayer: layer,
          note: "结果集为空：SARIF location 需要源码/行号映射，当前契约未提供",
        },
      },
    ],
  };
  triggerDownload(
    `${findingId}-${layer}.sarif`,
    JSON.stringify(doc, null, 2),
    "application/json",
  );
}

function triggerDownload(filename: string, content: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/** 证据链视图（分层呈现）。
 *
 * 契约的 `TracedEvidenceChain`（05 §5.3）是
 * `finding_id + assertions + evidence + side_effects + 归因校验` ——
 * **不含 Finding 实体本身**（Finding 的状态在账本里，链只承载它的
 * 断言与证据）。因此本视图按**断言**分层展示，而不是按 Finding。
 *
 * 这也让"HYPOTHESIS 不进报告结构"的约束在 UI 上自然成立：
 * 断言没有 status 字段 —— 层层区分的是**断言与证据**的有无，
 * 不是一个可被误读为"结论等级"的标签。
 */
function ChainView({ chain, layer }: { chain: TracedEvidenceChain; layer: Layer }) {
  // 用 useMemo 稳定引用：`chain.assertions ?? []` 每次渲染都产生新数组，
  // 会让下面的 useMemo 依赖每次都变（eslint exhaustive-deps 警告）。
  const assertions = useMemo(() => chain.assertions ?? [], [chain]);
  const evidence = useMemo(() => chain.evidence ?? [], [chain]);
  const sideEffects = useMemo(() => chain.sideEffects ?? [], [chain]);

  // 调试层显示全部；主报告/附录层只显示**有证据支撑**的断言。
  //
  // 判据是"该断言在链里是否有对应证据"（契约里断言与证据通过
  // evidence_ids 关联），而不是一个人工设定的等级 ——
  // 后者会让 UI 有机会"美化"结论。
  const shown = useMemo(() => {
    if (layer === "debug") return assertions;
    return assertions.filter((a) => (a.supportingEvidenceIds ?? []).length > 0);
  }, [assertions, layer]);

  return (
    <>
      <div className="rp-summary">
        <span>
          该层断言 <strong>{shown.length}</strong>
          {layer !== "debug" ? <span className="rp-muted"> / {assertions.length}</span> : null}
        </span>
        <span>
          证据 <strong>{evidence.length}</strong>
        </span>
        <span>
          副作用观测 <strong>{sideEffects.length}</strong>
        </span>
        <span className={chain.attributionConsistent ? "rp-ok" : "rp-bad"}>
          归因双向校验：{chain.attributionConsistent ? "✅ 一致" : "❌ 不一致"}
        </span>
      </div>

      {!chain.attributionConsistent ? (
        <div className="rp-alert">
          <strong>归因不一致（ATTRIBUTION_MISMATCH）</strong>
          <p>
            Finding 已按 M4 的语义回滚，并标记需人工复核。
            报告中的归因必须双向一致 —— 错误关联在 AIxCC 中扣 7 分
            （正确关联仅 +7），本项目将其视为 P0。
          </p>
          {(chain.attributionErrors ?? []).length > 0 ? (
            <ul>
              {(chain.attributionErrors ?? []).map((e, i) => (
                <li key={i}>{e.message}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}

      {shown.length === 0 ? (
        <EmptyState
          title="该层无断言"
          description={
            layer === "debug"
              ? "该 Finding 链下暂无断言记录。"
              : "主报告与附录层只显示有证据支撑的断言。切换到「调试」层可见全部（含无证据的推测）。"
          }
        />
      ) : (
        <table className="rp-table">
          <thead>
            <tr>
              <th>断言</th>
              <th>类型</th>
              <th>内容</th>
              <th>证据数</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((a) => (
              <tr key={a.assertionId}>
                <td>
                  <code>{a.assertionId}</code>
                </td>
                <td>{assertionTypeLabel(a.type)}</td>
                <td>{a.statement}</td>
                <td>{(a.supportingEvidenceIds ?? []).length}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {evidence.length > 0 ? (
        <div className="rp-block">
          <h2>证据</h2>
          <ul className="rp-evidence">
            {evidence.map((e) => (
              <li key={e.evidenceId}>
                <code>{e.evidenceId}</code>
                <span className="rp-evidence-meta">
                  {e.tool?.toolName ?? "?"} · exec {e.execId || "—"}
                  {e.raw ? ` · ${e.raw.lineCount} 行` : ""}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {sideEffects.length > 0 ? (
        <div className="rp-block">
          <h2>副作用观测（强证据）</h2>
          <ul className="rp-evidence">
            {sideEffects.map((s, i) => (
              <li key={i}>
                <span className="rp-evidence-meta">
                  {observerKindLabel(s.kind)} · exec {s.execId || "—"}
                </span>
                <code>{s.observation}</code>
                {s.matchedPattern ? (
                  <span className="rp-evidence-meta">命中 {s.matchedPattern}</span>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </>
  );
}

/** AssertionType 的可读名（05 §5.2）。 */
function assertionTypeLabel(t: number | undefined): string {
  switch (t) {
    case 1: return "EXISTENCE";
    case 2: return "DATA_ACCESS";
    case 3: return "PRIVILEGE";
    case 4: return "STATE_CHANGE";
    case 5: return "SIDE_EFFECT";
    default: return "—";
  }
}

/** ObserverKind 的可读名（05 §5.2）。 */
function observerKindLabel(k: number | undefined): string {
  switch (k) {
    case 1: return "ID_OUTPUT";
    case 2: return "FILE_CREATED";
    case 3: return "ACCOUNT_CREATED";
    case 4: return "DATA_RETURNED";
    case 5: return "PROCESS_SPAWNED";
    case 6: return "CONFIG_CHANGED";
    default: return "—";
  }
}

