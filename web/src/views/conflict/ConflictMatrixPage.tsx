import { useCallback, useEffect, useMemo, useState } from "react";
import { EmptyState } from "../../components/EmptyState";
import { prismClient } from "../../lib/api";
import type { Entity, Relation } from "@gen/aleth/v1/aletheia";
import "../../styles/conflict.css";

// 06 §6.1 页面 6 —— 冲突矩阵视图（I8 交付）★核心视图。
//
// 06 §6.2 给出的目标形态：
//
//               白盒: 有缺陷        白盒: 无缺陷
//   黑盒: 可利用    ✅ 双源确认 (7)      ⚠ 白盒漏检? (2)
//   黑盒: 打不通    ★ 深度优先 (11)     ○ 低优先级 (34)
//                    ↑ 最高价值象限
//
// **「11 个"打不通但有缺陷"的目标是本次评估最有价值的部分」** ——
// 它们是链式漏洞的候选第一环。在纯 CLI 输出里，这 11 条会混在 54 条
// 结果中（06 §6.2 原文）。
//
// R9 约束：本视图不可省略。省略它等于放弃"三路融合"这一差异化能力 ——
// 而这正是本项目与 PentestGPT / Strix 那类纯黑盒 agent 的分界。
//
// # 数据来源
//
// M7 的融合结果以两种形式落在 M2 图里（M7 §3.1 R3 + §4.5）：
//   · DEFECT 实体 —— 各路的观测（带 SourceKind 的 provenance）
//   · CONTRADICTS 关系 —— 冲突本身（属性含 quadrant）
//
// 因此本页读 PrismService.Project，用 `CONTRADICTS` 关系重建矩阵。
// **这不需要新的契约** —— 与决策队列不同，M7 的输出完全落在既有
// 图模型内（这正是 M7 §3.2 N1「不维护独立存储」的好处）。

type LoadState =
  | { kind: "loading" }
  | { kind: "loaded"; entities: Entity[]; relations: Relation[] }
  | { kind: "unavailable"; detail: string };

const QUADRANT_META: Record<
  string,
  { label: string; row: number; col: number; icon: string; cls: string; priority: string; interpretation: string; action: string }
> = {
  CONFIRMED_BOTH: {
    label: "双源确认",
    row: 0, col: 0, icon: "✅", cls: "q-confirmed",
    priority: "高",
    interpretation: "黑盒可打且静态有缺陷 —— 两个独立来源一致",
    action: "直接进 Candidate，复现后 Confirmed",
  },
  EXPLOITABLE_BUT_CLEAN: {
    label: "白盒漏检?",
    row: 0, col: 1, icon: "⚠",
    cls: "q-clean",
    priority: "中",
    interpretation: "配置/环境类问题，或静态分析漏检（盲区）",
    action: "交叉复核，确认是否为静态盲区",
  },
  UNREACHABLE_BUT_FLAWED: {
    label: "深层优先",
    row: 1, col: 0, icon: "★",
    cls: "q-chained",
    priority: "最高",
    interpretation: "利用条件未满足 / 环境差异 / 需前置认证 —— 可能是链式漏洞的第一环",
    action: "深挖前置条件（不要当作失败丢弃）",
  },
  NEITHER: {
    label: "低优先级",
    row: 1, col: 1, icon: "○",
    cls: "q-low",
    priority: "低",
    interpretation: "黑盒打不通且静态无缺陷 —— 可能确实安全",
    action: "降优先级",
  },
};

export function ConflictMatrixPage() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [selected, setSelected] = useState<string>("");

  const load = useCallback(() => {
    setState({ kind: "loading" });
    // 取全图（含 CONTRADICTS 关系与 DEFECT 实体）。
    prismClient
      .project({ branchId: "", maxEntities: 2000, kinds: [] })
      .then((sub) => {
        setState({
          kind: "loaded",
          entities: sub.entities ?? [],
          relations: sub.relations ?? [],
        });
      })
      .catch((err: unknown) => {
        setState({
          kind: "unavailable",
          detail: err instanceof Error ? err.message : String(err),
        });
      });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const cells = useMemo(
    () => buildCells(state.kind === "loaded" ? state.relations : []),
    [state],
  );

  const total = cells.reduce((n, c) => n + c.items.length, 0);
  const chained = cells.find((c) => c.quadrant === "UNREACHABLE_BUT_FLAWED");

  return (
    <section>
      <h1>冲突矩阵视图</h1>
      <p className="page-hint">
        三路观测（黑盒 / 白盒 / 二进制）的结果对比。
        <strong>冲突不是需要消除的噪声，而是最高价值的信号</strong> ——
        「打不通但有缺陷」是链式漏洞的候选第一环。
      </p>

      <div className="cf-toolbar">
        <button type="button" className="btn" onClick={load}>
          刷新
        </button>
        {total > 0 ? (
          <span className="cf-total">
            冲突总数 <strong>{total}</strong>
          </span>
        ) : null}
      </div>

      {state.kind === "loading" && <p>加载中…</p>}
      {state.kind === "unavailable" && (
        <EmptyState title="冲突矩阵不可用" description={state.detail} />
      )}

      {state.kind === "loaded" && total === 0 && (
        <EmptyState
          title="尚无冲突记录"
          description={
            "冲突由 M7 三路融合产生：同一缺陷同时被两种以上观测路报告且" +
            "结论不一致时，以 CONTRADICTS 关系落图。\n\n" +
            "当前图中没有 CONTRADICTS 关系 —— 可能是尚未执行三路观测，" +
            "或三路结论一致（那就不构成冲突）。"
          }
        />
      )}

      {state.kind === "loaded" && total > 0 && (
        <>
          {chained && chained.items.length > 0 ? (
            <div className="cf-highlight">
              <div className="cf-highlight-head">
                <span className="cf-highlight-icon">★</span>
                <strong>
                  {chained.items.length} 个「打不通但有缺陷」的目标
                </strong>
                <span className="cf-highlight-sub">最高价值象限</span>
              </div>
              <p>
                白盒说有缺陷、黑盒打不通 —— 对纯黑盒 agent 这是盲区（它只知道
                "打不通"），对纯白盒工具也无意义（它不验证可利用性）。
                <strong>它们是链式漏洞的候选第一环。</strong>
                在纯 CLI 输出里，这些会被混在全部结果中。
              </p>
            </div>
          ) : null}

          {/* 四象限矩阵（06 §6.2 的形态） */}
          <table className="cf-matrix">
            <thead>
              <tr>
                <th className="cf-corner"></th>
                <th>白盒：有缺陷</th>
                <th>白盒：无缺陷</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <th className="cf-rowhead">黑盒：可利用</th>
                {[0, 1].map((col) => (
                  <QuadrantCell
                    key={col}
                    cell={cells.find((c) => c.row === 0 && c.col === col)!}
                    selected={selected}
                    onSelect={setSelected}
                  />
                ))}
              </tr>
              <tr>
                <th className="cf-rowhead">黑盒：打不通</th>
                {[0, 1].map((col) => (
                  <QuadrantCell
                    key={col}
                    cell={cells.find((c) => c.row === 1 && c.col === col)!}
                    selected={selected}
                    onSelect={setSelected}
                  />
                ))}
              </tr>
            </tbody>
          </table>

          {/* 选中象限的下钻明细 */}
          {selected ? (
            <QuadrantDetail
              cell={cells.find((c) => c.quadrant === selected)!}
              entities={state.entities}
            />
          ) : (
            <p className="cf-hint">点击象限下钻到具体冲突（06 §6.1 页面 6）。</p>
          )}
        </>
      )}
    </section>
  );
}

type Cell = {
  quadrant: string;
  row: number;
  col: number;
  items: Relation[];
};

/** 从 CONTRADICTS 关系重建四象限（M7 §4.5 的 quadrant 属性）。 */
function buildCells(relations: Relation[]): Cell[] {
  const cells: Cell[] = Object.entries(QUADRANT_META).map(([q, meta]) => ({
    quadrant: q,
    row: meta.row,
    col: meta.col,
    items: [],
  }));
  const byQuadrant = new Map(cells.map((c) => [c.quadrant, c]));

  for (const r of relations) {
    // RelationType 14 = CONTRADICTS（05 §3.1）。
    if (r.type !== 14) continue;
    const q = r.attributes?.quadrant ?? "";
    const cell = byQuadrant.get(q);
    if (cell) cell.items.push(r);
  }
  return cells;
}

function QuadrantCell({
  cell,
  selected,
  onSelect,
}: {
  cell: Cell;
  selected: string;
  onSelect: (q: string) => void;
}) {
  const meta = QUADRANT_META[cell.quadrant];
  const n = cell.items.length;
  const isActive = selected === cell.quadrant;
  return (
    <td
      className={`cf-cell ${meta.cls}${isActive ? " cf-cell-active" : ""}${n === 0 ? " cf-cell-empty" : ""}`}
      onClick={() => (n > 0 ? onSelect(cell.quadrant) : undefined)}
      title={meta.interpretation}
      role="button"
      tabIndex={n > 0 ? 0 : -1}
      aria-pressed={isActive}
    >
      <div className="cf-cell-main">
        <span className="cf-cell-icon">{meta.icon}</span>
        <span className="cf-cell-label">{meta.label}</span>
        <span className="cf-cell-count">({n})</span>
      </div>
      <div className="cf-cell-priority">优先级：{meta.priority}</div>
    </td>
  );
}

function QuadrantDetail({ cell, entities }: { cell: Cell; entities: Entity[] }) {
  const meta = QUADRANT_META[cell.quadrant];
  const byId = useMemo(() => {
    const m = new Map<string, Entity>();
    for (const e of entities) m.set(e.entityId ?? "", e);
    return m;
  }, [entities]);

  return (
    <div className="cf-detail">
      <h2>
        <span className="cf-cell-icon">{meta.icon}</span>
        {meta.label}
        <span className="cf-count">{cell.items.length}</span>
      </h2>
      <dl className="cf-detail-meta">
        <dt>解读</dt>
        <dd>{meta.interpretation}</dd>
        <dt>动作</dt>
        <dd>{meta.action}</dd>
      </dl>

      {cell.items.length === 0 ? (
        <p className="cf-empty">该象限当前没有冲突。</p>
      ) : (
        <table className="cf-table">
          <thead>
            <tr>
              <th>实体</th>
              <th>缺陷类型</th>
              <th>目标</th>
              <th>关系</th>
            </tr>
          </thead>
          <tbody>
            {cell.items.map((r, i) => {
              const e = byId.get(r.fromEntity ?? "");
              const attrs = e?.attributes ?? {};
              return (
                <tr key={`${r.relationId ?? ""}-${i}`}>
                  <td>
                    <code className="cf-eid">{r.fromEntity}</code>
                  </td>
                  <td>{attrs["defect_type"] ?? "—"}</td>
                  <td>{attrs["addr"] ?? r.attributes?.target ?? "—"}</td>
                  <td>
                    <code>{r.fromEntity}</code>
                    <span className="cf-arrow">—CONTRADICTS→</span>
                    <code>{r.toEntity}</code>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      {cell.quadrant === "UNREACHABLE_BUT_FLAWED" && cell.items.length > 0 ? (
        <div className="cf-note cf-note-chained">
          这些目标已由 M7 派生出深挖任务（带结构化{" "}
          <code>target_entity_hints</code>），可在「人机协同决策队列」
          （页面 7）查看。<strong>不要当作失败的利用尝试而跳过</strong>。
        </div>
      ) : null}
    </div>
  );
}
