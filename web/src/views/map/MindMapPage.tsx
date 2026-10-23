import { useCallback, useEffect, useMemo, useState } from "react";
import { EmptyState } from "../../components/EmptyState";
import { classifyError, prismClient } from "../../lib/api";
import type { Entity, ProjectedSubgraph, Relation } from "@gen/aleth/v1/aletheia";
import "../../styles/map.css";

// 06 §6.1 页面 3 —— 心智地图浏览器（I4 交付）。
//
// 页面职责（06 §6.1 / M2 §2.1）：让用户看见"系统记住了什么"。
// 三种模式（06 §6.1 原文要求"图视图 + 表视图双模，按类型/来源/置信度
// 筛选，支持时间回放"）：
//
//   1. 表视图 —— 实体的扁平清单，可排序、可按类型筛选；
//   2. 图视图 —— 以焦点实体为中心的邻域关系（不在浏览器里做力导向布局：
//      图规模上去后布局抖动会让"记住什么"这个判断本身失真，改用
//      按关系类型的结构化邻接表 —— 更接近 M2 §4.2「视图投影」的本意）；
//   3. 时间回放 —— 拖动到任意时刻，看见当时的认知状态（M2 §4.4）。
//
// I4 范围说明：图后端未运行时显示不可用状态而非假数据
// （docs/09 §6 #4：不渲染看起来正常的空结果）。

type LoadState =
  | { kind: "loading" }
  | { kind: "loaded"; sub: ProjectedSubgraph }
  | { kind: "unavailable"; detail: string }
  | { kind: "error"; detail: string };

/** 七类实体（05 §3.1）的显示名与配色键。 */
const KIND_META: Record<number, { label: string; cls: string }> = {
  1: { label: "资产", cls: "k-asset" },
  2: { label: "服务", cls: "k-service" },
  3: { label: "身份", cls: "k-identity" },
  4: { label: "端点", cls: "k-endpoint" },
  5: { label: "缺陷", cls: "k-defect" },
  6: { label: "路径", cls: "k-path" },
  7: { label: "事件", cls: "k-timeline" },
};

/** 关系类型的可读名（05 §3.1 RelationType）。 */
const RELATION_LABEL: Record<number, string> = {
  1: "解析到",
  2: "运行于",
  3: "认证到",
  4: "拥有权限",
  5: "暴露",
  6: "属于",
  7: "调用",
  8: "位于",
  9: "可被利用",
  10: "使能",
  11: "依赖",
  12: "先于",
  13: "印证",
  14: "矛盾",
};

export function MindMapPage() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [view, setView] = useState<"table" | "graph">("table");
  const [kindFilter, setKindFilter] = useState<number | "all">("all");
  const [focus, setFocus] = useState<string>("");
  const [replayAt, setReplayAt] = useState<string>("");

  const load = useCallback(() => {
    setState({ kind: "loading" });
    const req = {
      branchId: "",
      focus,
      maxHops: focus ? 2 : 0,
      maxEntities: 500,
      kinds: [],
    };
    const call = replayAt
      ? prismClient.snapshotAt({
          branchId: "",
          // ts-proto 的 Timestamp 映射为 Date（不是 {seconds,nanos}）。
          at: new Date(replayAt),
          maxEntities: 500,
        })
      : prismClient.project(req);

    call
      .then((sub: ProjectedSubgraph) => setState({ kind: "loaded", sub }))
      .catch((err: unknown) => {
        // 区分三类失败 —— 它们对使用者的含义完全不同，混为一谈会让人
        // 误判「功能不存在」，而实际可能只是守护进程没启动：
        //   1. UNIMPLEMENTED → 该服务还没交付（诚实告知，指向迭代规划）；
        //   2. 传输层失败   → 前端根本没连上（端点配置 / daemon 未运行）；
        //   3. 其他 gRPC 错误 → 服务在，但请求被拒。
        const cls = classifyError("PrismService", err);
        if (cls instanceof Error && cls.name === "UnimplementedError") {
          setState({
            kind: "unavailable",
            detail: "PrismService 尚未交付（见 docs/04 §4 的迭代规划）。",
          });
        } else {
          setState({
            kind: "error",
            detail: err instanceof Error ? err.message : String(err),
          });
        }
      });
  }, [focus, replayAt]);

  useEffect(() => {
    load();
  }, [load]);

  // ts-proto 对 repeated 字段生成可选类型；统一在取值处收敛为数组。
  const entities: Entity[] = useMemo(
    () => (state.kind === "loaded" ? (state.sub.entities ?? []) : []),
    [state],
  );
  const relations: Relation[] = useMemo(
    () => (state.kind === "loaded" ? (state.sub.relations ?? []) : []),
    [state],
  );

  const shown = useMemo(
    () => (kindFilter === "all" ? entities : entities.filter((e) => e.kind === kindFilter)),
    [entities, kindFilter],
  );

  /** 按类型统计（用于筛选器上的计数与"看得见有多少"）。 */
  const counts = useMemo(() => {
    const m = new Map<number, number>();
    for (const e of entities) {
      const k = e.kind ?? 0;
      m.set(k, (m.get(k) ?? 0) + 1);
    }
    return m;
  }, [entities]);

  return (
    <section>
      <h1>心智地图浏览器</h1>
      <p className="page-hint">
        M2 是系统的唯一真源：上下文、agent 记忆、报告全部从它派生。
        这里让「系统记住了什么」可见 —— 包括记住了几个版本、来自哪个来源。
      </p>

      <div className="map-toolbar">
        <div className="map-viewswitch">
          <button
            type="button"
            className={view === "table" ? "btn btn-active" : "btn"}
            onClick={() => setView("table")}
          >
            表视图
          </button>
          <button
            type="button"
            className={view === "graph" ? "btn btn-active" : "btn"}
            onClick={() => setView("graph")}
          >
            关系视图
          </button>
        </div>

        <label className="map-field">
          <span>类型</span>
          <select
            value={kindFilter === "all" ? "all" : String(kindFilter)}
            onChange={(e) =>
              setKindFilter(e.target.value === "all" ? "all" : Number(e.target.value))
            }
          >
            <option value="all">全部（{entities.length}）</option>
            {Object.entries(KIND_META).map(([k, meta]) => (
              <option key={k} value={k}>
                {meta.label}（{counts.get(Number(k)) ?? 0}）
              </option>
            ))}
          </select>
        </label>

        <label className="map-field">
          <span>焦点实体</span>
          <input
            value={focus}
            placeholder="entity_id（留空 = 全景）"
            onChange={(e) => setFocus(e.target.value.trim())}
          />
        </label>

        <label className="map-field">
          <span>回放到</span>
          <input
            type="datetime-local"
            value={replayAt}
            onChange={(e) => setReplayAt(e.target.value)}
          />
        </label>

        <button type="button" className="btn" onClick={load}>
          刷新
        </button>
        {replayAt ? (
          <button type="button" className="btn" onClick={() => setReplayAt("")}>
            退出回放
          </button>
        ) : null}
      </div>

      {state.kind === "loading" && <p>加载中…</p>}
      {state.kind === "unavailable" && (
        <EmptyState title="心智地图不可用" description={state.detail} />
      )}
      {state.kind === "error" && (
        <EmptyState
          title="无法连接 PrismService"
          description={
            `${state.detail}\n\n` +
            "常见原因：alethd 未运行（先 ./bin/alethd --authorization roe.yaml），" +
            "或前端构建产物与后端不是同一次构建（重新 make build）。"
          }
        />
      )}

      {state.kind === "loaded" && (
        <>
          <div className="map-summary">
            <span>
              实体 <strong>{entities.length}</strong>
            </span>
            <span>
              关系 <strong>{relations.length}</strong>
            </span>
            {state.sub.snapshotId ? (
              <span className="map-snapshot">
                快照 <code>{state.sub.snapshotId}</code>
              </span>
            ) : null}
            {replayAt ? <span className="map-replay-badge">时间回放中</span> : null}
          </div>

          {entities.length === 0 && relations.length === 0 ? (
            <EmptyState
              title="图中还没有实体"
              description="心智地图随光谱摄入增长。先执行一次工具调用（IngestService.Execute），实体与关系会出现在这里。"
            />
          ) : view === "table" ? (
            <EntityTable entities={shown} />
          ) : (
            <RelationGraph entities={entities} relations={relations} focus={focus} />
          )}
        </>
      )}
    </section>
  );
}

/** 表视图：实体清单 + 版本/置信度/来源列。 */
function EntityTable({ entities }: { entities: Entity[] }) {
  if (entities.length === 0) {
    return <EmptyState title="该类型下没有实体" description="调整上方类型筛选。" />;
  }
  return (
    <table className="map-table">
      <thead>
        <tr>
          <th>实体</th>
          <th>类型</th>
          <th>版本</th>
          <th>置信度</th>
          <th>假设</th>
          <th>属性</th>
        </tr>
      </thead>
      <tbody>
        {entities.map((e) => {
          const kind = e.kind ?? 0;
          const meta = KIND_META[kind] ?? { label: `#${kind}`, cls: "" };
          return (
            <tr key={`${e.entityId ?? ""}-${String(e.version ?? 0)}`}>
              <td>
                <code className="map-eid">{e.entityId}</code>
              </td>
              <td>
                <span className={`map-kind ${meta.cls}`}>{meta.label}</span>
              </td>
              <td>
                v{e.version ?? 1}
                {e.validTo ? <span className="map-muted"> · 已过期</span> : null}
              </td>
              <td>{(e.confidence ?? 0).toFixed(2)}</td>
              <td>{e.isHypothesis ? <span className="map-hyp">假设</span> : "—"}</td>
              <td>
                <AttrList attrs={e.attributes ?? {}} />
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

/** 关系视图：以关系类型分组的结构化邻接表。
 *
 *  刻意不做力导向布局：图规模上去后布局抖动会让"记住了什么"这个判断
 *  本身失真。结构化邻接表更接近 M2 §4.2「视图投影」的本意 ——
 *  用户要判断的是"关系对不对"，不是"图好不好看"。
 */
function RelationGraph({
  entities,
  relations,
  focus,
}: {
  entities: Entity[];
  relations: Relation[];
  focus: string;
}) {
  const byId = useMemo(() => {
    const m = new Map<string, Entity>();
    for (const e of entities) m.set(e.entityId ?? "", e);
    return m;
  }, [entities]);

  const grouped = useMemo(() => {
    const m = new Map<number, Relation[]>();
    for (const r of relations) {
      const t = r.type ?? 0;
      const list = m.get(t) ?? [];
      list.push(r);
      m.set(t, list);
    }
    return [...m.entries()].sort((a, b) => a[0] - b[0]);
  }, [relations]);

  if (relations.length === 0) {
    return (
      <EmptyState
        title="没有关系"
        description="当前投影未包含关系。关系在实体同时出现于同一光谱时自动抽取（如 SERVICE —运行于→ ASSET）。"
      />
    );
  }

  const label = (id: string) => {
    const e = byId.get(id);
    if (!e) return <code className="map-eid map-eid-external">{id}</code>;
    const kind = e.kind ?? 0;
    const meta = KIND_META[kind] ?? { label: `#${kind}`, cls: "" };
    const attrs = e.attributes ?? {};
    const main = attrs["addr"] ?? attrs["url"] ?? e.entityId ?? "";
    return (
      <span className="map-node">
        <span className={`map-kind ${meta.cls}`}>{meta.label}</span>
        <code>{main}</code>
      </span>
    );
  };

  return (
    <div className="map-graph">
      {grouped.map(([type, list]) => (
        <div key={type} className="map-relgroup">
          <h3>
            {RELATION_LABEL[type] ?? `关系 #${type}`}
            <span className="map-relcount">{list.length}</span>
          </h3>
          <ul>
            {list.map((r, i) => {
              const isContradicts = type === 14;
              return (
                <li
                  key={`${r.relationId ?? ""}-${i}`}
                  className={isContradicts ? "map-rel map-rel-conflict" : "map-rel"}
                >
                  <span className={focus && r.fromEntity === focus ? "map-rel-focus" : ""}>
                    {label(r.fromEntity ?? "")}
                  </span>
                  <span className="map-arrow">→</span>
                  <span>{label(r.toEntity ?? "")}</span>
                  {isContradicts ? (
                    <span className="map-conflict-note">
                      三路融合的冲突以此关系落图，冲突不合并（05 §3.1）
                    </span>
                  ) : null}
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </div>
  );
}

function AttrList({ attrs }: { attrs: Record<string, string> }) {
  const keys = Object.keys(attrs ?? {}).sort();
  if (keys.length === 0) return <span className="map-muted">—</span>;
  return (
    <span className="map-attrs">
      {keys.map((k) => (
        <span key={k} className="map-attr">
          <span className="map-attr-key">{k}</span>
          <span className="map-attr-val">{attrs[k]}</span>
        </span>
      ))}
    </span>
  );
}
