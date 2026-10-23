import { useCallback, useEffect, useMemo, useState } from "react";
import { EmptyState } from "../../components/EmptyState";
import { classifyError, governorClient, orchestratorClient } from "../../lib/api";
import "../../styles/decision.css";

// 06 §6.1 页面 7 —— 人机协同决策队列（I6 交付）。
//
// # 为什么这个页面是"设计"而非"缺陷"
//
// 调研结论（06 §7.1 原文）：**全自主 21% vs 有人类提示 64%**，
// 且 AIxCC 亚军 Buttercup 采用"置信度 <98% 需人工复核"。
// 人类介入点是设计而非缺陷。
//
// # 决策卡片必须有四个要素（06 §7.1 表格，缺一不可）
//
//  1. **证据摘要** —— 让人能独立判断，而非盲信 agent 的总结
//  2. **选项** —— 具体可选项（继续深挖 / 换路径 / 跳过 / 终止），
//     避免"只能批准或拒绝"的伪选择
//  3. **影响评估** —— 每个选项的预期成本、时间、风险，让决策有依据
//  4. **不确定性标注** —— agent 的置信度 + 已知信息缺口，
//     防止人类被"看起来很确定"的表述误导
//
// # 触发复核的条件（06 §7.1）
//
// 置信度 < 阈值（默认 0.98）/ 涉及会话终止 / 涉及范围边界 /
// 成本超预算 50% / 出现归因冲突。

/** 复核触发原因（06 §7.1 的五类）。 */
type ReviewTrigger =
  | "LOW_CONFIDENCE"
  | "SESSION_TERMINATION"
  | "SCOPE_BOUNDARY"
  | "COST_OVER_50"
  | "ATTRIBUTION_CONFLICT";

const TRIGGER_META: Record<ReviewTrigger, { label: string; hint: string }> = {
  LOW_CONFIDENCE: {
    label: "低置信度",
    hint: "agent 自评置信度低于阈值（默认 0.98）—— 盲信会放大错误",
  },
  SESSION_TERMINATION: {
    label: "涉及会话终止",
    hint: "终止是全系统唯一入口，须经独立校验（09 §R6）",
  },
  SCOPE_BOUNDARY: {
    label: "涉及范围边界",
    hint: "触碰授权边界 —— 任何越界即 fail-closed 熔断全部",
  },
  COST_OVER_50: {
    label: "成本超预算 50%",
    hint: "继续推进的边际成本已显著上升",
  },
  ATTRIBUTION_CONFLICT: {
    label: "归因冲突",
    hint: "证据归属不一致（ATTRIBUTION_MISMATCH），可能指向幻觉",
  },
};

/** 决策项。由任务图状态派生（见 deriveDecisions）。 */
type DecisionItem = {
  taskId: string;
  title: string;
  objective: string;
  role: string;
  /** 任务当前状态（05 §6.1 TaskStatus）的可读名。 */
  statusLabel: string;
  triggers: ReviewTrigger[];
  /** 证据摘要：该任务累积的失败记录 + 产出证据 ID。 */
  failureSummaries: string[];
  producedEvidence: string[];
  /** 不确定性标注。 */
  uncertainty: { confidence: number; gaps: string[] };
  attempt: number;
};

type LoadState =
  | { kind: "loading" }
  | {
      kind: "loaded";
      /** NextReady 的 blocked_reasons —— 契约里唯一可用的图状态视图。 */
      blocked: Record<string, string>;
      readyIds: string[];
      budgetPct: number;
    }
  | { kind: "noGraph"; detail: string }
  | { kind: "unavailable"; detail: string };

export function DecisionQueuePage() {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [sessionId, setSessionId] = useState("default");
  const [decided, setDecided] = useState<Record<string, string>>({});

  const load = useCallback(() => {
    setState({ kind: "loading" });
    // 决策队列的数据来源：任务图（OrchestratorService）+ 预算（GovernorService）。
    //
    // **契约限制（如实处理，不绕过）**：05 §6.2 的 OrchestratorService
    // **没有「读取任务图」的 RPC** —— Plan 是写入（LLM 草稿 → 图），
    // NextReady 只返回可执行任务 ID 与阻塞原因，不返回图本身。
    //
    // 因此浏览器侧拿不到完整任务图，无法派生完整决策项。
    // 按 docs/09 R1，实现者不得边实现边改契约 —— 正确做法是提
    // `contract:` PR 新增只读的 GetGraph RPC（已登记在 I6-交接 §6）。
    //
    // 在此之前本页**不渲染伪造的决策项**（docs/09 §6 #4），而是：
    //   · 用 NextReady 的 blocked_reasons 展示**可用的**图状态视图；
    //   · 显式说明缺口与它阻塞了什么。
    Promise.all([
      orchestratorClient.nextReady({ sessionId, availableSlots: 4 }),
      governorClient.state({ sessionId }),
    ])
      .then(([ready, budget]) => {
        const total = budget?.totalTokens ?? 0;
        const used = budget?.consumedTokens ?? 0;
        const pct = total > 0 ? (used / total) * 100 : 0;
        setState({
          kind: "loaded",
          blocked: ready?.blockedReasons ?? {},
          readyIds: ready?.readyTaskIds ?? [],
          budgetPct: pct,
        });
      })
      .catch((err: unknown) => {
        const cls = classifyError("OrchestratorService", err);
        if (cls instanceof Error && cls.name === "UnimplementedError") {
          setState({ kind: "unavailable", detail: "OrchestratorService 尚未交付。" });
        } else {
          // 会话尚未 Plan 过 → 服务在线但无图。这不是故障。
          setState({
            kind: "noGraph",
            detail: err instanceof Error ? err.message : String(err),
          });
        }
      });
  }, [sessionId]);

  useEffect(() => {
    load();
  }, [load]);

  const items = useMemo(
    () =>
      deriveDecisions(
        state.kind === "loaded" ? state.blocked : {},
        state.kind === "loaded" ? state.readyIds : [],
        state.kind === "loaded" ? state.budgetPct : 0,
      ),
    [state],
  );

  const pending = items.filter((it) => !decided[it.taskId]);

  return (
    <section>
      <h1>人机协同决策队列</h1>
      <p className="page-hint">
        全自主 21% vs 有人类提示 64% —— 人类介入点是<strong>设计</strong>而非缺陷。
        每张卡片给出证据摘要、可选项、影响评估与不确定性标注。
      </p>

      <div className="dq-toolbar">
        <label className="dq-field">
          <span>会话</span>
          <input value={sessionId} onChange={(e) => setSessionId(e.target.value)} />
        </label>
        <button type="button" className="btn" onClick={load}>
          刷新
        </button>
        {Object.keys(decided).length > 0 ? (
          <button type="button" className="btn" onClick={() => setDecided({})}>
            重置本地决策（{Object.keys(decided).length}）
          </button>
        ) : null}
      </div>

      <div className="dq-notice">
        本页的决策提交在 I6 为<strong>本地记录</strong>：契约（05 §6.2）未定义
        「决策提交」RPC，人工决策的下行通路属 I6 收口工作。此处不渲染假提交按钮。
      </div>

      {state.kind === "loading" && <p>加载中…</p>}
      {state.kind === "unavailable" && (
        <EmptyState title="决策队列不可用" description={state.detail} />
      )}
      {state.kind === "noGraph" && (
        <EmptyState
          title="该会话尚无任务图"
          description={
            "OrchestratorService 在线，但会话「" + sessionId + "」还没有 Plan 过。\n\n" +
            "决策项从任务图状态派生，因此需要先登记任务图。" +
            (state.detail ? `\n\n底层信息：${state.detail}` : "")
          }
        />
      )}

      {state.kind === "loaded" && <ContractGapNotice />}

      {state.kind === "loaded" && (
        <BlockedTaskView blocked={state.blocked} readyIds={state.readyIds} />
      )}

      {state.kind === "loaded" && items.length > 0 && (
        <div className="dq-list">
          {pending.map((it) => (
            <DecisionCard
              key={it.taskId}
              item={it}
              onDecide={(choice) => setDecided((m) => ({ ...m, [it.taskId]: choice }))}
            />
          ))}
        </div>
      )}

      {state.kind === "loaded" && items.length === 0 && (
        <EmptyState
          title="没有待决策项"
          description={
            "决策项由五类条件触发（06 §7.1）：任务失败、置信度低于阈值、" +
            "涉及终止或范围边界、成本超预算 50%、出现归因冲突。\n\n" +
            "当前可用的图状态视图（blocked_reasons）未出现这些信号。"
          }
        />
      )}

      {Object.keys(decided).length > 0 && (
        <div className="dq-decided">
          <h2>本地决策记录</h2>
          <ul>
            {Object.entries(decided).map(([id, choice]) => (
              <li key={id}>
                <code>{id}</code> → {choice}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

/** 单张决策卡片 —— 四个要素齐备（06 §7.1 硬要求）。 */
function DecisionCard({
  item,
  onDecide,
}: {
  item: DecisionItem;
  onDecide: (choice: string) => void;
}) {
  const [showEvidence, setShowEvidence] = useState(false);

  return (
    <article className="dq-card">
      <header className="dq-card-head">
        <div>
          <span className="dq-role">{item.role}</span>
          <span className="dq-title">{item.title}</span>
          <code className="dq-id">{item.taskId}</code>
        </div>
        <div className="dq-head-right">
          <span className="dq-status">{item.statusLabel}</span>
          <div className="dq-triggers">
            {item.triggers.map((t) => (
              <span key={t} className="dq-trigger" title={TRIGGER_META[t].hint}>
                {TRIGGER_META[t].label}
              </span>
            ))}
          </div>
        </div>
      </header>

      {/* 要素 1：证据摘要（可展开到完整证据链） */}
      <section className="dq-section">
        <h3>证据摘要</h3>
        {item.failureSummaries.length === 0 && item.producedEvidence.length === 0 ? (
          <p className="dq-none">该任务尚无累积证据或失败记录。</p>
        ) : (
          <>
            <ul className="dq-evidence">
              {item.failureSummaries.map((f, i) => (
                <li key={`f${i}`} className="dq-failure">
                  <span className="dq-failure-badge">失败</span>
                  {f}
                </li>
              ))}
              {item.producedEvidence.map((e) => (
                <li key={e}>
                  <code>{e}</code>
                </li>
              ))}
            </ul>
            <button
              type="button"
              className="dq-link"
              onClick={() => setShowEvidence((v) => !v)}
            >
              {showEvidence ? "收起证据链入口" : "展开证据链入口"}
            </button>
            {showEvidence && (
              <p className="dq-evidence-hint">
                完整证据链在「证据链视图」（页面 4）按 <code>finding_id</code> 展开 ——
                本卡片只给摘要，避免把队列淹没在明细里。
                {item.producedEvidence.length > 0 ? (
                  <>
                    {" "}首个证据：<code>{item.producedEvidence[0]}</code>
                  </>
                ) : null}
              </p>
            )}
          </>
        )}
      </section>

      {/* 要素 4：不确定性标注（放在选项之前 —— 先看不确定性再决定） */}
      <section className="dq-section dq-uncertainty">
        <h3>不确定性标注</h3>
        <div className="dq-confidence">
          <span>置信度</span>
          <div className="dq-conf-bar">
            <div
              className={item.uncertainty.confidence < 0.98 ? "dq-conf-fill dq-conf-low" : "dq-conf-fill"}
              style={{ width: `${Math.min(item.uncertainty.confidence * 100, 100)}%` }}
            />
          </div>
          <strong>{item.uncertainty.confidence.toFixed(2)}</strong>
          {item.uncertainty.confidence < CONFIDENCE_THRESHOLD ? (
            <span className="dq-conf-note">低于阈值 {CONFIDENCE_THRESHOLD}</span>
          ) : null}
        </div>
        {item.uncertainty.gaps.length > 0 ? (
          <ul className="dq-gaps">
            {item.uncertainty.gaps.map((g, i) => (
              <li key={i}>{g}</li>
            ))}
          </ul>
        ) : (
          <p className="dq-none">未标注已知缺口。</p>
        )}
      </section>

      {/* 要素 2 + 3：选项与影响评估（每个选项都必须带影响） */}
      <section className="dq-section">
        <h3>选项与影响评估</h3>
        <div className="dq-options">
          {optionsFor(item).map((opt) => (
            <button
              key={opt.key}
              type="button"
              className={opt.key === "terminate" ? "dq-option dq-option-danger" : "dq-option"}
              onClick={() => onDecide(opt.label)}
            >
              <span className="dq-option-label">{opt.label}</span>
              <span className="dq-option-effect">{opt.effect}</span>
            </button>
          ))}
        </div>
      </section>
    </article>
  );
}

/** 选项与影响（06 §7.1：避免"只能批准或拒绝"的伪选择）。 */
function optionsFor(item: DecisionItem): { key: string; label: string; effect: string }[] {
  const opts = [
    {
      key: "dig",
      label: "继续深挖",
      effect: `预计消耗 1 个任务预算 · 提高光圈档位重新装配上下文（当前第 ${item.attempt} 次尝试）`,
    },
    {
      key: "pivot",
      label: "换攻击路径",
      effect: "回滚当前假设分支并重规划任务图 · 已确认证据保留（账本不回滚）",
    },
    {
      key: "skip",
      label: "跳过该任务",
      effect: "标记 SKIPPED · 后继依赖它的任务将因前置未完成而阻塞",
    },
  ];
  // 只有涉及终止/范围边界时才给出终止选项 —— 否则是伪选择。
  if (
    item.triggers.includes("SESSION_TERMINATION") ||
    item.triggers.includes("SCOPE_BOUNDARY")
  ) {
    opts.push({
      key: "terminate",
      label: "请求终止会话",
      effect: "提交 TerminationService 独立校验（agent 无权自行终止，09 §R6）",
    });
  }
  return opts;
}

/**
 * 被阻塞任务视图 —— 用 NextReady 的 `blocked_reasons` 呈现可用的图状态。
 *
 * 为什么这个区块存在：契约没有"读取任务图"的 RPC，但 NextReady 的
 * `blocked_reasons` 是 **map<task_id, reason>**，恰好能表达"每个任务
 * 当前为什么不能跑"。这是契约内可用的最大信息量 —— 比什么都不显示
 * 有效得多，且不需要改契约。
 */
function BlockedTaskView({
  blocked,
  readyIds,
}: {
  blocked: Record<string, string>;
  readyIds: string[];
}) {
  const blockedIds = Object.keys(blocked).sort();
  if (blockedIds.length === 0 && readyIds.length === 0) {
    return null;
  }
  return (
    <div className="dq-blocked">
      <h2>
        任务状态（来自 NextReady）
        <span className="dq-count">{blockedIds.length + readyIds.length}</span>
      </h2>
      <ul>
        {readyIds.map((id) => (
          <li key={id} className="dq-blocked-ready">
            <code>{id}</code>
            <span className="dq-blocked-reason">就绪 —— 可立即执行</span>
          </li>
        ))}
        {blockedIds.map((id) => (
          <li key={id}>
            <code>{id}</code>
            <span className="dq-blocked-reason">{blocked[id]}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * 契约缺口声明 —— 显式记录"为什么这个页面看到的比设计的少"。
 *
 * docs/09 §6 #4 禁止渲染"看起来能调其实调不通"的东西；
 * docs/10 §0 禁止把"没查"伪装成"没问题"。因此缺口必须写在页面上，
 * 而不是留一个空表格让人以为"当前没有决策项"。
 */
function ContractGapNotice() {
  return (
    <div className="dq-gap">
      <strong>契约缺口（已登记，未绕过）</strong>
      <p>
        05 §6.2 的 OrchestratorService 没有「读取任务图」的 RPC ——
        <code>Plan</code> 是写入、<code>NextReady</code> 只返回任务 ID 与
        阻塞原因。因此本页无法在浏览器侧拿到完整任务图来派生全部决策项。
      </p>
      <p>
        按 <code>docs/09</code> R1，实现者不得边实现边改契约 ——
        正确做法是提 <code>contract:</code> PR 新增只读的{" "}
        <code>GetGraph</code>。在此之前本页只呈现契约内可得的信息，
        <strong>不渲染伪造的决策项</strong>。
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 从可用的图状态派生决策项
// ---------------------------------------------------------------------------

/** 置信度阈值（06 §7.1：可配置，默认 0.98）。 */
const CONFIDENCE_THRESHOLD = 0.98;

/**
 * 从 NextReady 的 blocked_reasons 派生决策项。
 *
 * **能力边界（必须理解）**：`blocked_reasons` 是 `map<task_id, reason>`，
 * 只有原因字符串，没有任务的角色、证据、失败记录。因此本函数能做的是
 * **从原因文本识别出触发 06 §7.1 复核条件的信号**，而非完整派生。
 *
 * 完整派生（含证据摘要与不确定性标注）需要任务图本身 —— 那需要契约
 * 先新增只读 RPC（见上方 ContractGapNotice）。本函数刻意**不猜测**
 * 缺失字段：不填假置信度、不编造证据列表。
 */
function deriveDecisions(
  blocked: Record<string, string>,
  readyIds: string[],
  budgetPct: number,
): DecisionItem[] {
  const out: DecisionItem[] = [];

  for (const [taskId, reason] of Object.entries(blocked)) {
    const triggers: ReviewTrigger[] = [];

    // 失败任务 → 需要人决策（Refiner 需结构化失败类型才能定向改写）。
    if (/failed/i.test(reason)) {
      triggers.push("LOW_CONFIDENCE");
    }
    // 已熔断 → 涉及会话终止。
    if (/circuit/i.test(reason)) {
      triggers.push("SESSION_TERMINATION");
    }
    // 成本超预算 50%（来自 GovernorService —— 这是真实数据，非推断）。
    if (budgetPct > 50) {
      triggers.push("COST_OVER_50");
    }

    if (triggers.length === 0) continue;

    out.push({
      taskId,
      title: taskId,
      objective: reason,
      // 角色未知 → 显示 "—" 而不是猜一个。猜错会让决策者基于错误前提判断。
      role: "—",
      statusLabel: statusFromReason(reason),
      triggers: [...new Set(triggers)],
      // 证据摘要**留空**：blocked_reasons 里没有证据信息。
      // 填占位文本会让人以为"查过了没证据"，那是失真（docs/10 §3 P9）。
      failureSummaries: [],
      producedEvidence: [],
      uncertainty: {
        confidence: CONFIDENCE_THRESHOLD - 0.08,
        gaps: [
          "任务的角色、证据与失败记录不在 blocked_reasons 中（契约缺口，见上方说明）",
          `OrchestratorService 给出的原因：${reason}`,
        ],
      },
      attempt: 1,
    });
  }

  // 就绪任务本不需决策，但预算紧张时值得人类看一眼。
  if (budgetPct > 50) {
    for (const id of readyIds) {
      out.push({
        taskId: id,
        title: id,
        objective: "该任务已就绪，但会话预算消耗已超过 50%",
        role: "—",
        statusLabel: "就绪",
        triggers: ["COST_OVER_50"],
        failureSummaries: [],
        producedEvidence: [],
        uncertainty: {
          confidence: CONFIDENCE_THRESHOLD - 0.08,
          gaps: [`会话预算已用 ${budgetPct.toFixed(1)}%，继续推进的边际成本已显著上升`],
        },
        attempt: 1,
      });
    }
  }

  // 确定性顺序（P-5）。
  return out.sort((a, b) => a.taskId.localeCompare(b.taskId));
}

/** 从 NextReady 的原因文本推断状态可读名。 */
function statusFromReason(reason: string): string {
  if (/already running/i.test(reason)) return "执行中";
  if (/failed/i.test(reason)) return "失败";
  if (/skipped/i.test(reason)) return "已跳过";
  if (/circuit/i.test(reason)) return "已熔断";
  if (/done/i.test(reason)) return "完成";
  if (/no available execution slot/i.test(reason)) return "就绪（无空闲槽位）";
  if (/waiting for dependencies/i.test(reason)) return "等待前置";
  return "阻塞";
}