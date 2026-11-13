# `contract:` 变更自审材料 —— 供双人 Review

| 项 | 内容 |
|---|---|
| 提交 | `250afd6` — `contract: 补齐三个已登记的契约缺口 + 修复 Plan 未生成 graph_id` |
| 涉及冻结文档 | `docs/05-接口契约与数据模型.md`（§4.2 `AssembleRequest`、§6.2 `OrchestratorService`） |
| 涉及契约文件 | `proto/aleth/v1/aletheia.proto` |
| 变更规模 | 18 文件，+3046 / −486（其中生成物占绝大部分） |
| 规则依据 | `docs/09` §R1：契约变更须独立 PR、标题前缀 `contract:`、**双人 review（其中一人必须是 M4 反幻觉负责人）** |
| 状态 | **⚠️ 待双人签字。本文是自审材料，不是 review 结论。** |

---

## 0. 给审阅者的第一句话

**本文由实施者自写，不构成 R1 要求的 review。** 它的作用是让两位审阅者
在最短时间内看到"改了什么、为什么、风险在哪、怎么验证"，而不是替代他们判断。

签字前请至少做 §5 的三件事（逐条给结论，不要只写"同意"）。

---

## 1. 变更清单

### 1.1 新增 RPC（`OrchestratorService`）

| RPC | 语义 | 解决的问题 |
|---|---|---|
| `GetGraph(session_id, graph_id) → TaskGraph` | **只读**、幂等 | 决策队列（`06` 页面 7）此前**无法读取整图**，只能消费 `NextReady.blocked_reasons`，渲染不出 `06` §7.1 的四要素卡片 |
| `ListSessions(limit, cursor) → SessionSummary[]` | **只读**、幂等、分页 | 会话总览（`06` 页面 1）此前**无法枚举会话** —— 全契约唯一带 List 语义的方法是 `ListAdapters` |

### 1.2 新增消息

`GetGraphRequest` / `ListSessionsRequest` / `ListSessionsResponse` / `SessionSummary`。

`SessionSummary` 刻意**只放计数与状态**，不含任何真实敏感值（高频读取路径
不应成为泄漏面，`07` §T8）。

### 1.3 `AssembleRequest` 新增字段

| 字段号 | 名称 | 语义 |
|---|---|---|
| 7 | `max_hops` | 覆盖图遍历跳数（0 = 不覆盖） |
| 8 | `max_entities` | 覆盖实体数上限（0 = 不覆盖） |
| 9 | `depth_per_entity` | 覆盖每实体属性深度（0 = 不覆盖） |

解决：`04` §I5 DoD① 的「连续调节」此前只能走进程内 API，gRPC 与 MCP 的
`assemble_context` 只能三档。

### 1.4 实现侧同时修复的真缺陷（非契约变更，但同一提交）

**`Plan` 从不生成 `graph_id`**：`NewGraph` 直接采用调用方给的值，不给就留空。
而 `NextReady` / `GetGraph` / 检查点全都要它 —— 实测后果是执行侧拿到空值后
按"空即失败"处理，**整场渗透在第一步就中断**。

修法：缺失时按**内容哈希**派生 `g_<session>_<12hex>`，只纳入结构性字段
（任务 id / 依赖 / 角色 / 预算）。

* 不用自增计数器：那会让同一份计划在不同进程生命周期里得到不同 ID，
  **直接违背 P-5**（检查点/rewind/fork 都比对图版本）；
* 忽略标题/目标文本：改一个错别字不该让图身份变掉，否则已有检查点失联。

---

## 2. 兼容性分析（审阅者请重点看这节）

**结论：全部为纯增量，向后兼容。**

| 维度 | 判断 | 依据 |
|---|---|---|
| 新 RPC | 兼容 | proto3 新增方法不影响旧客户端 |
| 新消息 | 兼容 | 仅被新 RPC 引用 |
| 新字段号 7/8/9 | 兼容 | `AssembleRequest` 此前只用到 1–6，无占用冲突 |
| 旧客户端不发送新字段 | **行为不变** | proto3 scalar 默认 0；`Overrides.IsZero()` 为真时走原路径，有专门用例 |
| 旧服务端收到新客户端请求 | 忽略未知字段 | proto3 语义 |

**wire 兼容已验证**：`make proto` 三侧生成（Go / Python / TS）后
`make check-gen-fresh` 通过；`pytest` / `go test` 全绿。

---

## 3. 风险分析（我自己认为的风险点，请审阅者复核）

| # | 风险 | 缓解 | 残余风险 |
|---|---|---|---|
| 1 | `GetGraph` 显式给了不匹配的 `graph_id` 时，**可能返回当前图**从而让页面拿历史版本之名渲染另一版本 | 实现 **拒绝**（`NOT_FOUND` + 说明），有用例 `TestGetGraphRefusesMismatchedGraphID` | 低 |
| 2 | `ListSessions` 在来源缺失时把成本 **填 0**，与"真的花了 0"不可区分 | Go 侧拿不到 Python 账本的 finding 计数时，适配器返回 `provided=false`，字段**留空**；预算已接 Governor | **中** —— 前端如何渲染"未知"需 UI 侧确认（见 §6 待办） |
| 3 | `ListSessions` 排序用 `session_id` 而非 `created_at` | 编排层只知道"图何时被 Plan"，会话可能更早存在；用本地时钟排序在多实例下不稳定（P-5） | 低（但用户体验上"最新会话排后面"，需产品侧认可） |
| 4 | 覆盖字段可被用来放大曝光（例如一次要 200 实体 × 深 5） | `Overrides.Apply` → `validateApertureSemantics` 在**进入装配循环之前**拒绝"又宽又深"与超上限；有 `TestAssembleRejectsInvalidOverrideCombination` | 低 |
| 5 | `graph_id` 派生规则若变更，会让已有检查点失联 | 规则写在 `graphid.go` 并有用例锁定（跨 Server 稳定、与声明顺序无关、仅措辞变化不变） | 低（但**属于兼容性契约**，未来改规则需同样走 `contract:`） |
| 6 | 新只读 RPC 是否构成新的信息暴露面 | `GetGraph` 需 `session_id`；`ListSessions` 只返回计数与状态，不含证据内容 | 低 |

**我认为最需要 M4 负责人判断的是 #2 与 #6** —— 它们关系到"报告/列表是否会
让人误以为拿到了完整数据"。

---

## 4. 测试证据（可复跑）

```bash
# 契约生成物与契约一致
make proto && make check-gen-fresh          # → OK (Q14)

# 新增 RPC 的测试（整包跑，避免 -run 过滤漏项）
go test ./core/orchestrate/ -count=1 -v
# 相关用例：sessions_test.go 15 个 + graphid_test.go 7 个（实测 grep -c '^func Test'）
# ⚠️ 不要用 `-run 'GetGraph|ListSessions|Derived'` 之类过滤来核对条数：
#    实测过滤后只命中 21 个（`TestCallerSuppliedGraphIDIsPreserved` 不含这些词），
#    会把"23/22/21"这类数字写成错的。

# 覆盖字段的测试（走 gRPC 入口 Assemble，不是内部函数）
go test ./core/aperture/ -count=1 -v
# 相关用例：contract_overrides_test.go 4 个（实测）

# 全量
go test ./cmd/... ./core/... && .venv/Scripts/python.exe -m pytest -q && make gate
```

关键用例（请审阅者抽查这几条）：

| 用例 | 守的是什么 |
|---|---|
| `TestGetGraphRefusesMismatchedGraphID` | 不用"当前图"冒充历史版本 |
| `TestListSessionsLeavesBudgetEmptyWithoutSource` | 来源缺失时留空而非填 0 |
| `TestListSessionsCursorPaginationIsComplete` | 分页不重不漏 |
| `TestDerivedGraphIDIsStableAcrossServers` | P-5 可复现 |
| `TestAssembleRejectsInvalidOverrideCombination` | 覆盖不得绕过物理语义校验 |
| `TestAssembleWithoutOverridesKeepsProfileParams` | 向后兼容 |

---

## 5. 签字前请逐条回答（不要只写"同意"）

1. **新增两个只读 RPC 是否必要？** 有没有不扩契约就能满足页面 1/7 的办法？
   （我方结论：没有 —— 契约此前只有"写"与"按已知 ID 查"。）
2. **`SessionSummary` 的字段集合是否够用且不过度？** 特别是"不含内容"这条
   是否满足 `07` §T8。
3. **字段留空 vs 填 0 的语义**（风险 #2）：契约层面是否应明确写"未提供"
   与"值为 0"的区分方式？（当前只在实现层用适配器 `provided` 表达。）
4. **`graph_id` 派生规则**是否应写进 `05`？（它已实质成为跨模块契约。）
5. **字段号 7/8/9 的命名**（`max_hops` / `max_entities` / `depth_per_entity`）
   是否与 `05` §4.1 的档位参数术语一致。

---

## 6. 已知待办（不阻塞契约评审，但须记录）

| 项 | 说明 |
|---|---|
| 前端渲染"未知" | `SessionSummary` 的 budget/findings 可能为空；页面需区分"未知"与"0" |
| `aperture=off`（`04` §I5 DoD⑦） | **本次刻意未加**：它与"曝光上限 200 / 禁止又宽又深"的安全不变量冲突，正确实现需要一条显式绕过并在审计标记的路径。给契约加一个"永远报错"的字段是陷阱。 |
| finding 计数来源 | 需账本提供计数接口（如 `CountByState`），届时适配器接上即可，无需再改契约 |

---

## 7. 签字栏

| 角色 | 要求 | 姓名 | 日期 | 结论 |
|---|---|---|---|---|
| 审阅人 A | 熟悉 L2/L3/L4 契约语义 | | | ☐ 通过 ☐ 有条件通过 ☐ 退回 |
| 审阅人 B | **M4 反幻觉负责人**（`09` §R1 强制） | | | ☐ 通过 ☐ 有条件通过 ☐ 退回 |

**在两人签字前，本提交中的新 RPC 不得被视为已生效契约** ——
后续实现不应依赖它们，也不得在对外文档中宣称"已支持会话列举/任务图读取"。
