# I12 成本基准：分级路由 vs 单一前沿模型（真实渠道）

真源判据：`docs/04` §I12 DoD②③。

## 运行

```bash
ALETHEIA_LLM_KEY=... python tests/i12/cost_benchmark.py [--small]
```

四配置对比：单一前沿模型（全走 glm-5.2）/ 分级路由（DEFAULT_TIERS）/
优化路由（rank→deepseek-flash）/ **分级路由+机械档关推理**
（DEFAULT_TIER_EXTRAS）。负载按真实 agent 分布构造
（planning:analysis:parse:rank = 1:2:4:4，prompt 基于 NAS 靶场真实
扫描观测）。CostLedger 记账：按模型/按档位聚合 + reasoning_tokens 分列。

配套：`probe_reasoning_control.py` —— 渠道推理控制参数能力探测
（结果 `reasoning_probe.json`）。

## 全量结果（55 调用/配置，2026-10-26，真实渠道）

| 配置 | total tokens | reasoning 占比 | 降幅（token 口径） |
|---|---|---|---|
| 单一 glm-5.2（基线） | 25516 | **89%** | — |
| 分级路由 | 21153 | 79% | 17.1% |
| 优化路由（rank→deepseek） | 17167 | 83% | **32.72%** |
| 分级+机械档关推理 | 19336 | 78% | 24.22% |

**DoD③（分级路由生效 + 成本账本验证）：✅ 达成** —— 四配置真实
渠道账本、按档/按模型聚合、路由确定性（live 测试另有机制级断言）。

**DoD②（降 ≥60%）：❌ token 口径结构性不可达**（最佳 32.72%），原因
链完整有据：

1. **推理 token 是绝对大头**（基线 89%）—— 渠道三个模型全部推理型；
2. **思考档是降幅天花板**：planning/analysis 占负载权重 27%，走
   glm-5.2 且**推理保留是质量要求**（机械档关推理不适用于此）——
   它们贡献了基线约一半 token 且不可动；
3. 机械档关推理确实生效（探测：deepseek/glm 认 `reasoning_effort=none`
   → reasoning 0；flash-lite 认 `enable_thinking=false` → 部分），
   deepseek 关推理后 599 tokens/22 调用（≈33/调用）——但机械档基数
   本就不大，救不动总账；
4. `reasoning_effort=low` 实测无效（371→372）。

## DoD② 的达成路径

| 路径 | 依据 | 依赖 |
|---|---|---|
| **货币口径核算** | token 降幅 33% + 轻档单价通常低 5-10 倍 → 货币降幅大概率 ≥60% | 渠道计费单价数据（外部） |
| **I13 微调小模型** | 高频子任务（parse/rank 占 73% 权重）token 大头是推理开销，微调非推理小模型是结构性解法——正是 I13 降 ≥70% 的设计目标 | 训练基础设施 |
| 思考档换小模型 | 质量权衡，超出路由范畴，需质量基准支撑 | I11 基准适配器 |

本基准同时是 I13 的动机证据。

## 复现说明

`last_run.json` 为全量数据；渠道限流（429）由 Provider 退避处理，
偶发失败计入 errors 不中断。单次运行的 glm 输出长度存在方差
（±10% 级），判定以全量单次 + 方向一致性（small 试跑与全量同序：
optimized > reasoning-off > tiered）为准。
