# I12 成本基准：分级路由 vs 单一前沿模型（真实渠道）

真源判据：`docs/04` §I12 DoD②③。

## 运行

```bash
ALETHEIA_LLM_KEY=... python tests/i12/cost_benchmark.py [--small]
```

三配置对比：单一前沿模型（全走 glm-5.2）/ 分级路由（DEFAULT_TIERS）/
优化路由（rank→deepseek-flash）。负载按真实 agent 分布构造
（planning:analysis:parse:rank = 1:2:4:4，prompt 基于 NAS 靶场真实
扫描观测）。CostLedger 记账：按模型/按档位聚合 + reasoning_tokens 分列。

## 首次执行结论（2026-10-25，--small 试跑 22 调用/配置）

| 配置 | total tokens | reasoning 占比 | 降幅（token 口径） |
|---|---|---|---|
| 单一 glm-5.2 | ~10.6k | — | 基线 |
| 分级路由 | 7414 | **73%** | **31.95%** |
| 优化路由（rank→deepseek-flash） | 7508 | 80% | 31.09% |

**DoD③（分级路由生效 + 成本账本验证）：✅ 达成** —— 三配置真实
渠道账本、按档/按模型聚合、路由确定性（live 测试另有机制级断言）。

**DoD②（降 ≥60%）：❌ token 口径未达成（31.95%）**，如实登记。原因
分析（账本数据支撑）：

1. **reasoning token 是绝对大头**（73-80%）—— 渠道内三个模型全部是
   推理型，「轻档」省的是单价不是 token；
2. rank→deepseek-flash 的调优无效（其 reasoning 同样重）—— 档位内
   换模型解决不了推理开销；
3. token 口径是货币降幅的**下界**（轻档单价通常低一个量级），但本项目
   不引入无据的单价假设。

## DoD② 的达成路径（后续）

| 路径 | 依赖 |
|---|---|
| 货币口径核算（单价差可能直接达成） | 渠道计费单价数据（外部） |
| 轻档推理预算控制（reasoning_effort / 非推理模型） | 渠道参数支持验证 |
| **I13 微调小模型接管高频子任务（降 ≥70% 的设计目标正对本发现）** | 训练基础设施 |

本基准因此同时是 I13 的动机证据：高频子任务（parse/rank 占负载 80%）
的 token 大头在推理开销，微调非推理小模型是结构性的解法。

## 复现说明

`last_run.json` 为 --small（44 次真实调用）试跑数据；全量（220 次）
`python tests/i12/cost_benchmark.py`。渠道限流（429）由 Provider 的
退避重试处理，个别失败计数入 errors 不中断基准。
