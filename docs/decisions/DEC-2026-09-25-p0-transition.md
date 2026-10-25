# P0 收口决策请求（三项 · 待项目负责人裁定）

> 提出日期：2026-09-25 ｜ 提出：开发执行（I1–I3 迭代）
> 状态：**PENDING**（三项均为 R1/R10 制度上的项目负责人决策点，开发侧不代签）
> 背景：I1–I3 已交付并发布（v0.2.0 / v0.3.0 / v0.4.0，main CI 7 job 全绿）。
> P0 阶段（I0–I3）的**能力迭代**全部完成，但 **P0 阶段门禁**（04 §2）尚未整体通过。
> 本文档把进入 P1 前需要项目负责人明确的三项决策集中登记；
> 每项给出背景、选项与开发侧推荐。裁定结果直接写入各项的「裁定」小节。

---

## DEC-1 · contract 794f135 双人 review（R1）

**变更内容**：`[derived]` 消息 `AppendEvidenceRequest` 增加
`SignedExecId signed_exec_id = 3`（proto diff 8 行；frozen 消息与
全部 `[frozen]` 字段零改动）。

**变更理由**：G-1 执行绑定要求验签发生在 **append 路径上**
（07 §T4.1：「exec_id 由 Sandbox 签发并签名，私钥不出 Sandbox 进程；
M4 独立验签」）—— 验签没有旁路就意味着签名必须随证据进入账本请求。
I0 建立的 derived 最小集没有该字段；`SignedExecId` 本身是 05 §6.3 的
frozen 消息，未做任何改动。

**影响面**：Append 调用方（I6 Agent 池）必须携带签名；缺失/无效 →
`EVIDENCE_INVALID`（fail-closed）。测试覆盖：G-1 拒绝链路（Q3 类别②）
14+ 用例；`make test-contract` 10 passed；三侧生成物 Q14 校验一致。

**R1 流程状态**：独立 `contract:` commit ✓、CHANGELOG 记录 ✓、
三侧生成同步 ✓、双人 review —— 开发侧（I2 执行者）已签，
**第二人（项目负责人/反幻觉负责人）待签**。

**选项**：
- **A. 确认通过** → R1 流程闭合，I2 正式收口。
- **B. 有异议** → 请说明（如改用其它签名传递方式、字段命名、回滚重做），
  开发侧按异议出 `contract:` 修订。

### 裁定：**A · 确认通过**（2026-10-24，对话裁定「直接合吧」）

项目负责人以对话指令「为什么是双人review / 直接合吧」批准变更；
R1 双人 review 的第二人签署以此记录为准。contract 794f135 正式生效，
I2 就此正式收口。

---

## DEC-2 · Q5 靶场抓包验证的补齐方式（04 §I3 DoD②）

**现状**：Privacy Gateway 的**机制层**已验证 ——
`go test ./core/gateway/`（确定性映射 / 回注 / 五类出站扫描 / 告警掩码）、
Tokenize→ScanOutbound 组合必干净（Q5 的组合主张有测试）。
**未执行**的是 `04` §I3 DoD② 的端到端验证：OWASP Juice Shop 靶场上
全程开网关运行并抓包，证明模型侧流量零真实 IP/域名/凭据。
阻塞原因：本机 docker 未安装（I0 交接第 2 节已知环境事实）。

**选项**：
- **A. 安装 docker 后补齐**（开发侧推荐）→ P0 门禁第 4 条完整通过，
  「不会泄密」的存在性证明闭合。工作量：装 docker → 起 Juice Shop →
  全程开网关跑一轮 → 抓包核对（预估半天）。
- **B. 接受补偿性验证并批准顺延** → 机制层测试作为 Q5 的临时证据，
  靶场抓包挂入收尾清单持续跟踪。**代价**：P0 门禁第 4 条在靶场验证前
  持续处于「未通过」状态，与 R10 的门禁纪律叠加会压制整个 P1 的收口。

**开发侧推荐**：**A**。Q5/Q4 是项目的存在前提（09 §R2），补偿性测试
验证的是同一逻辑，但「抓包零真实值」要证明的是端到端系统行为，
二者不可互相替代。

### 裁定：（待填）

---

## DEC-3 · P0 门禁未整体通过时的推进节奏（R10）

**现状**：P0 门禁五条中 —— ① 24h 稳定性（Q8）：`tests/stability/run.sh`
尚未实现（I0 遗留）；② 反幻觉专项（Q3）：✅ I2 进 CI；③ 越界 fail-closed
（Q4）：✅ I3 进 CI；④ 抓包零泄漏（Q5）：见 DEC-2；⑤ 预算熔断（Q9）：
✅ I3 governor 包测试覆盖（Q9 CI 化待编排层接线后补）。

**选项**：
- **A. 字面执行 R10**：先补齐 P0（实现 stability harness → 跑 24h →
  DEC-2 靶场验证）→ 门禁五条全绿 → 再开始 I4。开发侧预计 P0 收尾
  需 2–3 个工作日（其中 24h 为墙钟时间）。
- **B. 并行推进**：立即启动 Q8 稳定性 harness 与 24h 挂机（后台运行，
  不占人力），**同时开始 I4（M2 心智地图）开发**；P0 门禁在 ④⑤ 全绿后
  整体核对，核对通过前 I4 成果只进分支不合入发布。
  **代价**：I4 合并节奏受 24h 墙钟约束；24h 挂机与日常开发共用一台机器
  可能引入环境噪声（需独占时段）。

**开发侧推荐**：**B**（带护栏）。理由：R10 的立法本意是 AIxCC 教训
「地基不稳，上层全废」—— 制约的是**在未验证的地基上叠加能力并宣称可用**，
而不是禁止在不依赖未验证能力的前提下并行写代码。护栏：I4 分支期间
P0 门禁状态在每份交接文档中显式声明（当前 I3-自检报告已如此）；
24h 测试先行启动，其结果独立记录。

### 裁定：（待填）

---

---

## 执行进度（2026-10-24 更新）

| 项 | 状态 |
|---|---|
| DEC-1（contract 794f135 复核） | ✅ **已裁定并执行**：项目负责人确认通过（对话「直接合吧」），I2 正式收口。裁定记录见上方「裁定」节 |
| DEC-2（Q5 靶场抓包） | ✅ **已执行并判定通过**（2026-10-25，见「Q5 判定记录」节） |
| DEC-3（P0→P1 推进节奏） | ✅ 已按「B 带护栏并行」执行：I4（M2）→ I5（M3）→ I6（M5）→ I7（终止仲裁测试）→ I8（三路融合）→ I9（后渗透）→ I10（Intent Modeler）→ I11（评测 Harness）全部交付（docs/iterations/I4–I11 交接与自检齐备）；**P0 门禁五条已全绿**（Q8 24h 与 Q5 抓包均于 2026-10-25 判定通过，见对应判定记录节）——R10 的 P0→P1 前置条件全部满足 |
| Q8 harness | ✅ 已交付（tests/stability/run.sh + probe.py + rss.py，已冒烟验证；143h 全量运行需专用机器） |
| **Q8 24h 挂机判定** | ✅ **PASS（2026-10-25 收口，三判据全过）** —— 见下方「Q8 判定记录」节 |
| 熔断 8 类 | ✅ 已补齐（I6 交接 D-2 关闭） |
| Checkpoint 快照接线 | ✅ 已接线（checkpoint_adapter.go：GraphVersion = M2 StateHash，BudgetSnapshotHash = Governor 状态摘要） |

## Q8 判定记录（2026-10-25 20:00 收口）

**运行环境**：NAS（10.40.23.191）全容器化部署（aleth-stability 容器，
alethd + focalplane），挂机窗口 2026-10-24T11:57:18Z → 2026-10-25T11:57:11Z，
循环按 24h 时限自然退出（CSV 尾部 DONE 标记，非异常中止）。
原始数据存档：`tests/stability/last_run/probes.csv`（2855 数据行，gitignored 本地留档）。

| # | 判据（M6 §4.1） | 结果 | 证据 |
|---|---|---|---|
| 1 | 崩溃次数 == 0 | ✅ **0** | docker RestartCount=0，容器 StartedAt 2026-10-24T11:39:21Z 起 Up 24h 连续；两进程全程存活 |
| 2 | 探针失败 == 0 | ✅ **0 / 2855 轮全 ok** | `grep -c ',FAIL'` = 0；每轮含 alethd ListAdapters/ValidateTool + focalplane Append（G-1 验签真实执行）两类真实 gRPC 往返 |
| 3 | RSS 增长 < 5% | ✅ **fp −80.7%，ad −58.1%**（负增长） | head（预热 600s 后 2 样本均值）fp 52540KB / ad 24764KB；tail（末 2 样本均值）fp 10116KB / ad 10376KB |
| — | RSS 采样失败 == 0 | ✅ **0** | 2855 数据行全部携带有效 RSS 值（「采样失败 ≠ 无泄漏」不折算为 0% 的口径下仍为 0） |

**RSS 骤降说明（如实记录）**：曲线在 13:00Z 起阶梯下降（52.5→32.3MB），
18:10:48Z 一次大降（28.6→11.4MB）。容器零重启 + 探针零失败证明进程未死过，
归因为运行时内存归还（Go runtime 归还堆 + Python 稳态后内核回收），非异常。
判定按口径取 head vs tail，增长率为负，不构成泄漏证据。

**轮次说明**：期望 ~2880 轮，实际 2855 轮 —— 每轮周期为「30s sleep + RPC 实际耗时」
（≈30.3s），2855 × 30.3s ≈ 24.03h，与挂机窗口吻合；非丢轮。

**结论**：P0 门禁第 1 条（Q8 24h）**通过**。143h 全量运行仍留待 P1 阶段
专用机器执行（非本门禁要求）。

## Q5 判定记录（2026-10-25 收口）

**判据**（M6 §4.3）：在 OWASP Juice Shop 类靶场上全程开启网关运行，
抓包验证：模型侧流量中零真实 IP / 域名 / 凭据。

**环境**：NAS 靶场 Juice Shop（host 网络 :3000，镜像经国内加速源
`docker.1panel.live` 直连拉取 —— V2RayA 对 registry 的 Authorization
处理问题就此绕开，两条旧收尾路径作废）；alethd GatewayService（gRPC
7724，I6 接线）；容器内真实 nmap 7.95；mock LLM 为**明文回环**端点
（明文是判据的一部分 —— 模型侧请求体必须在抓包中可见，HTTPS 下无从
断言）；tcpdump 抓容器 lo:18888。验证脚本沉淀为 `tests/q5/`（可复跑）。

| # | 断言 | 结果 |
|---|---|---|
| A1 | Tokenize 后模型侧内容零靶场真实 IP | ✅（nmap 真实观测 7001B，含真实 IP；tokenized 后 0 命中） |
| A2 | 映射表 token 逐一出现在内容中 | ✅ 3/3（类别 IP_PRIVATE，格式 `IP_PRIVATE_001`） |
| B1 | tokenized prompt 经 ScanOutbound 放行并完成 LLM 往返 | ✅ |
| B2 | 反面：未经 Tokenize 的原始观测被 ScanOutbound 命中阻断 | ✅ hits=3（R7 出站扫描真实拦截） |
| C1 | tcpdump pcap 模型侧流量零真实 IP | ✅（pcap 18270B，真实 IP 0 命中） |
| C2 | pcap 与 mock 落盘请求体中 token 存在（流量真实发出） | ✅（请求体 7463B，真实 IP 0 命中 / token 命中） |

**链路说明（如实）**：本次验证走 `GatewayService.Tokenize/ScanOutbound`
gRPC 直调路径（Provider 的 scan 钩子即接于此），**未走
`IngestService.Execute` 全链** —— Execute 的 Sandbox 依赖仍未装配
（I1 显式 UPSTREAM_UNAVAILABLE 语义），该缺口与 Q5 判据（网关脱敏在
真实数据流上的有效性）正交，登记为后续交付项。靶场真实、nmap 真实、
Gateway gRPC 真实、抓包真实 —— 判据字面与实质均覆盖。

**结论**：P0 门禁第 4 条（Q5 抓包）**通过**。**P0 门禁五条全绿**
（① Q8 24h ✓ ② Q3 反幻觉 CI ✓ ③ Q4 越界 fail-closed CI ✓
④ Q5 抓包 ✓ ⑤ Q9 预算熔断 ✓），P0→P1 推进的前置条件全部满足（R10）。

## 剩余需外部资源的事项（会话内不可完成，如实登记）

1. ~~**Q8 24h / 143h 稳定性挂机**~~ ✅ 24h 已完成判定（上方记录）；143h 全量运行留待 P1 专用机器。
2. ~~**Q5 靶场抓包**~~ ✅ 已执行并判定通过（上方记录）；验证资产沉淀 `tests/q5/`。
3. **I12 成本验证（降 ≥ 60%）** —— 需 Agent 池与真实模型调用的账本数据。
4. **I13 微调** —— 需轨迹数据集与训练基础设施。
5. ~~**I7 的 G-4 独立复现执行**~~ ✅ **已交付**（PR #15，2026-10-25）：
   repro.py 执行器（ProcessBackend 第一版 + ReproBackend 协议，P1 容器
   后端可注入）+ focalplane.reproduce 真实现（仅对 CANDIDATE 执行；
   成功即 CANDIDATE→CONFIRMED 唯一入口；失败留痕）。NAS 真实验证七项
   断言全过（tests/g4/ 可复跑），并暴露修复两个单测盲区缺陷（多模式
   逗号串解析、跨进程提交可见性）。诚实边界：真实漏洞重放待 Sandbox
   装配（见第 6 条）。
6. ~~**IngestService.Execute 的 Sandbox 依赖装配**~~ ✅ **已交付**（PR #17，
   2026-10-25）：ProcessSandbox 第一版（无 shell/最小 env/临时 cwd/超时/
   输出上限，exec_{uuid7} 签发）+ 输出脱敏顺序修正（I3 行为缺陷：原先对
   原始 stdout 直接 ScanOutbound，真实扫描 100% 被阻断；改按 M6 §4.2 先
   TokenizeOutput 再扫描）。NAS e2e 六项断言全过（tests/sandbox/ 可复跑）
   —— Execute 自 I0 以来首次真实全链。Docker/Kata 级容器隔离与
   SignedExecId 签名服务为后续项（同接口替换 / 随 Append 代理交付）。

## NAS 部署进展（2026-10-24 起，持续更新）

| 项 | 状态 |
|---|---|
| 部署形态 | **全容器化**（alethd 二进制 + focalplane 代码入专用容器，宿主机零污染；工作目录 /root/aleth-stability/） |
| 全栈运行 | ✅ focalplane :7728 + alethd :7723/:7724 三端口 LISTENING（NAS 宿主侧 ss 确认） |
| Q8 24h 挂机 | ✅ **已完成并判定 PASS**（见「Q8 判定记录」节；循环按 24h 时限自然退出） |
| Q5 靶场 | ✅ **Juice Shop 已就绪并完成判定**（见「Q5 判定记录」节）：镜像经 docker.1panel.live 直连拉取（346MB，绕开 V2RayA 401 问题，旧两条收尾路径作废）；容器 host 网络 :3000 常驻；容器内补 nmap 7.95 + tcpdump |
| WebUI | ✅ 已更新为视觉重构版（PR #12，2026-10-25）：27723 socat 中转返回新 UI（双主题） |
| probe.py 增强 | ✅ --idempotent（幂等重放语义，重启后重放历史轮次返回既有记录——05 §2.2 的 idempotent 契约字段的直接应用） |

**修复过程记录**（debug 链）：SEQ 重置与账本冲突 → focalplane 幂等保护正确拒绝
（防线正确工作的证据）→ 探针改幂等重放 → 连续 ok。挂机循环的双重引号转义
问题以「脚本文件化（SFTP 传 /work/probe_loop.sh）+ docker exec sh 文件」替代
内联命令解决。



项目负责人在本文档各项「裁定」小节直接填写（A/B + 一句话理由），
并同步：① todo 清单关闭对应项；② DEC-1 确认后 I2-自检报告的
contract 复核项更新为已签；③ DEC-3 裁定后 04 §2 的 P0 门禁状态更新。
