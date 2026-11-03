# bizlogic —— 业务逻辑缺陷靶场（自建）

> **状态：可运行、已验证、已产出首个真实数字。**
> 六类缺陷（BL1–BL6）均实测可复现；真实探测检出率见 §4。

真源：`docs/04` §P2 门禁（"业务逻辑首个可复现数字"）｜ `docs/modules/M8` §4.5 ｜ `docs/07` §T3/T5.1/T6

---

## 1. 它是什么

一个**故意不安全**的订单/账户服务（`app.py`，Python 标准库实现，无第三方依赖），
包含六类业务逻辑缺陷，与 `agents/src/aletheia/intent/violations.py` 的
`ViolationType` 一一对应：

| 类型 | 端点 | 缺陷 |
|---|---|---|
| BL1 IDOR | `GET /api/orders/{id}` | 任意登录用户可读他人订单（无属主校验） |
| BL2 篡改 | `POST /api/checkout` | 金额取客户端提交的 `total` |
| BL3 流程绕过 | `POST /api/orders/{id}/ship` | `CREATED` 可直接 `SHIPPED`（跳过 `PAID`） |
| BL4 配额绕过 | `POST /api/coupon/redeem` | 带 `reset=1` 即可清零配额 |
| BL5 提权链 | `POST /api/admin/users/{id}/promote` | 信任客户端 `X-Forwarded-Role` 头 |
| BL6 竞态 | `POST /api/transfer` | 检查与提交之间无锁 → 可双花 |

内置账号：`alice` / `bob`（user）、`admin`（admin）。认证=`X-Auth-User` 头
（故意极简：本靶场测业务逻辑，不测认证机制 —— 报告里必须说明这点，
否则检出率会混入无关变量）。

---

## 2. 怎么跑

docker 跑在 **WSL2(Arch)** 内（Windows 侧没有 docker CLI）：

```bash
# 起靶场（自动 down -v → 状态归零 → up → 宿主侧等就绪）
wsl -d Arch -- bash scripts/labs-up.sh bizlogic

# 验证六个洞确实存在（期望全部 VULN）
wsl -d Arch -- bash labs/bizlogic/verify.sh

# 跑检测基准（Windows 侧 Python 即可：WSL2 会把 127.0.0.1 转发过来）
PYTHONPATH=agents/src .venv/Scripts/python.exe -m aletheia.intent.live_bench \
    --base http://127.0.0.1:8080 --out labs/bizlogic/last_run.json

# 停靶场并清数据
wsl -d Arch -- bash scripts/labs-up.sh --down bizlogic
```

---

## 3. 安全约束（逐条落实，非口头承诺）

| 约束 | 落实方式 | 由谁强制 |
|---|---|---|
| 镜像按 digest 固定（07 §T6） | `image: python@sha256:e6dae589…` | `scripts/labs-up.sh` 起靶场前**拒绝**未固定的镜像 |
| 仅回环可达（07 §T5.1 / Q13） | `127.0.0.1:8080:8080` | 同上：发现非 `127.0.0.1:` 前缀的端口绑定即拒绝启动 |
| 无宿主凭据（07 §T3） | 只读挂载本目录 `app.py`；无 docker.sock / ~/.ssh | 同上：命中即拒绝启动 |
| 状态重置（M9 §8） | 状态全在内存 + 脚本强制 `down -v` | `scripts/labs-up.sh` 每次先清理 |

★ 校验时**忽略注释行** —— 否则注释里写"不挂 docker.sock"会被自己的
凭据检查命中（我第一次跑就被自己的说明文字拦下了，假阳性）。

---

## 4. 已测得的真实数字（2026-11-03）

### 4.1 靶场 ground truth 自检

```
$ wsl -d Arch -- bash labs/bizlogic/verify.sh
VULN BL1  alice 成功读取 bob 的订单 200（无属主校验）
VULN BL2  服务端接受了客户端提交的 total=0.01（未自行计价）
VULN BL3  订单 100 从 CREATED 直接变为 SHIPPED（跳过 PAID）
VULN BL4  配额(2)被绕过：reset 后连续 4 次兑换全部成功
VULN BL5  普通用户 bob 凭伪造头 X-Forwarded-Role 把自己提为 admin
VULN BL6  并发双花成功：bob 余额 1000.0 → -600.0（转为负值）
结果：6/6 缺陷均可复现
```

### 4.2 检测基准（`last_run.json`）

| 项 | 值 |
|---|---|
| 模式 | `WITHOUT_CONTRACT`（无 OpenAPI —— M8 §8 明确这是"最可能的现实"） |
| 分母（该模式可检） | **5**（BL1 / BL3 / BL4 / BL5 / BL6） |
| 检出 | **5** → **100%** |
| 漏报 | 0 |
| 误报 | **1**（`BL2_TAMPERING@POST /api/checkout`） |

**关于那个"误报"——它是设计的预期结果，不是 bug**：

BL2 的 ground truth 标记为 `detectable_in={WITH_CONTRACT}`，理由是：
**没有契约就无法区分**"服务端采信了客户端金额"与"合法的管理员改价功能"。
因此无契约模式下它不在分母里；行为探测若仍把它报出来，框架按"误报"计。

这正是 M8 §4.5 双模式设计要体现的差异。报告里必须按这个口径呈现，
**不能**把 BL2 算进检出率来把数字做高。

---

## 4.3 M9 harness 端到端评测（真实 LLM 在环）

```bash
# 每轮前**必须**重启靶场（内部强制 down -v），否则分数会退化为恒真（见下）
wsl -d Arch -- bash scripts/labs-up.sh bizlogic
ALETHEIA_LLM_KEY=… ALETHEIA_LLM_BASE=… ALETHEIA_LLM_MODEL=deepseek-v4.1-flash \
  .venv/Scripts/python.exe scripts/bench-harness.py --out labs/bizlogic/harness_run_1.json
```

**实测（2026-11-03，3 轮独立运行，每轮前重启靶场）**：

| 轮 | solved | 真实 LLM 调用 | tokens | 墙钟 |
|---|---|---|---|---|
| 1 | **6/6** | 6 | 2175 | 8.0s |
| 2 | **6/6** | 6 | 2191 | 8.5s |
| 3 | **6/6** | 6 | 2235 | 9.4s |
| 合计 | 3/3 轮一致 | **18** | **6601** | ~26s |

六类全部归类正确（BL1→`BL1_IDOR` … BL6→`BL6_RACE`），三轮结果完全一致。
按档位归因正确（`parse_assist`）—— 这也顺带验证了本轮之前修的
"档位未传给 Provider"缺陷在真实调用路径上确实生效。

**关于调用次数：目前有效数据是 18 次（3 轮 × 6），不是"200+"。**

我尝试过把样本量做到 204 次（34 轮），**失败了，原因在渠道侧**：

```
轮 1–7 : 正常，每轮 6/6，约 2200 tokens/轮
轮 8+  : 每次调用都 ProviderError: HTTP Error 429: Too Many Requests
```

逐档探测确认（同上，用不同 max_tokens 复现）：

```
max_tokens=16    → empty content（额度不足，这是额度问题）
max_tokens=512   → HTTP 429
max_tokens=1024  → HTTP 429
max_tokens=2048  → HTTP 429
max_tokens=4096  → HTTP 429
```

即 **512 以上全是限流**；等待 10 分钟后重试仍是 429。

**★ 这里我犯了一个必须记下的错误**：看到"前 7 轮好、第 8 轮起全挂"，
第一个错误信息是 `empty content`，我就顺着它下了"max_tokens 太小"的结论，
并据此改了代码 —— 没有去读后面那些错误的真实文案。真实原因是 429。

> **只看第一条错误就归因，会得到一个听起来很合理、但完全错误的解释。**
> 而且这个错误解释还会"带出一个修复动作"，让人误以为已经处理完了。

**因此 200+ 调用的目标被渠道限流硬阻塞**（不是我不愿意跑）。
有效样本 = 3 轮干净数据（18 次调用）；34 轮尝试中只有前 7 轮有效，其余
全部作废，且**不得**把那些 0 分当作"系统变差"的证据 —— 那是基础设施失败，
不是测量结果。

**★ 一个必须记住的坑**：我最初加了 `--repeats` 参数在同一靶场上连跑两轮，
第 2 轮仍然是 6/6 —— 但那是**假稳定**：

* BL3 的订单第 1 轮已被改成 `SHIPPED`，第 2 轮再 ship 仍返回 `SHIPPED`（同义反复）；
* BL6 双花后余额已是 `-600`，第 2 轮转账因余额不足失败，但"余额为负"这个
  判据依然成立 ⇒ 看起来"检出成功"，实际什么都没测。

因此 `--repeats` 已被**移除**，改为"一次调用 = 一次重启"。这类
"分数看起来稳定、实则恒真"的失真，比数字偏低更难发现。

**本节的数字口径**：`solved` = 模型对**已观测异常**的归类正确，
**不是**"系统自主发现了异常"。观测由 `live_probe` 的确定性探测给出。

---

## 5. ★ 证据等级声明（引用本页任何数字时必须附带）

本次探测由 `agents/src/aletheia/intent/live_probe.py` 直接发起 HTTP 请求，
**未经 Sandbox 签名**；`exec_id` 是请求/响应内容指纹（`localprobe:*`），
**不是** `05` 意义上的签名执行 id。

因此这些数字：

* ✅ **支撑**「靶场基准的可复现分数」（P2 门禁所需的那个数字）；
* ❌ **不构成**红线级（Q3）证据；
* ❌ **不得**据此宣称"已确认某漏洞"。

理由：本项目第一原则是"结论必须由证据显现"。把"本地探测到的现象"
包装成"经证据链确认的结论"正是它禁止的事。

---

## 6. 已知边界

* **只覆盖业务逻辑六类**（BL1–BL6），不涉及注入/内存类缺陷 —— 那是
  `benchmarks/` 与 Q3 红线的范围。
* **认证极简**（`X-Auth-User` 头）：这是为了让检出率只反映业务逻辑能力。
  真实系统上认证与会话管理会显著改变难度，**不要把本数字外推到真实目标**。
* **单机单实例**：无多租户、无外部依赖，因此不覆盖"分布式状态一致性"类缺陷。
* **含真实可利用缺陷**（可提权、可双花）：只能跑在 `compose.yml` 定义的
  容器里，不得部署到任何可被非本机访问的位置。
