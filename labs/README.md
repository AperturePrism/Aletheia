# labs/ —— 自建靶场

> **状态（2026-11-03 更新）：可运行。** docker 已在 **WSL2(Arch)** 内装好并验证，
> 两个靶场已落地并实跑：
>
> | 靶场 | 状态 | 说明 |
> |---|---|---|
> | `juice-shop/` | ✅ 可运行 | 镜像 digest 固定；`/rest/admin/application-version` → `{"version":"17.1.1"}` |
> | `bizlogic/` | ✅ 可运行 + **已出真实数字** | 六类缺陷（BL1–BL6）实测全可复现；检测基准 + harness 端到端评测（18 次真实调用，3 轮一致 6/6）见 `bizlogic/README.md` §4 |
> | `multi-hop/` | ✅ 可运行 | 真实两跳分段：internal **不发布端口**（宿主直连不到），只能经 front 代理触达；`verify.sh` 4/4 断言 |
> | `antifantasy/` | ⬜ 未建 | 反幻觉靶场（返回"看似有证据实则没有"的响应，验 M4 闸门）。设计要点见 §2 |
>
> **P2 阶段门禁**：`bizlogic` 已产出门禁要求的「业务逻辑首个可复现数字」；
> 「公开基准可复现分数」仍需 `benchmarks/` 的真实任务清单（见该目录 README）。

真源：`docs/04` §P2 阶段门禁 ｜ `docs/modules/M9-评测框架.md` §8 ｜ `docs/07` §T3/T5.1/T6/T8

---

## 0. 环境前提（重要）

本机的 docker **不在 Windows 侧**，而在 **WSL2 的 Arch 发行版内**：

```bash
# 一次性：启动 daemon（未启用 systemd 的项目，或 systemctl start docker）
wsl -d Arch -- bash -lc "nohup dockerd > /tmp/dockerd.log 2>&1 &"

# 之后用脚本起停靶场
wsl -d Arch -- bash scripts/labs-up.sh juice-shop bizlogic
wsl -d Arch -- bash scripts/labs-up.sh --down bizlogic
```

`scripts/labs-up.sh` 会在起靶场前**机械校验**三条硬约束
（digest 固定 / 仅回环 / 无宿主凭据），不合规直接拒绝 —— 见 §3。

WSL2 会把 `127.0.0.1` 上的监听端口转发到 Windows，因此 Windows 侧的
Python/CLI 可以直接访问 `http://127.0.0.1:<port>`（实测 `bizlogic` 的
`/health` 在 Windows 侧返回 200）。

---

## 1. 为什么这里是空的（而不是放一份"看起来能起"的 compose）

写一份**没跑过**的 compose 编排，会交付一个"看起来已完成"的靶场。代价：

1. **`07` §T6 要求镜像按 digest 固定** —— 我拿不到真实 digest，
   写 `image: juice-shop:latest` 会直接违反我们自己的威胁模型；
2. **没验证过的编排与没有编排，在下一次接手时是同一回事**，
   但前者更危险（它让人以为可以开跑了）。

因此本目录只提供**设计约束**与**验收清单**，不提供未经运行的编排。

---

## 2. 四个靶场的用途

| 目录 | 用途 | 对应门禁 / DoD |
|---|---|---|
| `antifantasy/` | 伪造证据与张冠李戴的对抗靶场 | Q3 红线复验 |
| `bizlogic/` | 业务逻辑缺陷（IDOR / 越权 / 状态机绕过） | I10 真实检出数字 |
| `multi-hop/` | 跨主机多跳与凭据复用 | I9 后渗透路径规划 |
| `juice-shop/` | 已知漏洞的对照靶场 | Q5 抓包零泄漏（已在 NAS 手工运行过） |

---

## 3. 实现者必须满足的约束（不可协商）

| # | 约束 | 依据 | 验收方式 |
|---|---|---|---|
| 1 | 镜像**按 digest 固定**（`image: repo@sha256:...`） | `07` §T6 | `grep -E 'image: .*@sha256:' compose.yml` 必须全部命中 |
| 2 | 容器内**无宿主凭据**（不挂 docker.sock、不挂 ~/.ssh、不挂云凭据） | `07` §T3 | 人工审阅 `volumes:` 与 `environment:` |
| 3 | 仅**回环可达**（`127.0.0.1:<port>:<port>`，不写 `0.0.0.0`） | `07` §T5.1 / Q13 | `check-loopback` 门禁 + 人工核 |
| 4 | 每次评测后**完全重建**（`down -v && up -d`） | `M9` §8 | `manifest_adapter.reset()` 已强制抛错指向此步骤 |
| 5 | 靶场自身**不含外网直连**（出站全经代理或完全阻断） | `07` §T8 | 抓包验证（Q5 同款方法） |
| 6 | 启动脚本幂等、可重复执行 | 工程实践 | 连续跑两次输出一致 |

---

## 4. 建议的实现步骤

1. 在目标机器上确认 docker 可用（`docker compose version`）；
2. 为每个靶场写 `compose.yml`，镜像用**已存在的公开 digest**
   （`docker pull` 后 `docker inspect --format='{{index .RepoDigests 0}}'` 取真实值）；
3. 写 `scripts/labs-up.sh <lab>` / `labs-down.sh <lab>`，内部 `down -v` 保证重置；
4. 按 §3 的六条**逐条验收**，把验收结果写进对应靶场的 `README.md`；
5. 写 `tasks.json` 到 `benchmarks/`（见 `benchmarks/README.md` §3），
   用 `manifest_adapter` 加载并实跑，把分数写进 `docs/iterations/` 的迭代文档。

**第 4 步不可跳过**：没有验收记录的靶场等于没做 —— 它会产出无法解释的分数。

---

## 5. 当前阻塞

* **docker 不可用**（本机 `docker: command not found`）
* 因此：编排无法编写后验证 → 靶场无法起 → 公开基准无法跑 →
  **P2 阶段门禁无法通过**

这不是可以通过改文档或改门禁解决的问题（`docs/09` R10 与 R2 都禁止那样做）。
