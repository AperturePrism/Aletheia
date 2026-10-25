# Q5 端到端验证（隐私网关抓包 · P0 红线）

真源判据：`docs/modules/M6` §4.3 ——「在 OWASP Juice Shop 类靶场上全程
开启网关运行，抓包验证：**模型侧流量中零真实 IP / 域名 / 凭据**」。
门禁定义：`docs/04` §6 Q5（阻断合并）。

## 为什么不在 CI 里跑

需要真实靶场容器 + 真实 nmap + 真实网络路径上的抓包 —— CI 沙箱不具备
（且把内网地址写进 CI 也不符合判据本意）。因此这是一套**手动验证资产**：
在任何有 docker 的机器上按下方步骤复跑，判定结果记录进
`docs/decisions/DEC-2026-09-25-p0-transition.md`。

## 环境

| 组件 | 要求 |
|---|---|
| 靶场 | Juice Shop 容器（host 网络 :3000），镜像可经国内加速源拉取（如 `docker.1panel.live/bkimminich/juice-shop`） |
| alethd | `--authorization` 启动（GatewayService gRPC 在 7724，I6 起接线） |
| 容器内工具 | `nmap`（apt），`tcpdump`（apt） |
| Python | 容器内 agents 包（`aletheia.providers` + `aletheia.gen`） |

## 步骤

```bash
# 1. mock LLM（明文回环 :18888 —— 明文是判据的一部分：
#    抓包必须能看到模型侧请求体，HTTPS 下无从断言）
docker exec -d <容器> sh -c 'python /work/mock_llm.py'

# 2. 抓模型侧流量
docker exec -d <容器> sh -c 'rm -f /work/q5.pcap; tcpdump -i lo -w /work/q5.pcap port 18888'

# 3. 验证（真实 nmap → Tokenize → scan 出站 → 反面用例）
docker exec <容器> sh -c 'cd /work && PYTHONPATH=/app/app python q5_verify.py'

# 4. 抓包断言
docker exec <容器> sh -c 'pkill tcpdump; \
  echo "真实IP命中(应0): $(tcpdump -A -r /work/q5.pcap 2>/dev/null | grep -c <靶场IP> || true)"; \
  echo "token命中(应>0): $(tcpdump -A -r /work/q5.pcap 2>/dev/null | grep -c IP_PRIVATE_ || true)"'
```

## 断言清单（与 q5_verify.py + 抓包脚本一一对应）

| # | 断言 | 层 |
|---|---|---|
| A1 | Tokenize 后的模型侧内容零靶场真实 IP | 机制（gRPC 真实调用） |
| A2 | 映射表 token 逐一出现在内容中（替换真实发生，非删词） | 机制 |
| B1 | tokenized prompt 经 ScanOutbound 放行并完成 LLM 往返 | 机制 |
| B2 | **反面**：未经 Tokenize 的原始观测被 ScanOutbound 命中阻断（R7） | 机制 |
| C1 | tcpdump pcap 中模型侧流量零真实 IP | 抓包 |
| C2 | pcap / mock 落盘请求体中 token 存在（流量真实发出） | 抓包 |

## 首次执行记录

2026-10-25，NAS（10.40.23.191）aleth-stability 容器内，靶场
10.40.23.191:3000（Juice Shop，镜像经 docker.1panel.live 拉取）。
六项断言全过：A1 ✓ / A2 ✓（3/3 tokens，类别 IP_PRIVATE）/ B1 ✓ /
B2 ✓（hits=3）/ C1 ✓（pcap 18270B 中真实 IP 0 命中）/ C2 ✓（token
命中，mock 落盘请求体 7463B 真实 IP 0 命中）。nmap 观测 7001 bytes。
证据 pcap 与请求体留档于执行机本地（不入库 —— 含 token 映射语义）。
