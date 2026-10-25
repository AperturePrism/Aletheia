# G-4 端到端验证（独立复现 · T4.9）

真源判据：`docs/modules/M4` §4.2 + `docs/04` §I7 DoD ——「G-4 独立复现
可运行，单次复现 < 10 min」。

## 为什么不在 CI 里跑

验证对象是**真实部署形态**（容器内常驻 focalplane 的 gRPC 全链路 +
跨进程 SQLite 可见性）—— CI 单测覆盖同进程逻辑；跨进程提交可见性
恰恰是 NAS 首次真实验证暴露的缺陷（transition 不自提交被同连接可见性
掩盖），这类问题只有跨进程环境能暴露。

## 步骤（NAS 或任意 docker 主机）

```bash
# focalplane 以新代码运行后：
docker exec <容器> sh -c 'cd /work && PYTHONPATH=/app/app python /work/g4_verify.py'
```

前置：`/work/probe_key.hex`（Sandbox 签发私钥，与 focalplane 公钥同对）、
`/work/ledger.db`。

## 断言清单

| # | 断言 |
|---|---|
| 1 | 证据经 G-1 验签路径入账 |
| 2 | ID_OUTPUT 强观测被接受（id_root + id_generic 逗号多模式命中路径） |
| 3 | 断言经 G-1/G-2/G-3 到达 CANDIDATE |
| 4 | 环境哈希不匹配的复现请求被 fail-closed 拒绝 |
| 5 | 正确 ReproSpec 复现成功（副作用模式再命中），耗时 < 10min |
| 6 | reproduction_exec_id 签发（repro_ 前缀） |
| 7 | finding 跨进程可见地跃迁 CANDIDATE→CONFIRMED（唯一入口） |

## 首次执行记录（2026-10-25，NAS aleth-stability 容器）

七项断言全过；复现耗时 0.07s。诚实边界：验证的是执行器机制在真实部署
可运行（DoD 的「可运行」），步骤用 echo 还原观测文本；真实漏洞重放
待 Sandbox 装配（P1，见 DEC 文档登记）。
