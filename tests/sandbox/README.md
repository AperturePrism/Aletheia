# IngestService.Execute 全链 e2e（Sandbox 装配后）

链路（全部真实组件）：Scope 校验（真实 Kernel + roe）→ 参数 Tokenize
→ 版本门禁 → **ProcessSandbox 真实执行 nmap** → 输出 Tokenize →
ScanOutbound（tokenized 后扫描）→ 解析 → Spectrum（真实实体）→
PrismService.Ingest 进图 → Project 验证。

## 关键回归点（I3 行为缺陷修正）

nmap 真实输出含私网 IP（靶场地址）—— 修正前对原始 stdout 直接
ScanOutbound → 真实扫描 100% 被 PRIVACY_LEAK_DETECTED 阻断；
修正后先 TokenizeOutput 再扫描 → 放行，且 Spectrum 保留真实值
（图谱/账本消费真实值；模型侧脱敏在 M3 装配与 M6 出站）。

## 步骤（NAS 靶场）

前置：alethd 以含靶场地址的 roe 启动；容器内 nmap；Juice Shop :3000。

```bash
docker exec <容器> sh -c 'cd /work && PYTHONPATH=/app/app python /work/sandbox_e2e.py'
```

## 首次执行记录（2026-10-25，NAS）

六项断言全过：Execute 成功、exec_ 前缀签发、ASSET/SERVICE 真实草稿、
观测折叠、进图 created=1、图谱可见。这是 I0 以来 Execute 的首次真实
全链运行（此前 Sandbox 未装配，显式 UPSTREAM_UNAVAILABLE）。
