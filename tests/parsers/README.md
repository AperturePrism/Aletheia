# 解析器边界用例与 fixtures

交付迭代：**I1**
docs/04 §I1 DoD①：解析器测试覆盖率 ≥ 90%，含边界用例（nmap 版本串前导数字守卫、ANSI 转义、schema 参数名变体）

## 目录结构

```
fixtures/
├── nmap/    v7.94-basic.xml（多 host/端口、rpc 程序号陷阱）
│            v7.94-ansi.xml（TTY 着色污染，@ESC@ 占位符 = 单个 ESC 字节 0x1B）
├── httpx/   v1.6.0-basic.jsonl（有效行 / failed 行 / 缺 method 行 / ESC 污染 / 坏行）
└── nuclei/  v3.2.7-basic.jsonl（matched / unmatched / 截断行）
```

约定（modules/M1 §6）：

- 样本标注来源工具版本；文件名即版本号。
- **禁止包含真实目标信息** —— 全部使用 RFC 5737 文档网段（192.0.2.0/24）
  与 `.test` 保留域。
- fixtures 是唯一真源：Go 测试经 `core/ingest/testutil.Fixture` 加载，
  包内不复制样本。
- `@ESC@` 占位符在测试加载时替换为单个 ESC 字节（0x1B），
  用于模拟 TTY 输出污染（XML 1.0 禁止原始 ESC，因此必须是占位符形态）。

## 覆盖率门禁

`bash scripts/coverage-go.sh 90`（`make coverage` 内含）：
统计 `core/ingest/**` 与 `core/spectrum/**`（排除 testutil），阈值 90%。
