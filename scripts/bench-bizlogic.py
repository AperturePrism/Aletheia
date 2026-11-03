#!/usr/bin/env python3
"""在真实靶场上跑业务逻辑检测基准（`docs/04` §P2 的"首个可复现数字"）。

# 为什么 CLI 在 scripts/ 而不是在 agents/ 里

`scripts/check-no-bypass.sh` 的 R6 规则禁止 `agents/` 下出现
`sys.exit` / `raise SystemExit` —— 因为 **agent 代码不得自行终止会话**
（`docs/09` §R6）。

而"跑一次基准并按退出码报告"是脚本的职责，不是 agent 的职责。
因此本文件的定位与仓库既有的 `scripts/extract-release-notes.py` 一致：
**库在 agents/，CLI 在 scripts/**。这样既不削弱门禁规则
（`docs/09` §R2 禁止为了让检查变绿而删规则），也不把 agent 库
写成一个会杀进程的东西。

# 用法

    # 1) 起靶场（docker 在 WSL2 内）
    wsl -d Arch -- bash scripts/labs-up.sh bizlogic

    # 2) 跑基准
    PYTHONPATH=agents/src .venv/Scripts/python.exe scripts/bench-bizlogic.py \
        --base http://127.0.0.1:8080 --out labs/bizlogic/last_run.json

# 退出码

* 0 = 基准跑完（**不代表"检出率达标"** —— 本命令是测量工具，不是门禁）；
* 2 = 靶场不可达（此时**不应**把结果当作有效数字）。
"""

from __future__ import annotations

import sys
from pathlib import Path

# 让脚本在未设置 PYTHONPATH 时也能直接运行（仓库内相对定位）。
_SRC = Path(__file__).resolve().parents[1] / "agents" / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aletheia.intent.live_bench import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
