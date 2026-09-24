"""Aletheia —— L1–L4 的 Python 实现。

命名依据 docs/03-项目命名方案：项目名 **Aletheia**（古希腊语 ἀλήθεια，
"去蔽"），短形式 `aleth`。

分层（docs/02 §3）：
    L0 摄入   → Go（core/ingest）
    L1 棱镜   → 本包（agents/.../prism）
    L2 光圈   → 本包（agents/.../aperture）
    L3 焦平面 → 本包（agents/.../focalplane）
    L4 编排   → 本包（agents/.../orchestration）
    横切层    → Go（core/）

I0 的范围：只有一个可导入的包与版本号。子模块在对应迭代加入，
不预先创建空目录 —— 空包会让 `git status` 噪音化，
也让"哪些能力已交付"变得难以判断（`10` §3 P7 范围蔓延的检查点）。
"""

__version__ = "0.1.0"
