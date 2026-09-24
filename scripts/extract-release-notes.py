#!/usr/bin/env python3
"""从 docs/CHANGELOG.md 提取指定版本的 Release Notes。

Release 工作流用本脚本生成 Release Notes 的正文。
依据 docs/09 §10 第 8 项（每迭代必须写 CHANGELOG 条目）与
docs/README §3 铁律（任何事实只写在一个地方）：
    Release Notes 不另手写一份，而是从 CHANGELOG 提取 ——
    手写会让同一事实存在两处，两者终将不一致。

匹配规则（按优先级）：
    1. `## [X.Y.Z]`     —— 精确版本段（正式发布）
    2. `## [X.Y]`       —— minor 段（Keep a Changelog 允许省略 patch）
    3. `## [Unreleased]`—— 未发布段（版本段尚未建立时的兜底）

提取范围：锚点行之后，到下一个 `## [` 行之前（不含锚点本身）。

用法：
    extract-release-notes.py <version> <changelog-path> [output-path]

    version       形如 0.1.0（不带 v 前缀）或 v0.1.0
    changelog     docs/CHANGELOG.md
    output        省略时写到 stdout

退出码：
    0  成功（含提取到空内容 —— 那本身是有效结果，调用方决定如何处置）
    1  用法错误 / 文件不存在
    2  CHANGELOG 中找不到对应段落（调用方应据此告警而非发布空 Notes）
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# 章节锚点：`## [x]` 或 `## [x](link)`。Keep a Changelog 允许带链接。
SECTION_RE = re.compile(r"^##\s+\[([^\]]+)\]")


def extract(text: str, version: str) -> tuple[str, str] | None:
    """提取 version 对应的段落。

    返回 (段落内容, 实际命中的锚点名)；找不到返回 None。
    """
    # 规范化：去掉可能带的 v 前缀。
    v = version.lstrip("v").strip()
    if not v:
        return None

    lines = text.splitlines()

    # 候选锚点，按优先级。
    candidates = [v]
    # 补 minor 形式：0.1.0 → 0.1
    parts = v.split(".")
    if len(parts) >= 2:
        candidates.append(f"{parts[0]}.{parts[1]}")
    candidates.append("Unreleased")

    for want in candidates:
        start = None
        for i, line in enumerate(lines):
            m = SECTION_RE.match(line)
            if m and m.group(1).strip() == want:
                start = i
                break
        if start is None:
            continue

        # 从锚点下一行收集到下一个 `## [` 之前。
        body: list[str] = []
        for line in lines[start + 1 :]:
            if re.match(r"^##\s+\[", line):
                break
            body.append(line)

        # 去掉首尾空行，让输出干净。
        while body and not body[0].strip():
            body.pop(0)
        while body and not body[-1].strip():
            body.pop()

        return "\n".join(body), want

    return None


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 1

    version = sys.argv[1]
    changelog_path = Path(sys.argv[2])
    output_path = Path(sys.argv[3]) if len(sys.argv) > 3 else None

    if not changelog_path.exists():
        print(f"error: CHANGELOG not found: {changelog_path}", file=sys.stderr)
        return 1

    text = changelog_path.read_text(encoding="utf-8")
    result = extract(text, version)

    if result is None:
        # 这是需要调用方注意的情况：CHANGELOG 缺段落。
        # 不静默返回空 —— 那会让 Release 带上空 Notes 而没人发现
        # （docs/10 §0「绿灯替代有效」的同类问题）。
        print(
            f"error: no section for version '{version}' in {changelog_path}; "
            f"looked for [{version.lstrip('v')}], its minor form, and [Unreleased]. "
            f"docs/09 §10 item 8 requires a CHANGELOG entry per iteration.",
            file=sys.stderr,
        )
        return 2

    body, anchor = result

    if not body:
        # 段落存在但为空：仍然算成功，但提示调用方。
        print(f"warning: section [{anchor}] exists but is empty", file=sys.stderr)

    if output_path is not None:
        output_path.write_text(body + "\n", encoding="utf-8")
        print(f"wrote {len(body)} chars to {output_path} (section [{anchor}])", file=sys.stderr)
    else:
        sys.stdout.write(body + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
