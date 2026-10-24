"""R9 守护：三个核心视图不得被省略（docs/09 §R9）。

# 为什么需要这个测试

`docs/09` R9 是十条红线之一：

> **不得省略三个核心视图**
>
> | 视图 | 为什么不可省 |
> |---|---|
> | 证据链视图 | 用户验证"系统是否在幻觉"的唯一界面 |
> | 光圈上下文视图 | 诊断"系统是不是漏看了什么"的唯一界面 |
> | 冲突矩阵视图 | "打不通但有缺陷"这个最高价值象限的唯一呈现方式 |
>
> **允许简化视觉细节（配色、动画、布局精修），不允许省略功能与信息密度。**
>
> **为什么：** `06` §2.3 论证过 —— 如果这三个能力用户感知不到，
> 项目会退化成普通 CLI 渗透 agent，而那个赛道已有 PentestGPT、Strix
> 等成熟产品。

# 在这之前，R9 **没有机械化守护**

`scripts/check-no-bypass.sh` 覆盖 R4–R8，但 R9 只出现在注释与 ★ 图标里 ——
没有任何检查会因"某人删掉一个核心视图"而失败。

这正是 `docs/10` §0 点名的模式：**用"绿灯"替换"有效性"** ——
测试全绿、门禁全过，而红线其实可以被无声地破坏。

本测试把 R9 变成可执行的断言：

1. 三个核心视图的路由必须存在且指向真实组件（不是占位）；
2. 导航里必须恰好有 3 个 `core: true` 标记；
3. 被标记的必须正好是那三个视图（不是别的页面被顺手标了 ★）。

第 3 条很关键：若只断言"有 3 个 ★"，把别的页面标上 ★ 也能过 ——
那会让红线变成形式。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MAIN_TSX = REPO / "web" / "src" / "main.tsx"
LAYOUT_TSX = REPO / "web" / "src" / "components" / "AppLayout.tsx"

#: 红线标记：不可抽样、不可跳过（`docs/10` §3 P2）。
#:
#: 用与 `tests/redline/` 相同的 marker，因此 `make redline` 与 CI 的
#: redline job（`pytest tests/ -q -m redline`）都会收集本文件 ——
#: 无需改 CI 配置，也不会因"忘记登记"而让守护失效。
pytestmark = pytest.mark.redline

#: 三个核心视图（`docs/09` R9 表格的三行）。
#:
#: 键 = 路由路径（`main.tsx` 的 `path:`），值 = 该视图承载的能力。
#: 路由路径是稳定的锚点；组件文件名会随重构变化，因此不锚定文件名。
CORE_VIEWS: dict[str, str] = {
    "evidence": "证据链视图 —— 验证系统是否在幻觉",
    "aperture": "光圈上下文视图 —— 诊断系统是否漏看了什么",
    "conflicts": "冲突矩阵视图 —— 呈现「打不通但有缺陷」象限",
}


def main_tsx_text() -> str:
    return MAIN_TSX.read_text(encoding="utf-8")


def layout_tsx_text() -> str:
    return LAYOUT_TSX.read_text(encoding="utf-8")


def test_web_sources_exist() -> None:
    """前置：源文件存在（否则后面的断言会因"文件不存在"而假通过）。"""
    assert MAIN_TSX.is_file(), f"missing {MAIN_TSX}"
    assert LAYOUT_TSX.is_file(), f"missing {LAYOUT_TSX}"


@pytest.mark.parametrize(("route", "purpose"), sorted(CORE_VIEWS.items()))
def test_core_view_route_exists(route: str, purpose: str) -> None:
    """R9：每个核心视图必须有路由，且指向**真实组件**。"""
    text = main_tsx_text()
    pattern = re.compile(r'\{\s*path:\s*"' + re.escape(route) + r'[^"]*"\s*,\s*element:\s*<(\w+)')
    m = pattern.search(text)
    assert m, (
        f"核心视图路由 {route!r} 不存在 —— {purpose}。\n"
        "docs/09 R9：三个核心视图不得省略（允许简化视觉，不允许省略功能）。"
    )
    component = m.group(1)
    assert component != "NotImplementedPage", (
        f"核心视图 {route!r} 指向占位组件 NotImplementedPage —— {purpose}。\n"
        "R9 要求「不允许省略功能与信息密度」，占位页等价于省略。"
    )


def test_exactly_three_core_views_are_marked() -> None:
    """R9：导航里必须**恰好**有 3 个核心视图标记。

    形态（`AppLayout.tsx` 的 JSX）：
        <NavItem to="/aperture" label="光圈上下文视图" core iteration="I5" ... />

    注意 `core` 是 **JSX 的裸属性**（等价于 `core={true}`），不是 `core: true`
    —— 后者是对象字面量形态。测试必须匹配真实形态，否则会误判为"没有标记"。

    少于 3 = 省略了某个核心视图；多于 3 = ★ 标记失去区分度。
    """
    text = layout_tsx_text()
    marked = parse_core_nav_routes(text)
    assert len(marked) == 3, (
        f"导航中核心视图标记有 {len(marked)} 个（{sorted(marked)}），应为 3 个。\n"
        "docs/09 R9 的表格恰好列了三个核心视图。"
    )


def test_core_marks_are_on_the_right_views() -> None:
    """★ R9 的关键断言：被标记的必须**正好是**那三个视图。

    若只断言"有 3 个标记"，把别的页面标上也能通过 —— 那会让红线变成形式。
    因此这里逐个核对：被标记的路由集合必须等于 R9 表格里的三个。
    """
    marked = parse_core_nav_routes(layout_tsx_text())
    expected = set(CORE_VIEWS)
    assert marked == expected, (
        f"被标记的视图是 {sorted(marked)}，应为 {sorted(expected)}。\n"
        "R9 只把那三个视图列为不可省 —— 标错位置会让红线失去意义。"
    )


def parse_core_nav_routes(text: str) -> set[str]:
    """解析导航中带核心视图标记的路由（顶层路径段）。

    支持两种等价形态（视觉重构引入了数据驱动的导航数组，语义不变）：
      1. JSX 裸属性：`<NavItem ... to="/x" ... core ... />`
      2. 对象字面量：`{ to: "/x", ..., core: true }`
    两者都表示"该导航项被标记为核心视图"。用**行级**解析而不是
    跨行正则 —— 每个导航项占一行，行级解析不易被括号干扰。
    """
    out: set[str] = set()
    for line in text.splitlines():
        m = re.search(r'to:\s*"(/?)([^/" ]+)"', line) or re.search(r'to="/([^/"]+)', line)
        if not m:
            continue
        route = m.group(2)
        # 形态 1：core 作为 JSX 独立属性（前后是空白或行尾），
        # 避免把 `coreView` / `core={false}` 误判为标记。
        if re.search(r"(?<![\w{])core(?![\w=])", line):
            out.add(route)
            continue
        # 形态 2：对象字面量里的 `core: true`（core: false 不算标记）。
        if re.search(r"(?<![\w])core:\s*true(?![\w])", line):
            out.add(route)
    return out


def test_core_views_are_not_mock_pages() -> None:
    """R9 的"不允许省略功能"：核心视图不得渲染硬编码示例数据。

    这与仓库既有的"禁止 mock 掩盖契约不一致"一致（`docs/09` §6 #4）——
    一个只有假数据的核心视图在功能上等价于省略。
    """
    text = main_tsx_text()
    for route in CORE_VIEWS:
        m = re.search(
            r'\{\s*path:\s*"' + re.escape(route) + r'[^"]*"\s*,\s*element:\s*<(\w+)',
            text,
        )
        assert m, f"route {route} missing"
        component = m.group(1)
        # 找到该组件的定义文件。
        candidates = list((REPO / "web" / "src").rglob(f"{component}.tsx"))
        assert candidates, f"component {component} for route {route} not found"
        body = candidates[0].read_text(encoding="utf-8")
        for banned in ("MOCK_", "SAMPLE_", "FAKE_", "mockData", "sampleData"):
            assert banned not in body, (
                f"核心视图 {component}（路由 {route}）出现 {banned} —— "
                "R9 不允许省略功能，假数据在功能上等价于省略。"
            )


def test_r9_is_documented_where_it_is_enforced() -> None:
    """守护测试自身要能被追溯：R9 的出处必须写在文档里。

    这是元断言 —— 若有人从 `docs/09` 删掉 R9，本测试会失败，
    从而暴露"守护的是一个已不存在的规则"。
    """
    handoff = (REPO / "docs" / "09-开发交接说明-致ClaudeCode.md").read_text(encoding="utf-8")
    assert "R9" in handoff, "docs/09 必须保留 R9（本测试守护的规则）"
    assert "不得省略三个核心视图" in handoff, "docs/09 的 R9 标题被改动"
    for purpose in ("证据链", "光圈上下文", "冲突矩阵"):
        assert purpose in handoff, f"docs/09 的 R9 表格缺少 {purpose}"
