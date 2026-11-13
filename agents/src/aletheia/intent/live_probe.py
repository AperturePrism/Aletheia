"""真实 HTTP 探测器 —— 把 I10 的检测从"模拟探测轮次"变成真实数字。

# 这个模块补的是什么

2026-11-02 的项目检查指出：I10 的 100% 检出率来自**模拟探测轮次**
（`lab.py` 的 `Lab` 是内存对象），`docs` 也明确写着"真实数字待执行侧"。

`docs/04` §P2 门禁要求「业务逻辑首个可复现数字」。没有真实靶场上的
真实探测，那条门禁无法通过 —— 无论模拟数字多漂亮。

本模块对**真实运行的目标**发起真实请求，逐类判定 BL1–BL6，
并把结果交给 `lab.evaluate_detection` 产出 TP / 漏报 / 误报。

# ★ 证据等级的诚实声明（最重要的一段）

本模块的探测**不是**经 Sandbox 签发的执行。因此：

* `ProbeResult.exec_id` 由本模块生成，格式为 `localprobe:<sha256前16位>` ——
  它是"请求/响应内容"的确定性指纹，用于**复现与对账**；
* 它**不是** `05` 意义上的签名 `exec_id`，**不能**作为红线级（Q3）证据，
  也**不能**据此宣称"已确认漏洞"。它只能支撑"靶场基准的可复现分数"。

这条区分必须写进任何引用本模块数字的报告，否则就是把
"本地探测到的现象"包装成"经证据链确认的结论" —— 那是本项目第一原则
（结论必须由证据显现）明令禁止的事。

# 为什么判定要基于"数据是否真的返回/变更"

`violations.judge` 的强证据门禁要求 `data_returned=True`。因此每个
探测器都不看状态码，而看**响应体里是否真的出现了受保护的数据**、
或**服务端状态是否真的变成了不该变的样子**。

例（BL1）：`GET /api/orders/200` 返回 200 不算证据 —— 必须响应体里
真的包含 bob 的订单内容（含 owner 与金额）。只看状态码会把
"401 变成 500"这类无关差异误报成越权。
"""

from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from aletheia.intent.lab import Lab, LabDefect, LabMode
from aletheia.intent.violations import ProbeResult, Violation, ViolationType, judge

#: 端点键（与靶场 ground truth 对齐）。
EP_ORDERS = "GET /api/orders/{id}"
EP_CHECKOUT = "POST /api/checkout"
EP_SHIP = "POST /api/orders/{id}/ship"
EP_COUPON = "POST /api/coupon/redeem"
EP_PROMOTE = "POST /api/admin/users/{id}/promote"
EP_TRANSFER = "POST /api/transfer"


def bizlogic_ground_truth() -> Lab:
    """`labs/bizlogic` 的 ground truth（六类各一个）。

    端点键必须与探测器产出的 `endpoint_key` **逐字符一致**，
    否则 `evaluate_detection` 会把它算成漏报 + 误报（两边都不匹配）。
    这是"靶场基准"最容易出错的地方，因此单独成一个函数，便于测试断言。
    """
    lab = Lab(name="bizlogic")
    lab.add(
        LabDefect(
            defect_id="BL1-order-idor",
            violation_type=ViolationType.BL1_IDOR,
            endpoint_key=EP_ORDERS,
            # BL1 属于纯行为可检：不需要契约也知道"不该读到别人的订单"。
            detectable_in=frozenset({LabMode.WITH_CONTRACT, LabMode.WITHOUT_CONTRACT}),
            description="任意登录用户可读他人订单（无属主校验）",
        )
    )
    lab.add(
        LabDefect(
            defect_id="BL2-client-total",
            violation_type=ViolationType.BL2_TAMPERING,
            endpoint_key=EP_CHECKOUT,
            # BL2 需要"金额应由服务端计算"这一契约知识；无契约模式下
            # 原理上不可检（M8 §4.5 的双模式设计正为体现这类差异）。
            detectable_in=frozenset({LabMode.WITH_CONTRACT}),
            description="服务端采信客户端提交的 total",
        )
    )
    lab.add(
        LabDefect(
            defect_id="BL3-skip-payment",
            violation_type=ViolationType.BL3_FLOW_BYPASS,
            endpoint_key=EP_SHIP,
            detectable_in=frozenset({LabMode.WITH_CONTRACT, LabMode.WITHOUT_CONTRACT}),
            description="CREATED 可直达 SHIPPED（跳过 PAID）",
        )
    )
    lab.add(
        LabDefect(
            defect_id="BL4-quota-reset",
            violation_type=ViolationType.BL4_QUOTA_BYPASS,
            endpoint_key=EP_COUPON,
            detectable_in=frozenset({LabMode.WITH_CONTRACT, LabMode.WITHOUT_CONTRACT}),
            description="配额计数可被 reset 参数重置",
        )
    )
    lab.add(
        LabDefect(
            defect_id="BL5-header-promote",
            violation_type=ViolationType.BL5_PRIVILEGE_CHAIN,
            endpoint_key=EP_PROMOTE,
            detectable_in=frozenset({LabMode.WITH_CONTRACT, LabMode.WITHOUT_CONTRACT}),
            description="普通用户凭伪造 X-Forwarded-Role 头提权",
        )
    )
    lab.add(
        LabDefect(
            defect_id="BL6-double-spend",
            violation_type=ViolationType.BL6_RACE,
            endpoint_key=EP_TRANSFER,
            detectable_in=frozenset({LabMode.WITH_CONTRACT, LabMode.WITHOUT_CONTRACT}),
            description="并发转账可双花（检查与提交之间有窗口）",
        )
    )
    return lab


@dataclass
class HttpProber:
    """对真实目标发起探测。

    `base` 形如 `http://127.0.0.1:8080`。**只应指向本机靶场** ——
    本模块不做范围校验（那是 Scope Kernel 的职责，见 `07` §T7：
    不得有绕过闸门的特权路径）。正因如此，本模块只在评测脚本里用，
    不接入生产执行链。
    """

    base: str
    timeout_s: float = 8.0
    #: 记录每次探测的原始请求/响应摘要（供报告取证）。
    log: list[dict] = field(default_factory=list)

    # ---- 底层 ----
    def _req(
        self,
        method: str,
        path: str,
        *,
        user: str = "",
        body: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        url = f"{self.base.rstrip('/')}{path}"
        data = None
        hdrs = {"Accept": "application/json"}
        if user:
            hdrs["X-Auth-User"] = user
        if headers:
            hdrs.update(headers)
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)  # noqa: S310 —— 只指向本机靶场
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as r:  # noqa: S310
                text = r.read().decode("utf-8", "replace")
                code = r.status
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            code = e.code
        except OSError as e:
            text = f"__transport_error__ {e}"
            code = 0
        self.log.append(
            {"method": method, "path": path, "user": user, "code": code, "body_prefix": text[:400]}
        )
        return code, text

    def _exec_id(self, *parts: str) -> str:
        """内容指纹（**不是**签名 exec_id —— 见模块文档的证据等级声明）。"""
        h = hashlib.sha256()
        for p in parts:
            h.update(p.encode("utf-8", "replace"))
            h.update(b"\x1f")
        return f"localprobe:{h.hexdigest()[:16]}"

    # ---- 六类探测 ----
    def probe_bl1(self) -> ProbeResult:
        """BL1：alice 读 bob 的订单，看**响应体里是否真有** bob 的数据。"""
        code, text = self._req("GET", "/api/orders/200", user="alice")
        leaked = False
        try:
            j = json.loads(text)
            order = j.get("order") or {}
            leaked = order.get("owner") == "bob" and "total" in order
        except (json.JSONDecodeError, AttributeError):
            leaked = False
        return ProbeResult(
            violation_type=ViolationType.BL1_IDOR,
            endpoint_key=EP_ORDERS,
            data_returned=leaked,
            exec_id=self._exec_id("bl1", "alice", str(code), text[:200]),
            details={
                "status": str(code),
                "leaked_owner": "bob" if leaked else "",
                # 说明为何算强证据：不是状态码，而是**他人数据被返回**。
                "evidence": "response contained another user's order fields",
            },
        )

    def probe_bl2(self) -> ProbeResult:
        """BL2：提交 0.01 的 total，看服务端是否照单全收。"""
        code, text = self._req("POST", "/api/checkout", user="alice", body={"total": 0.01})
        accepted = False
        try:
            j = json.loads(text)
            order = j.get("order") or {}
            accepted = float(order.get("total", -1)) == 0.01
        except (json.JSONDecodeError, ValueError, TypeError, AttributeError):
            accepted = False
        return ProbeResult(
            violation_type=ViolationType.BL2_TAMPERING,
            endpoint_key=EP_CHECKOUT,
            data_returned=accepted,
            exec_id=self._exec_id("bl2", str(code), text[:200]),
            details={"status": str(code), "accepted_total": "0.01" if accepted else ""},
        )

    def probe_bl3(self) -> ProbeResult:
        """BL3：对 CREATED 的订单直接 ship，看状态是否被改成 SHIPPED。"""
        code, text = self._req("POST", "/api/orders/100/ship", user="alice", body={})
        bypassed = False
        try:
            j = json.loads(text)
            bypassed = (j.get("order") or {}).get("status") == "SHIPPED"
        except (json.JSONDecodeError, AttributeError):
            bypassed = False
        return ProbeResult(
            violation_type=ViolationType.BL3_FLOW_BYPASS,
            endpoint_key=EP_SHIP,
            data_returned=bypassed,
            exec_id=self._exec_id("bl3", str(code), text[:200]),
            details={"status": str(code), "final_state": "SHIPPED" if bypassed else ""},
        )

    def probe_bl4(self, attempts: int = 4) -> ProbeResult:
        """BL4：带 reset 反复兑换，看是否超过配额还能成功。"""
        successes = 0
        last_code = 0
        for _ in range(attempts):
            last_code, _t = self._req("POST", "/api/coupon/redeem", user="bob", body={"reset": 1})
            if last_code == 200:
                successes += 1
        # 配额为 2；超过 2 次成功即绕过。
        bypassed = successes > 2
        return ProbeResult(
            violation_type=ViolationType.BL4_QUOTA_BYPASS,
            endpoint_key=EP_COUPON,
            data_returned=bypassed,
            exec_id=self._exec_id("bl4", str(successes), str(last_code)),
            details={"successes": str(successes), "attempts": str(attempts)},
        )

    def probe_bl5(self) -> ProbeResult:
        """BL5：普通用户带伪造头提权。"""
        code, text = self._req(
            "POST",
            "/api/admin/users/2/promote",
            user="bob",
            body={},
            headers={"X-Forwarded-Role": "admin"},
        )
        promoted = False
        try:
            j = json.loads(text)
            promoted = j.get("promoted") == "bob"
        except (json.JSONDecodeError, AttributeError):
            promoted = False
        return ProbeResult(
            violation_type=ViolationType.BL5_PRIVILEGE_CHAIN,
            endpoint_key=EP_PROMOTE,
            data_returned=promoted,
            exec_id=self._exec_id("bl5", str(code), text[:200]),
            details={"status": str(code), "promoted": "bob" if promoted else ""},
        )

    def probe_bl6(self, amount: float = 800.0) -> ProbeResult:
        """BL6：并发两笔转账，看余额是否被扣两次（转为负值）。"""
        _c, before_text = self._req("GET", "/api/state", user="alice")
        try:
            before = float(json.loads(before_text)["users"]["bob"]["balance"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            before = float("nan")

        results: list[int] = []
        lock = threading.Lock()

        def one() -> None:
            code, _t = self._req(
                "POST",
                "/api/transfer",
                user="bob",
                body={"to": "alice", "amount": amount},
            )
            with lock:
                results.append(code)

        threads = [threading.Thread(target=one) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        _c2, after_text = self._req("GET", "/api/state", user="alice")
        try:
            after = float(json.loads(after_text)["users"]["bob"]["balance"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            after = float("nan")

        # 双花的判据：余额变为负数（扣了两次而余额不够扣两次）。
        double_spent = after < 0
        return ProbeResult(
            violation_type=ViolationType.BL6_RACE,
            endpoint_key=EP_TRANSFER,
            data_returned=double_spent,
            exec_id=self._exec_id("bl6", str(before), str(after), str(sorted(results))),
            details={
                "balance_before": f"{before:.2f}",
                "balance_after": f"{after:.2f}",
                "codes": ",".join(str(c) for c in results),
            },
        )

    # ---- 全量 ----
    def probe_all(self) -> list[ProbeResult]:
        """跑全部六类。顺序固定（可复现）。"""
        return [
            self.probe_bl1(),
            self.probe_bl2(),
            self.probe_bl3(),
            self.probe_bl4(),
            self.probe_bl5(),
            self.probe_bl6(),
        ]


def violations_from(results: list[ProbeResult]) -> list[Violation]:
    """把探测结果过**强证据门禁**转为违背列表。"""
    out: list[Violation] = []
    for r in results:
        v = judge(r, rationale=f"live probe on {r.endpoint_key}")
        if v is not None:
            out.append(v)
    return out
