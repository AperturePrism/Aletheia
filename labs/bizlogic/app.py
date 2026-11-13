#!/usr/bin/env python3
"""bizlogic 靶场 —— 故意包含六类业务逻辑缺陷的最小服务。

# 这是什么

`labs/bizlogic/` 是 `docs/04` §P2 门禁要求的「业务逻辑首个可复现数字」的
被测目标。它是一个**故意不安全**的订单/账户服务，六类缺陷与
`agents/src/aletheia/intent/violations.py` 的 `ViolationType` 一一对应：

    BL1_IDOR            GET  /api/orders/<id>           任何登录用户可读他人订单
    BL2_TAMPERING       POST /api/checkout              金额取客户端提交的 total
    BL3_FLOW_BYPASS     POST /api/orders/<id>/ship      允许 CREATED 直接 SHIP（跳过 PAID）
    BL4_QUOTA_BYPASS    POST /api/coupon/redeem         配额计数可重置/绕过
    BL5_PRIVILEGE_CHAIN POST /api/admin/users/<id>/promote  普通用户凭伪造头即可提权
    BL6_RACE            POST /api/transfer               读-改-写无锁 → 并发双花

# 安全边界（为什么它只该跑在隔离容器里）

本文件**故意**包含真实可利用的缺陷，包括可提权与可双花。它只能运行在
`labs/bizlogic/compose.yml` 定义的容器里，且该容器：
  · 端口只绑 127.0.0.1（07 §T5.1 / Q13）
  · 不挂载宿主凭据（07 §T3）
  · 镜像按 digest 固定（07 §T6）

**不要**把它部署到任何可被非本机访问的地方。

# 内置账号（供探测器使用）

    alice / user    （订单 100 的属主）
    bob   / user    （订单 200 的属主）
    admin / admin

认证方式故意做得极简：请求头 `X-Auth-User: <username>`。
理由：本靶场要测的是**业务逻辑**缺陷，不是认证机制；把认证做复杂只会
让"检出率"混入无关变量。这一点在报告里必须说明（否则数字不可解释）。

# 为什么用标准库而没有第三方依赖

靶场要能离线构建、镜像固定后永不变化。引第三方包会让"复现同一分数"
依赖于 PyPI 当时的版本。
"""

from __future__ import annotations

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# 内存状态（每次容器重建即重置 —— 对应 M9 §8 的状态重置要求）
# ---------------------------------------------------------------------------

LOCK = threading.Lock()

USERS: dict[str, dict] = {
    "alice": {"id": 1, "role": "user", "balance": 1000.0},
    "bob": {"id": 2, "role": "user", "balance": 1000.0},
    "admin": {"id": 3, "role": "admin", "balance": 5000.0},
}

#: 订单：属主、金额、状态机（CREATED → PAID → SHIPPED）
ORDERS: dict[int, dict] = {
    100: {"id": 100, "owner": "alice", "total": 100.0, "status": "CREATED"},
    200: {"id": 200, "owner": "bob", "total": 50.0, "status": "PAID"},
}

#: 优惠券：每人配额 2 次
COUPON = {"code": "SAVE10", "quota_per_user": 2}
COUPON_USED: dict[str, int] = {}

#: 订单自增 id
NEXT_ORDER_ID = [300]


def _balance_snapshot(user: str) -> float:
    """BL6 的读侧：读取余额（**不持锁**，检查与提交之间存在窗口）。"""
    return USERS[user]["balance"]


def _commit_transfer(frm: str, to: str, amount: float) -> None:
    """提交转账（BL6 的写侧）。

    刻意**不**在检查与提交之间持锁 —— 这正是可被双花的地方。
    """
    USERS[frm]["balance"] -= amount
    USERS[to]["balance"] += amount


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # ---- 基础设施 ----
    def log_message(self, fmt: str, *args) -> None:
        # 把访问日志写到 stderr（docker logs 可见），便于取证。
        print(f"[bizlogic] {self.address_string()} {fmt % args}", flush=True)

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _user(self) -> str | None:
        u = self.headers.get("X-Auth-User", "").strip()
        return u if u in USERS else None

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0:
                return {}
            raw = self.rfile.read(n)
            data = json.loads(raw or b"{}")
            return data if isinstance(data, dict) else {}
        except (ValueError, json.JSONDecodeError):
            return {}

    # ---- 路由 ----
    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path == "/health":
            self._json(200, {"status": "ok"})
            return

        if path == "/":
            # 目录页：让扫描器/审阅者能发现全部端点（不做隐藏式安全）。
            self._json(
                200,
                {
                    "service": "bizlogic-lab",
                    "note": "intentionally vulnerable business-logic target",
                    "endpoints": [
                        "GET  /api/orders/<id>",
                        "POST /api/checkout",
                        "POST /api/orders/<id>/ship",
                        "POST /api/coupon/redeem",
                        "POST /api/admin/users/<id>/promote",
                        "POST /api/transfer",
                    ],
                },
            )
            return

        m = re.fullmatch(r"/api/orders/(\d+)", path)
        if m:
            user = self._user()
            if user is None:
                self._json(401, {"error": "unauthenticated"})
                return
            oid = int(m.group(1))
            order = ORDERS.get(oid)
            if order is None:
                self._json(404, {"error": "not found"})
                return
            # ★ BL1（IDOR）：不校验 order["owner"] == user。
            self._json(200, {"order": order, "requested_by": user})
            return

        if path == "/api/state":
            # 观测端点：报告用它取证（不是漏洞，但必须存在才能算"可复现"）。
            self._json(200, {"users": USERS, "orders": ORDERS, "coupon_used": COUPON_USED})
            return

        self._json(404, {"error": "no such endpoint"})

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        user = self._user()

        if path == "/api/checkout":
            if user is None:
                self._json(401, {"error": "unauthenticated"})
                return
            data = self._body()
            # ★ BL2（价格篡改）：直接用客户端给的 total 建单。
            total = data.get("total")
            if not isinstance(total, (int, float)):
                self._json(400, {"error": "total required"})
                return
            with LOCK:
                oid = NEXT_ORDER_ID[0]
                NEXT_ORDER_ID[0] += 1
                ORDERS[oid] = {
                    "id": oid,
                    "owner": user,
                    "total": float(total),
                    "status": "CREATED",
                }
            self._json(201, {"order": ORDERS[oid], "accepted_client_total": True})
            return

        m = re.fullmatch(r"/api/orders/(\d+)/ship", path)
        if m:
            if user is None:
                self._json(401, {"error": "unauthenticated"})
                return
            oid = int(m.group(1))
            order = ORDERS.get(oid)
            if order is None:
                self._json(404, {"error": "not found"})
                return
            # ★ BL3（流程绕过）：不要求 status == "PAID" 即可 SHIP。
            order["status"] = "SHIPPED"
            self._json(200, {"order": order, "skipped_payment_state": True})
            return

        if path == "/api/coupon/redeem":
            if user is None:
                self._json(401, {"error": "unauthenticated"})
                return
            # ★ BL4（配额绕过）：每次请求都按"当前已用"重算，但允许带
            # `reset=1` 把计数清零 —— 等价于配额可被无限重置。
            data = self._body()
            if data.get("reset") in (1, "1", True):
                COUPON_USED[user] = 0
            used = COUPON_USED.get(user, 0)
            # 配额判断用的是"重置后的 used"，因此 reset 后永远通过。
            if used >= COUPON["quota_per_user"]:
                self._json(429, {"error": "quota exceeded", "used": used})
                return
            COUPON_USED[user] = used + 1
            self._json(200, {"redeemed": True, "used": COUPON_USED[user]})
            return

        m = re.fullmatch(r"/api/admin/users/(\d+)/promote", path)
        if m:
            if user is None:
                self._json(401, {"error": "unauthenticated"})
                return
            # ★ BL5（权限提升链）：信任客户端提交的角色头，而非服务端会话角色。
            claimed = self.headers.get("X-Forwarded-Role", "")
            if claimed != "admin":
                self._json(403, {"error": "admin required"})
                return
            uid = int(m.group(1))
            for name, u in USERS.items():
                if u["id"] == uid:
                    u["role"] = "admin"
                    self._json(200, {"promoted": name, "by": user, "trusted_header": True})
                    return
            self._json(404, {"error": "no such user"})
            return

        if path == "/api/transfer":
            if user is None:
                self._json(401, {"error": "unauthenticated"})
                return
            data = self._body()
            to = data.get("to")
            amount = data.get("amount")
            if to not in USERS or not isinstance(amount, (int, float)):
                self._json(400, {"error": "to/amount required"})
                return
            # ★ BL6（TOCTOU）：检查与提交之间存在窗口，且不持锁 ——
            # 并发请求可观察到同一份余额（双花）。
            if _balance_snapshot(user) < float(amount):
                self._json(400, {"error": "insufficient balance"})
                return
            # 人为制造窗口：让并发请求都能通过上面的检查。
            time.sleep(0.05)
            with LOCK:
                _commit_transfer(user, to, float(amount))
            self._json(200, {"ok": True, "from": user, "to": to, "amount": float(amount)})
            return

        self._json(404, {"error": "no such endpoint"})


def main() -> None:
    srv = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)  # noqa: S104 —— 容器内监听，宿主侧限 127.0.0.1
    print("[bizlogic] listening on 0.0.0.0:8080", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
