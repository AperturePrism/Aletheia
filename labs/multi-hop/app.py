#!/usr/bin/env python3
"""multi-hop 靶场 —— 两个容器的真实网络分段（第二跳只在内部可达）。

# 它测什么

`04` §P2 与 `07` §T5 要求系统能处理**多跳**目标：外网只见入口，真正的
资产在内网。多数扫描能力在"两次请求组合"式的发现上会失效 ——
本靶场把这件事做成可复现的判定：

    host ──► front:8080 ──► internal:9000
             (唯一发布端口)   (不发布，宿主直连不到)

因此：
* 宿主直连 `internal:9000` **必然失败**（这是靶场的核心不变量）；
* 宿主只能通过 `front` 的 `/proxy?path=/secret` 才能触达内部服务 ——
  这就是"第二跳"。

# 为什么用服务端代理而不是"两个都发布端口"

若两个端口都发布到宿主，"多跳"就退化成"两个独立目标"，测不出任何
跨跳推理能力。内网服务**必须**在宿主侧不可达，这条不变量由
`verify.sh` 断言。

# 安全边界

* `front` 的代理**只**允许访问本靶场内部服务（硬编码 host 白名单），
  不是通用 SSRF 转发器 —— 否则它就成了一个可被用来打外网的跳板
  （`07` §T8：靶场自身不得成为出网通道）。
* 两个服务都不出网（容器出站在本机环境本就阻断，且本应用不发外部请求）。
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

#: 内部服务地址（仅容器网络内可达）。
INTERNAL_URL = os.environ.get("INTERNAL_URL", "http://internal:9000")

#: 允许代理的路径白名单 —— 刻意收窄，避免变成通用转发器。
ALLOWED_PATHS = {"/secret", "/healthz"}


class FrontHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[multi-hop/front] {self.address_string()} {fmt % args}", flush=True)

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        if path == "/health":
            self._json(200, {"status": "ok", "role": "front"})
            return

        if path == "/":
            self._json(
                200,
                {
                    "service": "multi-hop-lab/front",
                    "note": "internal service is NOT reachable from the host; use /proxy",
                    "proxy": "GET /proxy?path=/secret",
                },
            )
            return

        if path == "/proxy":
            m = re.search(r"path=([^&]+)", self.path)
            target_path = m.group(1) if m else ""
            if target_path not in ALLOWED_PATHS:
                self._json(
                    400,
                    {"error": "path not allowed", "allowed": sorted(ALLOWED_PATHS)},
                )
                return
            # ★ 第二跳：从这里请求内部服务。
            try:
                with urllib.request.urlopen(  # noqa: S310 —— 目标固定为内网白名单
                    f"{INTERNAL_URL}{target_path}", timeout=5
                ) as r:
                    payload = json.loads(r.read().decode("utf-8", "replace"))
            except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
                self._json(502, {"error": f"internal unreachable: {type(exc).__name__}"})
                return
            self._json(200, {"second_hop": True, "internal_response": payload})
            return

        self._json(404, {"error": "no such endpoint"})


class InternalHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[multi-hop/internal] {self.address_string()} {fmt % args}", flush=True)

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path == "/healthz":
            self._json(200, {"status": "ok", "role": "internal"})
            return
        if path == "/secret":
            # 这就是"只有第二跳才拿得到"的资产。
            self._json(
                200,
                {
                    "flag": "MULTIHOP-6c1f9a",
                    "internal_only": True,
                    "note": "reachable only from the container network",
                },
            )
            return
        self._json(404, {"error": "no such endpoint"})


def main() -> None:
    role = os.environ.get("ROLE", "front")
    if role == "internal":
        srv = ThreadingHTTPServer(("0.0.0.0", 9000), InternalHandler)  # noqa: S104
        print("[multi-hop/internal] listening on 0.0.0.0:9000", flush=True)
    else:
        srv = ThreadingHTTPServer(("0.0.0.0", 8080), FrontHandler)  # noqa: S104
        print("[multi-hop/front] listening on 0.0.0.0:8080", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
