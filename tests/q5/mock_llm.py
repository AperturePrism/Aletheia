"""Q5 明文 mock LLM 端点（仅回环 18888）。

落盘每个请求体到 /work/q5_llm_request.json —— 与 tcpdump pcap
共同构成"模型侧流量"的双重证据。
"""

import json
import pathlib
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n)
        pathlib.Path("/work/q5_llm_request.json").write_bytes(body)
        resp = json.dumps(
            {
                "choices": [{"message": {"content": "ack"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 1, "total_tokens": 11},
            }
        ).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 18888), Handler).serve_forever()
