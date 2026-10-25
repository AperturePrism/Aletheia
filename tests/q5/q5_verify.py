"""Q5 端到端验证：Juice Shop 靶场 + 全程 Gateway + 模型侧出站零真实值。

链路（全部真实调用，零 mock 数据流）：
  1. 容器内真实 nmap 扫 Juice Shop（10.40.23.191:3000）→ 真实观测输出
  2. GatewayService.Tokenize（gRPC 7724）→ 模型侧内容
  3. 断言 A（机制）：tokenized 中零靶场真实 IP / 域名，token 存在
  4. Provider.chat(prompt=tokenized, scan=Gateway.ScanOutbound) → mock LLM
     （明文 HTTP 回环，tcpdump 同步抓包）
  5. 断言 B（反面）：未经 Tokenize 的原始 nmap 输出必须被 ScanOutbound
     命中并阻断（R7 出站扫描真实拦截）
  6. 断言 C（抓包）：tcpdump pcap 中模型侧流量零真实值

退出码 0 = 全部断言通过。
"""

from __future__ import annotations

import subprocess
import sys

import grpc

from aletheia.gen.aleth.v1 import aletheia_pb2 as pb
from aletheia.gen.aleth.v1.aletheia_pb2_grpc import GatewayServiceStub
from aletheia.providers.provider import OpenAICompatProvider

TARGET = "10.40.23.191"  # 靶场真实内网地址（Juice Shop :3000）
SESSION = "q5-e2e"

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def main() -> int:
    gw = GatewayServiceStub(grpc.insecure_channel("127.0.0.1:7724"))

    # 1. 真实 nmap 观测（-oX - 的 XML 输出与适配器同源）。
    # 行内 noqa 的理由：argv 是本文件内的固定常量（非外部输入），
    # S603/S607 针对"执行不可信输入"；裸命令名刻意继承容器 PATH 的 nmap。
    proc = subprocess.run(  # noqa: S603
        ["nmap", "-sV", "-p", "3000", "--script", "http-title", "-Pn", "-oX", "-", TARGET],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=120,
    )
    raw = proc.stdout
    check(
        "nmap 真实扫描产出观测",
        len(raw) > 500 and TARGET in raw,
        f"{len(raw)} bytes, 含真实 IP: {TARGET in raw}",
    )

    # 2. Gateway Tokenize（真实 gRPC）
    tok = gw.Tokenize(pb.TokenizeRequest(session_id=SESSION, content=raw), timeout=30)
    tokenized = tok.tokenized

    # 3. 断言 A：模型侧内容零真实值
    check("A1 tokenized 中零靶场真实 IP", TARGET not in tokenized)
    # A2：映射表里的 token 必须真实出现在内容中（格式为 {CATEGORY}_{seq}，
    # 如 IP_PRIVATE_001 —— 与映射清单逐一核对，比前缀假设更严格）
    tokens_in_content = [m.token for m in tok.mappings if m.token in tokenized]
    check(
        "A2 token 已替换进模型侧内容",
        len(tokens_in_content) == len(tok.mappings) and len(tok.mappings) > 0,
        f"{len(tokens_in_content)}/{len(tok.mappings)} tokens in content",
    )
    cats = sorted({m.category for m in tok.mappings})
    print(f"      映射类别: {cats}")

    # 4. Provider 出站（scan 钩子 = Gateway.ScanOutbound，R7）
    def scan(text: str) -> None:
        r = gw.ScanOutbound(
            pb.ScanRequest(session_id=SESSION, content=text, direction="model_request"),
            timeout=30,
        )
        if not r.clean:
            hits = "; ".join(f"{h.category}@{h.offset}" for h in r.hits[:3])
            raise RuntimeError(f"outbound scan blocked: {hits}")

    provider = OpenAICompatProvider(
        base_url="http://127.0.0.1:18888/v1",
        api_key="q5-mock-key",
        timeout_s=30,
    )
    result = provider.chat(tokenized, model="mock-1", max_tokens=16, scan=scan)
    check("B1 tokenized prompt 经 scan 出站成功", result.content == "ack")

    # 5. 断言 B（反面）：原始输出必须被 ScanOutbound 拦截
    raw_scan = gw.ScanOutbound(
        pb.ScanRequest(session_id=SESSION, content=raw, direction="model_request"),
        timeout=30,
    )
    check(
        "B2 原始观测被 ScanOutbound 命中（不 clean）",
        not raw_scan.clean,
        f"hits={len(raw_scan.hits)}",
    )

    print()
    if failures:
        print(f"Q5 VERIFY FAILED: {failures}")
        return 1
    print("Q5 VERIFY OK（机制断言全过；抓包断言由 pcap 侧脚本核对）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
