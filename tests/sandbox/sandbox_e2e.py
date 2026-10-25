"""Sandbox 装配后的 Execute 全链 e2e（NAS 靶场）。

链路：IngestService.Execute(nmap → Juice Shop) —— Scope 校验（真实
Kernel）→ 参数 Tokenize → 版本门禁 → ProcessSandbox 真实执行 nmap
→ 输出 Tokenize → ScanOutbound（tokenized 后扫描）→ 解析 → Spectrum
（真实实体）→ PrismService.Ingest 进图 → Project 验证。

修正点回归（I3 行为缺陷）：nmap 真实输出含私网 IP 10.40.23.191 ——
修正前此处 100% PRIVACY_LEAK_DETECTED；修正后 tokenized 放行。
"""
from __future__ import annotations

import sys

import grpc

from aletheia.gen.aleth.v1 import aletheia_pb2 as pb
from aletheia.gen.aleth.v1.aletheia_pb2_grpc import IngestServiceStub, PrismServiceStub

ALETHD = "127.0.0.1:7724"
TARGET = "10.40.23.191"  # Juice Shop :3000（NAS 本机）

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def main() -> int:
    ch = grpc.insecure_channel(ALETHD)
    ingest = IngestServiceStub(ch)

    req = pb.ToolRequest()
    req.tool_name = "nmap"
    req.params["target"] = TARGET
    req.params["ports"] = "3000"
    req.params["service_detection"] = "true"
    req.session_id = "sandbox-e2e"

    try:
        sp = ingest.Execute(req, timeout=180)
    except grpc.RpcError as e:
        print(f"FAIL  Execute 抛错: {e.code()} {e.details()}")
        return 1

    check("Execute 全链成功（scope/tokenize/sandbox/scan/parse）", True,
          f"spectrum={sp.spectrum_id[:18]}… exec={sp.exec_id[:18]}…")
    check("exec_id 由 Sandbox 签发（exec_ 前缀）", sp.exec_id.startswith("exec_"))
    assets = [d for d in sp.entities if d.kind == pb.ASSET]
    services = [d for d in sp.entities if d.kind == pb.SERVICE]
    check("真实实体草稿（ASSET 含靶场地址）",
          any(d.attributes.get("addr") == TARGET for d in assets),
          f"assets={len(assets)} services={len(services)}")
    check("观测行折叠（无损层）", len(sp.lines) > 0, f"lines={len(sp.lines)}")

    prism = PrismServiceStub(ch)
    r = prism.Ingest(sp, timeout=30)
    check("光谱进图（PrismService.Ingest）", True,
          f"created={len(r.created_entity_ids)} updated={len(r.updated_entity_ids)} conflicts={len(r.conflicts)}")

    preq = pb.ProjectRequest()
    preq.focus = ""
    preq.max_hops = 0
    preq.max_entities = 500
    sub = prism.Project(preq, timeout=30)
    hit = [e for e in sub.entities if e.attributes.get("addr") == TARGET]
    check("图谱可见靶场实体", len(hit) >= 1, f"graph entities={len(sub.entities)}")
    ch.close()

    print()
    if failures:
        print(f"SANDBOX E2E FAILED: {failures}")
        return 1
    print("SANDBOX E2E OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
