"""G-1 执行绑定（modules/M4 §4.2，T4.2）：exec_id 的独立验签。

07 §T4.1 的缓解原文：「exec_id 由 Sandbox 签发并签名，私钥不出 Sandbox
进程；**M4 独立验签**」。三个设计含义：

1. **非对称签名**（Ed25519）：M4 只持公钥。HMAC 等对称方案会让验签方
   同时持有签发能力，等于撤销「私钥不出 Sandbox」—— 那正是 T4.1 要防的。
2. **验签在 append 路径上**：Ledger.append 是唯一入库路径且强制验签，
   不存在绕过 G-1 的入库方式（对应 09 §R4 的「无旁路」原则）。
3. **不信任调用方字段**：verdict 只由公钥验证结果决定，与请求里任何
   自我声明（如「我来自 Sandbox」）无关。

签名输入（域分离，防跨域重放）::

    sign_input = b"aleth/exec-id/v1\\0" + exec_id.encode("utf-8")

I3 的 SandboxService 用同一域分离的私钥签发；I2 期间测试扮演 Sandbox。
"""

from __future__ import annotations

import abc
import binascii
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# 域分隔：算法与用途绑定。Sandbox（I3）签发时必须使用同一前缀。
EXEC_ID_SIGN_DOMAIN = b"aleth/exec-id/v1\x00"


def exec_id_sign_input(exec_id: str) -> bytes:
    """待签名载荷。Sandbox 与 M4 共享的唯一事实。"""
    return EXEC_ID_SIGN_DOMAIN + exec_id.encode("utf-8")


@dataclass(frozen=True)
class GateVerdict:
    """G-1 的独立结论。reason 写入 GateResult.reason（可审计）。"""

    passed: bool
    reason: str = ""


PASSED = GateVerdict(passed=True, reason="exec_id signature verified")


class ExecVerifier(abc.ABC):
    """exec_id 验签接口。M4 侧的唯一信任锚是 Sandbox 公钥。

    signature 采用 **hex 文本**（与 proto SignedExecId.signature 的 string
    类型对齐 —— 05 §6.3 frozen 原文如此；Ed25519 签名 64 字节 → 128 hex 字符）。
    """

    @abc.abstractmethod
    def verify(self, exec_id: str, signature: str) -> GateVerdict:
        """验证 signature（hex）是否为 Sandbox 私钥对 exec_id 的签名。"""


class Ed25519Verifier(ExecVerifier):
    """Ed25519 验签。公钥为 32 字节裸格式（hex 传入，配置面最小）。"""

    def __init__(self, public_key_hex: str) -> None:
        try:
            raw = bytes.fromhex(public_key_hex)
        except (ValueError, binascii.Error) as exc:
            raise ValueError(f"public_key_hex is not valid hex: {exc}") from exc
        if len(raw) != 32:
            raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(raw)}")
        self._key = Ed25519PublicKey.from_public_bytes(raw)

    def verify(self, exec_id: str, signature: str) -> GateVerdict:
        if not exec_id:
            return GateVerdict(passed=False, reason="exec_id is empty")
        if not signature:
            return GateVerdict(passed=False, reason="signature is empty")
        try:
            sig_bytes = bytes.fromhex(signature)
        except ValueError:
            return GateVerdict(passed=False, reason="signature is not valid hex")
        try:
            self._key.verify(sig_bytes, exec_id_sign_input(exec_id))
        except InvalidSignature:
            return GateVerdict(
                passed=False,
                reason="exec_id signature invalid (not issued by the Sandbox key)",
            )
        return PASSED
