"""focalplane 测试共享夹具。

测试在这里扮演 **Sandbox**（I3 交付前的签发方）：生成 Ed25519 密钥对，
私钥签发 exec_id 签名，公钥注入 Ledger 的 G-1 验签器。
密钥对仅在测试进程内存活 —— 不存在任何共享的测试私钥。
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from aletheia.focalplane.execverifier import Ed25519Verifier, exec_id_sign_input
from aletheia.gen.aleth.v1 import aletheia_pb2 as pb


@pytest.fixture()
def sandbox_keys() -> tuple[Ed25519PrivateKey, str]:
    """(私钥, 公钥 hex)。私钥扮演 Sandbox，公钥注入 M4 验签器。"""
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return priv, pub_hex


@pytest.fixture()
def verifier(sandbox_keys: tuple[Ed25519PrivateKey, str]) -> Ed25519Verifier:
    return Ed25519Verifier(sandbox_keys[1])


def sign_exec_id(priv: Ed25519PrivateKey, exec_id: str) -> pb.SignedExecId:
    """Sandbox 视角的合法签发（I3 将用同一域分离约定）。"""
    s = pb.SignedExecId()
    s.exec_id = exec_id
    s.signature = priv.sign(exec_id_sign_input(exec_id)).hex()
    return s


@pytest.fixture()
def sandbox_priv(sandbox_keys: tuple[Ed25519PrivateKey, str]) -> Ed25519PrivateKey:
    """测试扮演 Sandbox 的私钥。"""
    return sandbox_keys[0]


@pytest.fixture()
def append_ok(sandbox_priv: Ed25519PrivateKey):
    """合法签名路径的 append 快捷方式（正向用例的辅助）。"""

    def _append(led, entry: pb.EvidenceEntry, *, idempotent: bool = False):
        return led.append(entry, sign_exec_id(sandbox_priv, entry.exec_id), idempotent=idempotent)

    return _append
