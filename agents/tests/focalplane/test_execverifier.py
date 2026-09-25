"""G-1 验签器（execverifier.py）的单元测试。

分离于账本测试：这里只验证密码学原语本身的行为 ——
合法签名通过、任何篡改被拒、域分离生效、坏输入在构造期显式失败。
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from aletheia.focalplane.execverifier import Ed25519Verifier, exec_id_sign_input

EXEC_ID = "exec_018f2a00000000000000000000000001"


@pytest.fixture()
def keypair() -> tuple[Ed25519PrivateKey, Ed25519Verifier]:
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return priv, Ed25519Verifier(pub_hex)


def test_valid_signature_passes(keypair) -> None:
    priv, verifier = keypair
    sig = priv.sign(exec_id_sign_input(EXEC_ID)).hex()
    verdict = verifier.verify(EXEC_ID, sig)
    assert verdict.passed


def test_tampered_exec_id_rejected(keypair) -> None:
    priv, verifier = keypair
    sig = priv.sign(exec_id_sign_input(EXEC_ID)).hex()
    verdict = verifier.verify(EXEC_ID + "0", sig)  # 换一个 exec_id
    assert not verdict.passed
    assert "signature invalid" in verdict.reason


def test_tampered_signature_rejected(keypair) -> None:
    priv, verifier = keypair
    sig = bytearray(priv.sign(exec_id_sign_input(EXEC_ID)))
    sig[0] ^= 0xFF
    verdict = verifier.verify(EXEC_ID, bytes(sig).hex())
    assert not verdict.passed


def test_wrong_key_rejected() -> None:
    """Q3 类别②的核心：攻击者用自己的密钥签名，合法公钥验签必须拒绝。"""
    attacker = Ed25519PrivateKey.generate()
    legitimate = Ed25519PrivateKey.generate()
    pub_hex = legitimate.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    verifier = Ed25519Verifier(pub_hex)
    verdict = verifier.verify(EXEC_ID, attacker.sign(exec_id_sign_input(EXEC_ID)).hex())
    assert not verdict.passed


def test_cross_domain_signature_rejected(keypair) -> None:
    """域分离：同一私钥对裸 exec_id 的签名不得通过 exec-id 验证。"""
    priv, verifier = keypair
    verdict = verifier.verify(EXEC_ID, priv.sign(EXEC_ID.encode("utf-8")).hex())
    assert not verdict.passed


def test_empty_inputs_rejected(keypair) -> None:
    _, verifier = keypair
    assert not verifier.verify("", "").passed
    assert not verifier.verify(EXEC_ID, "").passed
    assert not verifier.verify("", "00").passed


def test_bad_public_key_hex_fails_fast() -> None:
    with pytest.raises(ValueError, match="not valid hex"):
        Ed25519Verifier("zz-not-hex")
    with pytest.raises(ValueError, match="32 bytes"):
        Ed25519Verifier("aabb")  # 合法 hex 但长度不对
