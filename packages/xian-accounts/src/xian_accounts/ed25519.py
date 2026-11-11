from __future__ import annotations

import secrets

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

_KEY_HEX_LENGTH = 64
_SIGNATURE_HEX_LENGTH = 128
_CANONICAL_HEX_DIGITS = frozenset("0123456789abcdef")


def is_canonical_hex(value: object, length: int) -> bool:
    """Canonical hex is exactly ``length`` characters from ``[0-9a-f]``.

    Addresses are state keys, so one Ed25519 key must have one spelling.
    """
    return (
        isinstance(value, str)
        and len(value) == length
        and all(char in _CANONICAL_HEX_DIGITS for char in value)
    )


def _is_private_key_hex(value: object) -> bool:
    # A private key is never a state key, so its hex case is not significant.
    return isinstance(value, str) and is_canonical_hex(value.lower(), _KEY_HEX_LENGTH)


def is_valid_ed25519_key(key: str) -> bool:
    return is_canonical_hex(key, _KEY_HEX_LENGTH)


def generate_private_key() -> str:
    return secrets.token_bytes(32).hex()


def public_key_from_private_key(private_key: str) -> str:
    signing_key = SigningKey(seed=bytes.fromhex(private_key))
    return signing_key.verify_key.encode().hex()


def sign_message(private_key: str, message: str) -> str:
    signing_key = SigningKey(seed=bytes.fromhex(private_key))
    signed_message = signing_key.sign(message.encode("utf-8"))
    return signed_message.signature.hex()


def verify_message(public_key: str, message: str, signature: str) -> bool:
    if not (
        is_canonical_hex(public_key, _KEY_HEX_LENGTH)
        and is_canonical_hex(signature, _SIGNATURE_HEX_LENGTH)
        and isinstance(message, str)
    ):
        return False
    try:
        VerifyKey(bytes.fromhex(public_key)).verify(
            message.encode("utf-8"),
            bytes.fromhex(signature),
        )
    except (BadSignatureError, ValueError):
        return False
    return True


class Ed25519Account:
    def __init__(self, private_key: str):
        if not _is_private_key_hex(private_key):
            raise ValueError("private_key must be a 32-byte hex string")
        self._private_key = private_key

    @classmethod
    def generate(cls) -> "Ed25519Account":
        return cls(generate_private_key())

    @property
    def private_key(self) -> str:
        return self._private_key

    @property
    def public_key(self) -> str:
        return public_key_from_private_key(self._private_key)

    def sign_message(self, message: str) -> str:
        return sign_message(self._private_key, message)

    def verify_message(self, message: str, signature: str) -> bool:
        return verify_message(self.public_key, message, signature)

    def sign_msg(self, message: str) -> str:
        return self.sign_message(message)

    def verify_msg(self, message: str, signature: str) -> bool:
        return self.verify_message(message, signature)

    @staticmethod
    def is_valid_key(key: str) -> bool:
        return is_valid_ed25519_key(key)
