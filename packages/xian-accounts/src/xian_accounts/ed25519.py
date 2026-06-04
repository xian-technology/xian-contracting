from __future__ import annotations

import secrets

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

_KEY_HEX_LENGTH = 64


def _is_hex_string(value: str, *, expected_length: int = _KEY_HEX_LENGTH) -> bool:
    if len(value) != expected_length:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def is_valid_ed25519_key(key: str) -> bool:
    return _is_hex_string(key)


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
    try:
        verify_key = VerifyKey(bytes.fromhex(public_key))
        verify_key.verify(
            message.encode("utf-8"),
            bytes.fromhex(signature),
        )
    except (BadSignatureError, ValueError):
        return False
    return True


class Ed25519Account:
    def __init__(self, private_key: str):
        if not is_valid_ed25519_key(private_key):
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
