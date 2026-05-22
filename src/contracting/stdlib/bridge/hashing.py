import hashlib
from types import ModuleType

_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def _text_bytes(value: str) -> bytes:
    assert isinstance(value, str), "hash text input must be a string"
    return value.encode("utf-8")


def _strict_hex_bytes(value: str) -> bytes:
    assert isinstance(value, str), "hash hex input must be a string"
    assert len(value) % 2 == 0, "hash hex input must contain whole bytes"
    assert all(char in _HEX_CHARS for char in value), (
        "hash hex input must be unprefixed hexadecimal"
    )
    return bytes.fromhex(value)


def sha3_text(value: str):
    byte_str = _text_bytes(value)

    hasher = hashlib.sha3_256()
    hasher.update(byte_str)

    hashed_bytes = hasher.digest()

    return hashed_bytes.hex()


def sha3_hex(value: str):
    byte_str = _strict_hex_bytes(value)

    hasher = hashlib.sha3_256()
    hasher.update(byte_str)

    hashed_bytes = hasher.digest()

    return hashed_bytes.hex()


def sha256_text(value: str):
    byte_str = _text_bytes(value)

    hasher = hashlib.sha256()
    hasher.update(byte_str)

    hashed_bytes = hasher.digest()

    return hashed_bytes.hex()


def sha256_hex(value: str):
    byte_str = _strict_hex_bytes(value)

    hasher = hashlib.sha256()
    hasher.update(byte_str)

    hashed_bytes = hasher.digest()

    return hashed_bytes.hex()


hashlib_module = ModuleType("hashlib")
hashlib_module.sha3_text = sha3_text
hashlib_module.sha3_hex = sha3_hex
hashlib_module.sha256_text = sha256_text
hashlib_module.sha256_hex = sha256_hex

exports = {
    "hashlib": hashlib_module,
}
