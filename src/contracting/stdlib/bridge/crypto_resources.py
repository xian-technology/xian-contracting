"""Admission limits shared by the local hash and crypto bridges.

Native execution owns chi pricing. Count UTF-8 bytes before encoding so a local
harness cannot allocate an arbitrarily large temporary merely to check a cap.
"""

TEXT_LIMIT = 1024 * 1024
HEX_LIMIT = 2 * TEXT_LIMIT
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_HEX_WHITESPACE = frozenset(" \t\n\r\v\f")


def check_size(size: int, maximum: int, label: str) -> None:
    if size > maximum:
        raise ValueError(f"{label} resource limit exceeded ({maximum} UTF-8 bytes)")


def utf8_size(value: str, maximum: int, label: str) -> int:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    check_size(len(value), maximum, label)
    if value.isascii():
        return len(value)
    size = 0
    for index, char in enumerate(value):
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            raise UnicodeEncodeError("utf-8", value, index, index + 1, "surrogates not allowed")
        size += 1 + (code >= 0x80) + (code >= 0x800) + (code >= 0x10000)
        check_size(size, maximum, label)
    return size


def legacy_hex_length(value: str) -> int | None:
    """Classify without allocating; whitespace may occur between whole pairs."""
    index = 0
    length = 0
    while index < len(value):
        if value[index] in _HEX_WHITESPACE:
            index += 1
            continue
        if index + 1 >= len(value):
            return None
        if value[index] not in _HEX_CHARS or value[index + 1] not in _HEX_CHARS:
            return None
        length += 1
        index += 2
    return length
