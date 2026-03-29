from __future__ import annotations

import re

MAX_CONTRACT_NAME_LENGTH = 64
_SAFE_CONTRACT_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def is_safe_contract_name(name: object) -> bool:
    if not isinstance(name, str):
        return False
    return _SAFE_CONTRACT_NAME_RE.fullmatch(name) is not None


def assert_safe_contract_name(name: object) -> str:
    assert isinstance(name, str) and name != "", (
        "Contract name must be a non-empty string."
    )
    assert len(name) <= MAX_CONTRACT_NAME_LENGTH, (
        f"Contract name length exceeds {MAX_CONTRACT_NAME_LENGTH} characters!"
    )
    assert is_safe_contract_name(name), (
        "Contract name must start with a lowercase ASCII letter and contain "
        "only lowercase ASCII letters, digits, and underscores."
    )
    return name
