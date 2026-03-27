import re


_CONTRACT_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def validate_contract_name(name: str) -> str:
    if not isinstance(name, str):
        raise AssertionError("Contract name must be a string!")

    if len(name) == 0:
        raise AssertionError("Contract name must not be empty!")

    if len(name) > 64:
        raise AssertionError("Contract name length exceeds 64 characters!")

    if not _CONTRACT_NAME_RE.fullmatch(name):
        raise AssertionError(
            "Contract name must start with a lowercase ASCII letter "
            "and contain only lowercase ASCII letters, digits, and underscores!"
        )

    return name
