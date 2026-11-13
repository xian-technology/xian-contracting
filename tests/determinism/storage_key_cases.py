"""V2 writes at LMDB's 511-byte storage key limit.

A key of exactly 511 bytes is committed and reopened in every scenario; one
byte more fails the transaction at the write.
"""

LIMIT = 511
PREFIX = "determinism_"  # the observer deploys each case as PREFIX + case id


def _hash_write(suffix_bytes, shape):
    if shape == "text":
        return f"data['x' * {suffix_bytes}] = 1"
    if shape == "utf8":  # two bytes per character
        return f"data['x' * {suffix_bytes % 2} + '\\u00e9' * {suffix_bytes // 2}] = 1"
    first = suffix_bytes // 2  # two dimensions joined by ':'
    return f"data['x' * {first}, 'y' * {suffix_bytes - first - 1}] = 1"


def _case(name, key_bytes, shape):
    contract = f"{PREFIX}storage_key_v2_{name}"
    if shape == "variable":
        binding = "v" * (key_bytes - len(contract) - 1)  # contract.binding
        declarations, write = f"{binding} = Variable()\n", f"{binding}.set(1)"
    else:
        declarations = "data = Hash()\n"
        write = _hash_write(key_bytes - len(f"{contract}.data:"), shape)
    return {
        "id": f"storage_key_v2_{name}",
        "vm_profile": "xian_vm_v2",
        "source": f"{declarations}@export\ndef probe():\n    {write}\n    return 1\n",
        **({"expected_result": 1} if key_bytes <= LIMIT else {"expected_failure": True}),
    }


def storage_key_cases():
    return [
        _case("hash_largest", LIMIT, "text"),
        _case("hash_over", LIMIT + 1, "text"),
        _case("utf8_largest", LIMIT, "utf8"),
        _case("utf8_over", LIMIT + 1, "utf8"),
        _case("multi_over", LIMIT + 1, "multi"),
        _case("variable_largest", LIMIT, "variable"),
        _case("variable_over", LIMIT + 1, "variable"),
    ]
