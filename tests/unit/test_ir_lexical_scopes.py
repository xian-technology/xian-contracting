"""Both IR lowerers must classify lexical reads before optimizing host access."""

import ast

import pytest

from contracting.compilation.lowering import XianIrLowerer


def lower(source):
    return XianIrLowerer(module_name="con_scopes", profile="xian_vm_v1").lower(
        ast.parse(source), source=source
    )


def test_function_local_host_call_is_not_lowered_to_syscall():
    ir = lower(
        "@export\ndef probe():\n    result = hashlib.sha3('x')\n    hashlib = 7\n    return result\n"
    )
    call = ir["functions"][0]["body"][0]["value"]
    assert call["syscall_id"] is None
    assert call["func"]["host_binding_id"] is None
    assert call["func"]["value"]["host_binding_id"] is None


def test_shadowed_storage_is_lowered_as_ordinary_value_access():
    ir = lower("h = Hash()\n@export\ndef probe():\n    h[0] += 1\n    h = {}\n    return h[0]\n")
    body = ir["functions"][0]["body"]
    assert body[0]["node"] == "aug_assign"
    assert body[0]["target"]["node"] == "subscript"
    assert body[2]["value"]["node"] == "subscript"


def test_comprehension_first_iterable_uses_enclosing_scope():
    ir = lower("@export\ndef probe():\n    return [hashlib for hashlib in hashlib.sha3('x')]\n")
    expression = ir["functions"][0]["body"][0]["value"]
    assert expression["element"]["host_binding_id"] is None
    assert expression["generators"][0]["iter"]["syscall_id"] == "hash.sha3_256_legacy"


@pytest.mark.parametrize(
    "expression",
    [
        "[hashlib.sha3('x') for hashlib in [1]]",
        "{hashlib: hashlib.sha3('x') for hashlib in [1]}",
    ],
)
def test_comprehension_targets_shadow_host_bindings(expression):
    ir = lower(f"@export\ndef probe():\n    return {expression}\n")
    comp = ir["functions"][0]["body"][0]["value"]
    call = comp.get("element", comp.get("value"))
    assert call["syscall_id"] is None


def test_later_comprehension_target_is_local_in_earlier_filter():
    ir = lower("@export\ndef probe():\n    return [x for x in [1] if hashlib for hashlib in [1]]\n")
    condition = ir["functions"][0]["body"][0]["value"]["generators"][0]["ifs"][0]
    assert condition["host_binding_id"] is None


def test_shadowed_static_contract_import_is_not_static_dispatch():
    ir = lower(
        "import currency\n@export\ndef probe():\n    result = currency.balance_of('x')\n    currency = 7\n    return result\n"
    )
    call = ir["functions"][0]["body"][0]["value"]
    assert call["syscall_id"] is None
    assert "contract_target" not in call


@pytest.mark.parametrize("parameters", ["*hashlib", "**hashlib"])
def test_variadic_parameters_shadow_module_calls(parameters):
    ir = lower(
        f"def probe({parameters}):\n    return hashlib.sha3('x')\n@export\ndef public_probe():\n    return 1\n"
    )
    call = ir["functions"][0]["body"][0]["value"]
    assert call["syscall_id"] is None
    assert call["func"]["value"]["host_binding_id"] is None
