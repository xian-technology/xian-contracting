"""Machine-readable contract-language surface and conformance cases."""

from __future__ import annotations

from types import ModuleType
from typing import Any

from contracting.compilation.ir import HOST_BINDINGS, XIAN_VM_HOST_CATALOG_V1
from contracting.compilation.lowering import (
    XIAN_IR_V1_BIN_OPS,
    XIAN_IR_V1_EXPRESSION_NODES,
    XIAN_IR_V1_STATEMENT_NODES,
    XIAN_IR_V1_UNARY_OPS,
)
from contracting.compilation.vm import (
    XIAN_VM_V1_DISALLOWED_CALLS,
    XIAN_VM_V1_PROFILE,
    XIAN_VM_V1_RESTRICTED_SYNTAX,
    XIAN_VM_V1_TRACKED_CALL_FEATURES,
)
from contracting.compilation.whitelists import (
    ALLOWED_ANNOTATION_TYPES,
    ALLOWED_BUILTINS,
    ILLEGAL_AST_TYPES,
)
from contracting.stdlib import env as stdlib_env

CONTRACT_LANGUAGE_MANIFEST_VERSION = "xian_contract_language_v1"


def _public_env_surface() -> dict[str, Any]:
    surface: dict[str, Any] = {}
    for name, value in stdlib_env.gather().items():
        if name == "rt" or name.startswith("_"):
            continue
        if isinstance(value, ModuleType):
            surface[name] = {
                "kind": "module",
                "exports": sorted(
                    member
                    for member in dir(value)
                    if not member.startswith("_")
                ),
            }
            continue
        surface[name] = {
            "kind": "value",
            "type": type(value).__name__,
        }
    return dict(sorted(surface.items()))


def build_contract_language_manifest() -> dict[str, Any]:
    return {
        "manifest_version": CONTRACT_LANGUAGE_MANIFEST_VERSION,
        "python_contracting": {
            "allowed_builtins": sorted(ALLOWED_BUILTINS),
            "illegal_ast_nodes": sorted(
                node.__name__ for node in ILLEGAL_AST_TYPES
            ),
            "allowed_annotations": sorted(ALLOWED_ANNOTATION_TYPES),
            "public_env_surface": _public_env_surface(),
        },
        "xian_vm_v1": {
            "profile": XIAN_VM_V1_PROFILE,
            "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
            "restricted_syntax": sorted(XIAN_VM_V1_RESTRICTED_SYNTAX),
            "tracked_call_features": sorted(XIAN_VM_V1_TRACKED_CALL_FEATURES),
            "disallowed_calls": sorted(XIAN_VM_V1_DISALLOWED_CALLS),
            "supported_ir": {
                "statement_nodes": sorted(XIAN_IR_V1_STATEMENT_NODES),
                "expression_nodes": sorted(XIAN_IR_V1_EXPRESSION_NODES),
                "binary_operators": sorted(XIAN_IR_V1_BIN_OPS),
                "unary_operators": sorted(XIAN_IR_V1_UNARY_OPS),
            },
            "host_bindings": list(HOST_BINDINGS),
        },
    }


CONTRACT_LANGUAGE_MANIFEST = build_contract_language_manifest()


def current_vm_parity_gaps() -> dict[str, list[str]]:
    return {
        "builtins": sorted(
            builtin
            for builtin in XIAN_VM_V1_DISALLOWED_CALLS
            if builtin in ALLOWED_BUILTINS
        ),
        "syntax": sorted(XIAN_VM_V1_RESTRICTED_SYNTAX),
    }

CONTRACT_LANGUAGE_CONFORMANCE_CASES: tuple[dict[str, Any], ...] = (
    {
        "id": "bitwise_integer_ops",
        "description": "Bitwise operators and unary invert behave like the Python VM.",
        "source": """
flags = Hash(default_value=0)

@export
def probe(value: int):
    flags["value"] = value
    flags["value"] &= 14
    flags["value"] ^= 3
    flags["value"] <<= 1
    return {
        "stored": flags["value"],
        "and": value & 6,
        "or": value | 8,
        "xor": value ^ 5,
        "left": value << 2,
        "right": value >> 1,
        "invert": ~value,
    }
""",
        "function_name": "probe",
        "kwargs": {"value": 13},
    },
    {
        "id": "raise_exception_instance",
        "description": "Explicit Exception(...) raising matches the Python VM error path.",
        "source": """
@export
def fail(armed: bool):
    if armed:
        raise Exception("boom")
    return "ok"
""",
        "function_name": "fail",
        "kwargs": {"armed": True},
    },
    {
        "id": "raise_exception_type",
        "description": "Raising the Exception type object instantiates the same error shape.",
        "source": """
@export
def fail():
    raise Exception
""",
        "function_name": "fail",
        "kwargs": {},
    },
    {
        "id": "keyword_unpack_calls",
        "description": "Keyword unpacking in calls behaves like the Python VM.",
        "source": """
def quote(amount: int, to: str, memo: str = ""):
    return {
        "amount": amount,
        "to": to,
        "memo": memo,
    }

@export
def render():
    base = {"amount": 5, "to": "bob"}
    override = {"memo": "hello", "to": "carol"}
    return quote(**base, **override)
""",
        "function_name": "render",
        "kwargs": {},
    },
)
