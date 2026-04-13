"""Machine-readable contract-language surface and conformance cases."""

from __future__ import annotations

import ast
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
    ILLEGAL_BUILTINS,
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

CONFORMANCE_BUILTIN_EXCLUSIONS: dict[str, str] = {
    "True": "Boolean literal, covered as syntax rather than a callable builtin.",
    "False": "Boolean literal, covered as syntax rather than a callable builtin.",
    "None": "None literal, covered as syntax rather than a callable builtin.",
    "import": "Contract imports are covered via import statements and importlib, not the raw builtin token.",
    "bytes": "Binary value parity needs a dedicated VM value type and serialization coverage.",
    "bytearray": "Mutable binary value parity needs a dedicated VM value type and serialization coverage.",
    "map": "Lazy higher-order iterator semantics need dedicated VM callable/value-model support.",
    "filter": "Lazy higher-order iterator semantics need dedicated VM callable/value-model support.",
}
CONFORMANCE_ENV_EXCLUSIONS: dict[str, str] = {}


def current_vm_parity_gaps() -> dict[str, list[str]]:
    syntax_nodes_by_name = {
        "dict comprehension": ast.DictComp,
        "generator expression": ast.GeneratorExp,
        "set comprehension": ast.SetComp,
        "set literal": ast.Set,
    }
    return {
        "builtins": sorted(
            builtin
            for builtin in XIAN_VM_V1_DISALLOWED_CALLS
            if builtin in ALLOWED_BUILTINS and builtin not in ILLEGAL_BUILTINS
        ),
        "syntax": sorted(
            syntax
            for syntax in XIAN_VM_V1_RESTRICTED_SYNTAX
            if syntax_nodes_by_name[syntax] not in ILLEGAL_AST_TYPES
        ),
    }


def covered_conformance_surface() -> dict[str, set[str]]:
    builtins: set[str] = set()
    env: set[str] = set()
    for case in CONTRACT_LANGUAGE_CONFORMANCE_CASES:
        builtins.update(case.get("covers_builtins", ()))
        env.update(case.get("covers_env", ()))
    return {"builtins": builtins, "env": env}

CONTRACT_LANGUAGE_CONFORMANCE_CASES: tuple[dict[str, Any], ...] = (
    {
        "id": "bitwise_integer_ops",
        "description": "Bitwise operators and unary invert behave like the Python VM.",
        "covers_builtins": ("int",),
        "covers_env": ("Hash",),
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
        "covers_builtins": ("Exception",),
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
        "covers_builtins": ("Exception",),
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
        "covers_builtins": ("dict",),
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
    {
        "id": "dict_comprehension",
        "description": "Dict comprehensions behave like the Python VM.",
        "covers_builtins": ("str",),
        "source": """
@export
def render(values: list[int]):
    return {str(value): value * 2 for value in values if value > 0}
""",
        "function_name": "render",
        "kwargs": {"values": [-1, 0, 2, 5]},
    },
    {
        "id": "builtin_scalar_helpers",
        "description": "Scalar/text builtins behave like the Python VM.",
        "covers_builtins": (
            "abs",
            "ascii",
            "bin",
            "bool",
            "chr",
            "divmod",
            "float",
            "format",
            "hex",
            "int",
            "isinstance",
            "issubclass",
            "oct",
            "ord",
            "pow",
            "round",
            "str",
            "tuple",
        ),
        "source": """
@export
def probe():
    return {
        "abs_int": abs(-7),
        "abs_float": abs(-2.5),
        "ascii": ascii("Grüß"),
        "bin": bin(13),
        "bool": bool([]),
        "chr": chr(65),
        "divmod": divmod(29, 6),
        "float": float("2.5"),
        "format": format(255, "08b"),
        "hex": hex(255),
        "int": int("ff", 16),
        "isinstance": isinstance(4, int),
        "issubclass": issubclass(bool, (bool, int)),
        "oct": oct(9),
        "ord": ord("A"),
        "pow": pow(7, 3, 13),
        "round_int": round(3.6),
        "round_digits": round(3.14159, 2),
        "str": str(42),
    }
""",
        "function_name": "probe",
        "kwargs": {},
    },
    {
        "id": "builtin_iterable_helpers",
        "description": "Iterable and aggregate builtins behave like the Python VM.",
        "covers_builtins": (
            "all",
            "any",
            "dict",
            "len",
            "list",
            "max",
            "min",
            "range",
            "reversed",
            "sorted",
            "sum",
            "tuple",
            "zip",
        ),
        "source": """
@export
def probe(values: list[int]):
    return {
        "len": len(values),
        "range": list(range(2, 8, 2)),
        "list": list((1, 2, 3)),
        "tuple": tuple([4, 5]),
        "dict": dict([("a", 1), ("b", 2)], c=3),
        "sorted": sorted(values),
        "sum": sum(values, 10),
        "min": min(values),
        "max": max(values),
        "all": all([value > 0 for value in values]),
        "any": any([value < 0 for value in values]),
        "reversed": list(reversed(values)),
        "zip": list(zip(values, range(len(values)))),
    }
""",
        "function_name": "probe",
        "kwargs": {"values": [3, 1, 2]},
    },
    {
        "id": "host_storage_event_context",
        "description": "Storage, event, typing, and context bridge values match the Python VM.",
        "covers_env": (
            "Any",
            "Hash",
            "LogEvent",
            "Variable",
            "ctx",
            "indexed",
        ),
        "source": """
counter = Variable()
balances = Hash(default_value=0)
Seen = LogEvent(
    "Seen",
    {
        "caller": indexed(str),
        "balance": int,
    },
)

@construct
def seed():
    counter.set(2)

@export(typecheck=True)
def probe(value: Any, amount: int) -> Any:
    balances[ctx.caller] += amount
    Seen({"caller": ctx.caller, "balance": balances[ctx.caller]})
    return {
        "value": value,
        "counter": counter.get(),
        "balance": balances[ctx.caller],
        "caller": ctx.caller,
        "this": ctx.this,
        "owner": ctx.owner,
        "entry": ctx.entry,
    }
""",
        "function_name": "probe",
        "kwargs": {"value": {"kind": "ok"}, "amount": 4},
    },
    {
        "id": "host_module_bridges",
        "description": "Bridge modules and foreign storage behave like the Python VM.",
        "covers_env": (
            "Contract",
            "ForeignHash",
            "ForeignVariable",
            "crypto",
            "datetime",
            "decimal",
            "hashlib",
            "importlib",
            "random",
            "zk",
        ),
        "dependencies": (
            {
                "name": "conformance_host_helper",
                "source": """
status = Variable()
ledger = Hash(default_value=0)

@construct
def seed():
    status.set("ready")
    ledger["alice"] = 7

@export
def ping(name: str):
    return {
        "name": name,
        "count": ledger[name],
        "status": status.get(),
    }
""",
            },
        ),
        "source": """
status = ForeignVariable(contract="conformance_host_helper", name="status")
ledger = ForeignHash(contract="conformance_host_helper", name="ledger")

@export
def probe():
    helper = importlib.import_module("conformance_host_helper")
    random.seed("alpha")
    return {
        "shadow": status.get(),
        "ledger": ledger["alice"],
        "exists": importlib.exists("conformance_host_helper"),
        "has_export": importlib.has_export("conformance_host_helper", "ping"),
        "call": importlib.call("conformance_host_helper", "ping", {"name": "alice"}),
        "owner": importlib.owner_of("conformance_host_helper"),
        "info": {
            "owner": Contract.get_info("conformance_host_helper")["owner"],
            "developer": Contract.get_info("conformance_host_helper")["developer"],
            "deployer": Contract.get_info("conformance_host_helper")["deployer"],
            "initiator": Contract.get_info("conformance_host_helper")["initiator"],
        },
        "module_ping": helper.ping(name="alice"),
        "decimal": decimal("1.25") + decimal("2.50"),
        "time": datetime.datetime.strptime(
            "2026-04-13 12:34:56",
            "%Y-%m-%d %H:%M:%S",
        ) + datetime.DAYS,
        "sha256": hashlib.sha256("hello"),
        "sha3": hashlib.sha3("hello"),
        "key_valid": crypto.key_is_valid("0" * 64),
        "randbits": random.getrandbits(8),
        "randrange": random.randrange(10),
        "randint": random.randint(5, 9),
        "choice": random.choice(["a", "b", "c"]),
        "choices": random.choices(["x", "y"], 3),
        "zk_available": zk.is_available(),
        "zk_payload_hash": zk.shielded_output_payload_hash("0x1234"),
    }
""",
        "function_name": "probe",
        "kwargs": {},
    },
)
