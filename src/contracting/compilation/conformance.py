"""Machine-readable contract-language surface and conformance cases."""

from __future__ import annotations

import ast
from functools import lru_cache
from types import ModuleType
from typing import Any

from xian_runtime_types.collections import ContractingFrozenSet

from contracting.compilation.artifacts import build_contract_artifacts
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
}
CONFORMANCE_ENV_EXCLUSIONS: dict[str, str] = {}


@lru_cache(maxsize=32)
def _compact_artifacts(module_name: str, source: str) -> dict[str, object]:
    return build_contract_artifacts(
        module_name=module_name,
        source=source,
        lint=True,
        compact=True,
    )


def _replay_submission_deploy_source() -> str:
    artifacts = _compact_artifacts(
        "con_replay_submission_child",
        """
value = Variable()

@construct
def seed(label: str):
    value.set(label)

@export
def read():
    return value.get()
""",
    )
    return f"""
ContractDeployedEvent = LogEvent(
    "ContractDeployed",
    {{
        "name": {{"type": str, "idx": True}},
        "owner": {{"type": str}},
        "developer": {{"type": str, "idx": True}},
    }},
)
ContractOwnerChangedEvent = LogEvent(
    "ContractOwnerChanged",
    {{
        "contract": {{"type": str, "idx": True}},
        "previous_owner": {{"type": str}},
        "new_owner": {{"type": str, "idx": True}},
    }},
)

ARTIFACTS = {artifacts!r}

@export
def probe():
    Contract.deploy(
        name="con_replay_submission_child",
        code=None,
        deployment_artifacts=ARTIFACTS,
        owner="owner_a",
        constructor_args={{"label": "ready"}},
        developer=ctx.caller,
        deployer=ctx.caller,
        initiator=ctx.signer,
    )
    ContractDeployedEvent(
        {{
            "name": "con_replay_submission_child",
            "owner": "owner_a",
            "developer": ctx.caller,
        }}
    )
    before = Contract.get_info("con_replay_submission_child")
    Contract.set_developer("con_replay_submission_child", "developer_b")
    Contract.set_owner("con_replay_submission_child", "owner_b")
    ContractOwnerChangedEvent(
        {{
            "contract": "con_replay_submission_child",
            "previous_owner": before["owner"],
            "new_owner": "owner_b",
        }}
    )
    child = importlib.import_module("con_replay_submission_child")
    return {{
        "before": before,
        "after": Contract.get_info("con_replay_submission_child"),
        "value": child.read(),
        "exists": importlib.exists("con_replay_submission_child"),
        "has_export": importlib.has_export(
            "con_replay_submission_child",
            "read",
        ),
    }}
"""


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
    features: set[str] = set()
    for case in CONTRACT_LANGUAGE_CONFORMANCE_CASES:
        builtins.update(case.get("covers_builtins", ()))
        env.update(case.get("covers_env", ()))
        features.update(case.get("covers_features", ()))
    return {"builtins": builtins, "env": env, "features": features}

CONTRACT_LANGUAGE_CONFORMANCE_CASES: tuple[dict[str, Any], ...] = (
    {
        "id": "binary_values",
        "description": "bytes/bytearray values behave like the Python VM and round-trip through storage.",
        "covers_builtins": (
            "bytearray",
            "bytes",
            "dict",
            "format",
            "isinstance",
            "len",
            "list",
            "ord",
        ),
        "covers_env": ("Variable",),
        "covers_features": (
            "storage.variable",
            "syntax.assert",
            "values.binary",
        ),
        "source": """
payload = Variable()

def mutate(value: bytearray) -> bytearray:
    value.append(100)
    value[1] = 122
    value.extend([101, 102])
    tail = value.pop()
    assert tail == 102
    return value

@export
def probe(seed: bytes) -> dict:
    literal = b"abc"
    frozen = bytes(seed)
    zeros = bytes(3)
    mutable = mutate(bytearray(frozen))
    payload.set(mutable.copy())
    stored = payload.get()
    return {
        "literal": literal,
        "frozen": frozen,
        "zeros": zeros,
        "stored": stored,
        "index": literal[1],
        "slice": literal[1:],
        "contains_int": 122 in stored,
        "contains_seq": b"zc" in stored,
        "is_bytes": isinstance(frozen, bytes),
        "is_bytearray": isinstance(stored, bytearray),
        "repeat": bytearray(b"ab") * 2,
        "iter": list(literal),
        "ord": ord(b"A"),
        "format": format(b"A"),
        "hex": stored.hex(),
    }
""",
        "function_name": "probe",
        "kwargs": {"seed": b"abc"},
    },
    {
        "id": "deterministic_sets",
        "description": "Deterministic set/frozenset values behave like the Python VM contract surface.",
        "covers_builtins": (
            "frozenset",
            "isinstance",
            "list",
            "set",
        ),
        "covers_env": ("Variable", "frozenset", "set"),
        "covers_features": (
            "decorators.export.typecheck",
            "storage.variable",
            "values.sets",
        ),
        "source": """
payload = Variable()

@export(typecheck=True)
def probe(seed: list[int], markers: frozenset[int]) -> dict:
    mutable = set(seed)
    mutable.add(7)
    mutable.remove(7)
    mutable.add(7)
    mutable.discard(99)
    removed = mutable.pop()
    mutable.add(removed)
    payload.set(mutable.copy())
    stored = payload.get()
    frozen = frozenset(stored)
    return {
        "stored": stored,
        "frozen": frozen,
        "union": stored.union((9, 1)),
        "intersection": stored.intersection((1, 7, 11)),
        "difference": stored.difference((1,)),
        "symmetric_difference": stored.symmetric_difference((7, 11)),
        "issubset": set((1, 3)) <= stored,
        "strict_subset": set((1,)) < stored,
        "issuperset": stored >= set((1,)),
        "isdisjoint": stored.isdisjoint((42,)),
        "contains": 7 in stored,
        "iter": list(stored),
        "copy": stored.copy(),
        "is_set": isinstance(stored, set),
        "is_frozenset": isinstance(frozen, frozenset),
        "marker_copy": markers.copy(),
        "marker_union": markers.union((9,)),
    }
""",
        "function_name": "probe",
        "kwargs": {
            "seed": [5, 1, 3],
            "markers": ContractingFrozenSet((1, 3)),
        },
    },
    {
        "id": "bitwise_integer_ops",
        "description": "Bitwise operators and unary invert behave like the Python VM.",
        "covers_builtins": ("int",),
        "covers_env": ("Hash",),
        "covers_features": (
            "storage.hash",
            "syntax.bitwise",
        ),
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
        "covers_features": ("syntax.raise",),
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
        "covers_features": ("syntax.raise",),
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
        "covers_features": ("syntax.keyword_unpack",),
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
        "covers_features": ("syntax.dict_comp",),
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
        "covers_features": ("syntax.list_comp",),
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
        "id": "eager_higher_order_helpers",
        "description": "map() and filter() use eager deterministic list semantics in both engines.",
        "covers_builtins": (
            "filter",
            "list",
            "map",
            "range",
        ),
        "covers_env": ("filter", "map"),
        "covers_features": ("helpers.higher_order",),
        "source": """
def double(value: int) -> int:
    return value * 2

def add_pair(left: int, right: int) -> int:
    return left + right

def keep_even(value: int) -> bool:
    return value % 2 == 0

@export
def probe(values: list[int]):
    return {
        "mapped": map(double, values),
        "paired": map(add_pair, values, range(10, 20)),
        "filtered": filter(keep_even, values),
        "truthy": filter(None, [0, 1, "", "hi", False, True]),
        "empty": map(double, []),
    }
""",
        "function_name": "probe",
        "kwargs": {"values": [3, 1, 2, 4]},
    },
    {
        "id": "string_method_helpers",
        "description": "Common deterministic string helpers behave like the Python VM.",
        "covers_features": (
            "methods.string",
            "methods.string.endswith",
            "methods.string.find",
            "methods.string.split",
            "methods.string.startswith",
            "methods.string.strip",
            "methods.string.upper",
        ),
        "source": """
@export
def probe():
    sample = "  Alpha beta ALPHA  "
    return {
        "upper": sample.upper(),
        "strip": sample.strip(),
        "strip_chars": "xyAlpha yx".strip("xy"),
        "startswith": sample.startswith(("  Al", "zzz"), 0, 10),
        "endswith": sample.endswith(("PHA", "beta"), 0, 18),
        "find": sample.find("beta"),
        "find_window": sample.find("ALPHA", 5, 20),
        "split_default": " a  b c ".split(None, 1),
        "split_sep": "a--b--c".split("--", 1),
    }
""",
        "function_name": "probe",
        "kwargs": {},
    },
    {
        "id": "local_collection_methods",
        "description": "Local list/dict helper methods behave like the Python VM.",
        "covers_features": (
            "methods.collection",
            "methods.list.clear",
            "methods.list.copy",
            "methods.list.count",
            "methods.list.index",
        ),
        "source": """
@export
def probe():
    values = [1, 2, 2, 3]
    snapshot = values.copy()
    count = values.count(2)
    position = values.index(2, 2)
    values.clear()

    record = {"alpha": 1, "beta": 2}
    record_copy = record.copy()
    popped = record.pop("beta")
    missing = record.pop("missing", 99)
    record.clear()

    return {
        "snapshot": snapshot,
        "count": count,
        "position": position,
        "values": values,
        "record_copy": record_copy,
        "popped": popped,
        "missing": missing,
        "record": record,
    }
""",
        "function_name": "probe",
        "kwargs": {},
    },
    {
        "id": "authored_string_and_list_methods",
        "description": "String and list helper methods used by authored contracts behave like the Python VM.",
        "covers_features": (
            "methods.collection",
            "methods.list.append",
            "methods.list.extend",
            "methods.list.insert",
            "methods.list.remove",
            "methods.string.isalnum",
            "methods.string.join",
            "methods.string.lower",
            "methods.string.replace",
        ),
        "source": """
@export
def probe():
    labels = ["Alpha", "BETA"]
    labels.append("gamma")
    labels.extend(["delta"])
    labels.insert(1, "inserted")
    labels.remove("BETA")

    lowered = "MiXeD42".lower()
    joined = "|".join(labels)
    return {
        "lower": lowered,
        "isalnum_true": lowered.isalnum(),
        "isalnum_false": "node-42".isalnum(),
        "join": joined,
        "replace": joined.replace("gamma", "omega"),
        "labels": labels,
    }
""",
        "function_name": "probe",
        "kwargs": {},
    },
    {
        "id": "control_flow_and_slicing_edges",
        "description": "Loop else blocks, chained comparisons, and negative slicing match the Python VM.",
        "covers_features": (
            "syntax.loop_else",
            "syntax.while",
        ),
        "source": """
@export
def probe():
    for_values = []
    for candidate in [1, 2, 3]:
        if candidate == 2:
            continue
        for_values.append(candidate)
    else:
        for_values.append(99)

    while_values = []
    counter = 0
    while counter < 3:
        counter += 1
        if counter == 2:
            continue
        while_values.append(counter)
    else:
        while_values.append(77)

    broken = []
    for candidate in [1, 2, 3]:
        if candidate == 2:
            break
        broken.append(candidate)
    else:
        broken.append(55)

    return {
        "for_values": for_values,
        "while_values": while_values,
        "broken": broken,
        "slice": "AlphaBeta"[-7:-1:2],
        "compare": 1 < 2 < 3 and 3 >= 3 > 1,
    }
""",
        "function_name": "probe",
        "kwargs": {},
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
        "covers_features": (
            "context.ctx",
            "decorators.construct",
            "decorators.export",
            "decorators.export.typecheck",
            "events.log",
            "storage.hash",
            "storage.variable",
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
        "covers_features": (
            "modules.contract",
            "modules.crypto",
            "modules.datetime",
            "modules.decimal",
            "modules.hashlib",
            "modules.importlib",
            "modules.random",
            "modules.zk",
            "storage.foreign",
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
status = ForeignVariable(foreign_contract="conformance_host_helper", foreign_name="status")
ledger = ForeignHash(foreign_contract="conformance_host_helper", foreign_name="ledger")

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
    {
        "id": "authored_reward_change_flow",
        "description": "Authored-style reward change flows through a statically imported module like the Python VM.",
        "covers_builtins": (
            "len",
            "sum",
        ),
        "covers_features": ("imports.static",),
        "dependencies": (
            {
                "name": "conformance_rewards_state",
                "source": """
state = Hash(default_value=None)

@construct
def seed():
    state["value"] = [0.88, 0.01, 0.01, 0.10]

@export
def set_value(value: list[float]):
    state["value"] = value
    return state["value"]

@export
def get_value():
    return state["value"]
""",
            },
        ),
        "source": """
import conformance_rewards_state

@export
def probe(change: list[float]):
    assert len(change) == 4
    assert sum(change) == 1
    before = conformance_rewards_state.get_value()
    after = conformance_rewards_state.set_value(change)
    return {
        "before": before,
        "after": after,
        "stored": conformance_rewards_state.get_value(),
    }
""",
        "function_name": "probe",
        "kwargs": {"change": [0.25, 0.25, 0.25, 0.25]},
    },
    {
        "id": "static_import_contract_calls",
        "description": "Static contract imports behave like the Python VM.",
        "covers_builtins": ("dict",),
        "covers_features": ("imports.static",),
        "dependencies": (
            {
                "name": "conformance_static_child",
                "source": """
balances = Hash(default_value=0)

@construct
def seed():
    balances["alice"] = 7

@export
def balance_of(account: str):
    return balances[account]
""",
            },
        ),
        "source": """
import conformance_static_child

@export
def probe(account: str):
    return {
        "balance": conformance_static_child.balance_of(account=account),
    }
""",
        "function_name": "probe",
        "kwargs": {"account": "alice"},
    },
    {
        "id": "token_allowance_event_flow",
        "description": "Token-like approval and transfer event flows match the Python VM.",
        "covers_features": (
            "events.log",
            "storage.hash",
        ),
        "source": """
balances = Hash(default_value=0)
approvals = Hash(default_value=0)

TransferEvent = LogEvent(
    "Transfer",
    {
        "from": indexed(str),
        "to": indexed(str),
        "amount": int,
    },
)
ApproveEvent = LogEvent(
    "Approve",
    {
        "from": indexed(str),
        "to": indexed(str),
        "amount": int,
    },
)

@construct
def seed():
    balances["alice"] = 10

def approve_for(owner: str, spender: str, amount: int):
    approvals[owner, spender] = amount
    ApproveEvent({"from": owner, "to": spender, "amount": amount})

def transfer_from_for(spender: str, main_account: str, to: str, amount: int):
    assert approvals[main_account, spender] >= amount
    assert balances[main_account] >= amount
    approvals[main_account, spender] -= amount
    balances[main_account] -= amount
    balances[to] += amount
    TransferEvent({"from": main_account, "to": to, "amount": amount})

@export
def probe():
    approve_for(ctx.caller, "broker", 4)
    transfer_from_for("broker", ctx.caller, "vault", 3)
    return {
        "allowance": approvals[ctx.caller, "broker"],
        "caller_balance": balances[ctx.caller],
        "vault_balance": balances["vault"],
    }
""",
        "function_name": "probe",
        "kwargs": {},
    },
    {
        "id": "replay_submission_deploy_flow",
        "description": "Submission-style deployment and contract metadata changes match the Python VM.",
        "covers_env": (
            "Contract",
            "importlib",
        ),
        "covers_features": (
            "events.log",
            "modules.contract",
            "modules.importlib",
        ),
        "source": _replay_submission_deploy_source(),
        "function_name": "probe",
        "kwargs": {},
        "ignore_write_suffixes": ("__code__",),
    },
    {
        "id": "replay_imported_token_event_sequence",
        "description": "Imported token-like approval and transfer flows preserve state and event ordering like historical workloads.",
        "covers_features": (
            "events.log",
            "imports.static",
            "storage.hash",
        ),
        "dependencies": (
            {
                "name": "conformance_replay_token",
                "source": """
balances = Hash(default_value=0)
approvals = Hash(default_value=0)

ApproveEvent = LogEvent(
    "Approve",
    {
        "from": indexed(str),
        "to": indexed(str),
        "amount": int,
    },
)
TransferEvent = LogEvent(
    "Transfer",
    {
        "from": indexed(str),
        "to": indexed(str),
        "amount": int,
    },
)

@construct
def seed():
    balances["alice"] = 10

@export
def approve_for(owner: str, spender: str, amount: int):
    approvals[owner, spender] = amount
    ApproveEvent({"from": owner, "to": spender, "amount": amount})
    return approvals[owner, spender]

@export
def transfer_from_for(spender: str, main_account: str, to: str, amount: int):
    assert approvals[main_account, spender] >= amount
    assert balances[main_account] >= amount
    approvals[main_account, spender] -= amount
    balances[main_account] -= amount
    balances[to] += amount
    TransferEvent({"from": main_account, "to": to, "amount": amount})
    return {
        "allowance": approvals[main_account, spender],
        "main": balances[main_account],
        "to": balances[to],
    }
""",
            },
        ),
        "source": """
import conformance_replay_token

@export
def probe():
    approved = conformance_replay_token.approve_for(
        owner="alice",
        spender="broker",
        amount=4,
    )
    moved = conformance_replay_token.transfer_from_for(
        spender="broker",
        main_account="alice",
        to="vault",
        amount=3,
    )
    return {
        "approved": approved,
        "moved": moved,
    }
""",
        "function_name": "probe",
        "kwargs": {},
    },
)
