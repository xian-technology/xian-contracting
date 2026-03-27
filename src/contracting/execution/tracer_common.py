from __future__ import annotations

import opcode
import os
from dataclasses import dataclass

DEFAULT_COST = 4
MIN_OPCODE_COST = 2
MAX_STAMPS = 6_500_000

DEFAULT_TRACER_MODE = "python_line_v1"
SUPPORTED_TRACER_MODES = {
    "python_line_v1",
    "native_instruction_v1",
}


@dataclass(frozen=True, slots=True)
class TracerPolicy:
    mode: str
    max_stamps: int
    max_events: int
    event_name: str


TRACER_POLICIES: dict[str, TracerPolicy] = {
    "python_line_v1": TracerPolicy(
        mode="python_line_v1",
        max_stamps=MAX_STAMPS,
        max_events=800_000,
        event_name="line",
    ),
    "native_instruction_v1": TracerPolicy(
        mode="native_instruction_v1",
        max_stamps=MAX_STAMPS,
        max_events=MAX_STAMPS // MIN_OPCODE_COST,
        event_name="instruction",
    ),
}

# Preserve the historical export for the default tracer backend.
MAX_CALL_COUNT = TRACER_POLICIES[DEFAULT_TRACER_MODE].max_events


class StampExceededError(AssertionError):
    """Raised when the accumulated cost exceeds the stamp budget."""


class CallLimitExceededError(AssertionError):
    """Raised when execution exceeds the deterministic instruction budget."""


_EXACT_OPCODE_COSTS = {
    "CACHE": 2,
    "POP_TOP": 2,
    "PUSH_NULL": 2,
    "NOP": 2,
    "LOAD_ASSERTION_ERROR": 2,
    "LOAD_COMMON_CONSTANT": 2,
    "LOAD_CONST": 2,
    "LOAD_FAST": 2,
    "LOAD_FAST_AND_CLEAR": 2,
    "LOAD_FAST_BORROW": 2,
    "LOAD_FAST_BORROW_LOAD_FAST_BORROW": 2,
    "LOAD_FAST_CHECK": 2,
    "LOAD_FAST_LOAD_FAST": 2,
    "LOAD_SMALL_INT": 2,
    "RESUME": 2,
    "RETURN_VALUE": 2,
    "STORE_FAST": 2,
    "STORE_FAST_LOAD_FAST": 2,
    "STORE_FAST_MAYBE_NULL": 2,
    "STORE_FAST_STORE_FAST": 2,
    "BUILD_INTERPOLATION": 8,
    "BUILD_LIST": 8,
    "BUILD_MAP": 38,
    "BUILD_SET": 8,
    "BUILD_SLICE": 12,
    "BUILD_STRING": 6,
    "BUILD_TEMPLATE": 38,
    "BUILD_TUPLE": 8,
    "CALL": 1610,
    "CALL_FUNCTION_EX": 1000,
    "CALL_INTRINSIC_1": 126,
    "CALL_INTRINSIC_2": 126,
    "CALL_KW": 1000,
    "COMPARE_OP": 6,
    "CONTAINS_OP": 6,
    "CONVERT_VALUE": 6,
    "COPY": 2,
    "COPY_FREE_VARS": 2,
    "DICT_MERGE": 8,
    "DICT_UPDATE": 8,
    "END_FOR": 2,
    "END_SEND": 2,
    "FOR_ITER": 6,
    "FORMAT_SIMPLE": 6,
    "FORMAT_WITH_SPEC": 6,
    "FORMAT_VALUE": 6,
    "GET_ITER": 2,
    "GET_LEN": 2,
    "IMPORT_FROM": 38,
    "IMPORT_NAME": 126,
    "IMPORT_STAR": 126,
    "IS_OP": 6,
    "LIST_APPEND": 6,
    "LIST_EXTEND": 8,
    "LOAD_ATTR": 6,
    "LOAD_BUILD_CLASS": 1610,
    "LOAD_CLOSURE": 2,
    "LOAD_DEREF": 4,
    "LOAD_FROM_DICT_OR_DEREF": 4,
    "LOAD_FROM_DICT_OR_GLOBALS": 4,
    "LOAD_GLOBAL": 4,
    "LOAD_LOCALS": 2,
    "LOAD_NAME": 4,
    "LOAD_SPECIAL": 6,
    "LOAD_SUPER_ATTR": 6,
    "MAKE_FUNCTION": 12,
    "MAKE_CELL": 2,
    "MAP_ADD": 6,
    "NOT_TAKEN": 2,
    "JUMP": 6,
    "POP_BLOCK": 2,
    "POP_EXCEPT": 2,
    "POP_JUMP_IF_FALSE": 6,
    "POP_JUMP_IF_NONE": 6,
    "POP_JUMP_IF_NOT_NONE": 6,
    "POP_JUMP_IF_TRUE": 6,
    "POP_ITER": 2,
    "PUSH_EXC_INFO": 2,
    "RAISE_VARARGS": 126,
    "RERAISE": 126,
    "SETUP_ANNOTATIONS": 1000,
    "SET_ADD": 6,
    "SET_FUNCTION_ATTRIBUTE": 6,
    "SET_UPDATE": 8,
    "STORE_SLICE": 8,
    "STORE_SUBSCR": 6,
    "SWAP": 2,
    "TO_BOOL": 4,
    "UNPACK_EX": 12,
    "UNPACK_SEQUENCE": 8,
}

_PREFIX_OPCODE_COSTS = (
    ("INSTRUMENTED_", None),
    ("BINARY_", 6),
    ("DELETE_", 4),
    ("JUMP_", 6),
    ("LOAD_", 4),
    ("POP_JUMP", 6),
    ("STORE_", 4),
    ("UNARY_", 4),
)


def _opcode_cost(opname: str) -> int:
    if not opname or opname.startswith("<"):
        return DEFAULT_COST

    exact_cost = _EXACT_OPCODE_COSTS.get(opname)
    if exact_cost is not None:
        return exact_cost

    for prefix, cost in _PREFIX_OPCODE_COSTS:
        if opname.startswith(prefix):
            if prefix == "INSTRUMENTED_":
                return _opcode_cost(opname.removeprefix(prefix))
            return cost

    return DEFAULT_COST


def _is_explicitly_costed(opname: str) -> bool:
    if opname in _EXACT_OPCODE_COSTS:
        return True
    for prefix, _cost in _PREFIX_OPCODE_COSTS:
        if opname.startswith(prefix):
            return True
    return False


CU_COSTS = [_opcode_cost(opname) for opname in opcode.opname[:256]]
if len(CU_COSTS) < 256:
    CU_COSTS.extend([DEFAULT_COST] * (256 - len(CU_COSTS)))

APPROVED_DEFAULT_COST_OPCODES = frozenset(
    {
        "ANNOTATIONS_PLACEHOLDER",
        "BEFORE_ASYNC_WITH",
        "BEFORE_WITH",
        "BUILD_CONST_KEY_MAP",
        "CHECK_EG_MATCH",
        "CHECK_EXC_MATCH",
        "CLEANUP_THROW",
        "DELETE_ATTR",
        "DELETE_DEREF",
        "DELETE_FAST",
        "DELETE_GLOBAL",
        "DELETE_NAME",
        "DELETE_SUBSCR",
        "END_ASYNC_FOR",
        "ENTER_EXECUTOR",
        "EXIT_INIT_CHECK",
        "EXTENDED_ARG",
        "GET_AITER",
        "GET_ANEXT",
        "GET_AWAITABLE",
        "GET_YIELD_FROM_ITER",
        "INTERPRETER_EXIT",
        "INSTRUMENTED_END_ASYNC_FOR",
        "INSTRUMENTED_END_FOR",
        "INSTRUMENTED_END_SEND",
        "INSTRUMENTED_INSTRUCTION",
        "INSTRUMENTED_LINE",
        "INSTRUMENTED_NOT_TAKEN",
        "INSTRUMENTED_POP_ITER",
        "INSTRUMENTED_YIELD_VALUE",
        "KW_NAMES",
        "LOAD_DEREF",
        "LOAD_FROM_DICT_OR_DEREF",
        "LOAD_FROM_DICT_OR_GLOBALS",
        "LOAD_GLOBAL",
        "LOAD_NAME",
        "MATCH_CLASS",
        "MATCH_KEYS",
        "MATCH_MAPPING",
        "MATCH_SEQUENCE",
        "POP_JUMP_IF_NOT_NONE",
        "POP_JUMP_IF_NONE",
        "RESERVED",
        "RETURN_CONST",
        "RETURN_GENERATOR",
        "SEND",
        "SETUP_CLEANUP",
        "SETUP_FINALLY",
        "SETUP_WITH",
        "STORE_ATTR",
        "STORE_DEREF",
        "STORE_GLOBAL",
        "STORE_NAME",
        "UNARY_INVERT",
        "UNARY_NEGATIVE",
        "UNARY_NOT",
        "WITH_EXCEPT_START",
        "YIELD_VALUE",
    }
)


def get_default_cost_opcodes() -> list[str]:
    return sorted(
        opname
        for opname in opcode.opmap
        if _opcode_cost(opname) == DEFAULT_COST
        and not _is_explicitly_costed(opname)
    )


def get_uncategorized_default_cost_opcodes() -> list[str]:
    return sorted(
        opname
        for opname in get_default_cost_opcodes()
        if opname not in APPROVED_DEFAULT_COST_OPCODES
    )


def get_tracer_policy(mode: str | None = None) -> TracerPolicy:
    selected = resolve_tracer_mode(mode)
    return TRACER_POLICIES[selected]


def resolve_tracer_mode(mode: str | None = None) -> str:
    selected = mode or os.environ.get("XIAN_TRACER_MODE", DEFAULT_TRACER_MODE)
    if selected not in SUPPORTED_TRACER_MODES:
        raise ValueError(
            f"tracer mode must be one of {sorted(SUPPORTED_TRACER_MODES)}"
        )
    return selected
