from __future__ import annotations

import opcode
import os

DEFAULT_COST = 4
MAX_STAMPS = 6_500_000
MAX_CALL_COUNT = 800_000

DEFAULT_TRACER_MODE = "python_line_v1"
SUPPORTED_TRACER_MODES = {
    "python_line_v1",
    "native_instruction_v1",
}


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
    "FOR_ITER": 6,
    "FORMAT_VALUE": 6,
    "GET_ITER": 2,
    "GET_LEN": 2,
    "IMPORT_FROM": 38,
    "IMPORT_NAME": 126,
    "IMPORT_STAR": 126,
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
    "MAP_ADD": 6,
    "POP_JUMP_IF_FALSE": 6,
    "POP_JUMP_IF_NONE": 6,
    "POP_JUMP_IF_NOT_NONE": 6,
    "POP_JUMP_IF_TRUE": 6,
    "RAISE_VARARGS": 126,
    "SETUP_ANNOTATIONS": 1000,
    "SET_ADD": 6,
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


CU_COSTS = [_opcode_cost(opname) for opname in opcode.opname[:256]]
if len(CU_COSTS) < 256:
    CU_COSTS.extend([DEFAULT_COST] * (256 - len(CU_COSTS)))


def resolve_tracer_mode(mode: str | None = None) -> str:
    selected = mode or os.environ.get("XIAN_TRACER_MODE", DEFAULT_TRACER_MODE)
    if selected not in SUPPORTED_TRACER_MODES:
        raise ValueError(
            f"tracer mode must be one of {sorted(SUPPORTED_TRACER_MODES)}"
        )
    return selected
