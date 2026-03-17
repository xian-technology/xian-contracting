"""Deterministic contract execution metering.

This tracer uses ``sys.monitoring`` (PEP 669) to meter contract bytecode at
instruction granularity. Only code objects explicitly registered through
``register_code`` are charged, which keeps the rest of the Python runtime out
of the hot path and out of consensus accounting.
"""

from __future__ import annotations

import opcode
import sys
import types

TOOL_ID = sys.monitoring.PROFILER_ID

DEFAULT_COST = 4
MAX_STAMPS = 6_500_000
MAX_CALL_COUNT = 800_000
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


class Tracer:
    """Deterministic per-instruction metering engine."""

    __slots__ = (
        "cost",
        "stamp_supplied",
        "started",
        "call_count",
        "_pending_codes",
        "_registered_codes",
    )

    def __init__(self) -> None:
        self.cost = 0
        self.stamp_supplied = 0
        self.started = False
        self.call_count = 0
        self._pending_codes: list[types.CodeType] = []
        self._registered_codes: set[int] = set()

    def start(self) -> None:
        self.cost = 0
        self.call_count = 0
        self.started = True

        try:
            sys.monitoring.use_tool_id(TOOL_ID, "contracting_tracer")
        except ValueError:
            pass

        sys.monitoring.register_callback(
            TOOL_ID,
            sys.monitoring.events.INSTRUCTION,
            self._instruction_callback,
        )

        for code in self._pending_codes:
            self._enable_local_events(code)
        self._pending_codes.clear()

    def stop(self) -> None:
        if not self.started:
            return

        try:
            sys.monitoring.set_events(TOOL_ID, 0)
            sys.monitoring.register_callback(
                TOOL_ID,
                sys.monitoring.events.INSTRUCTION,
                None,
            )
            sys.monitoring.free_tool_id(TOOL_ID)
        except ValueError:
            pass

        self.started = False

    def reset(self) -> None:
        self.stop()
        self.cost = 0
        self.stamp_supplied = 0
        self.call_count = 0
        self._pending_codes.clear()
        self._registered_codes.clear()

    def register_code(self, code: types.CodeType) -> None:
        if not self.started:
            self._pending_codes.append(code)
            return

        self._enable_local_events(code)

    def _enable_local_events(self, code: types.CodeType) -> None:
        code_id = id(code)
        if code_id in self._registered_codes:
            return

        self._registered_codes.add(code_id)
        sys.monitoring.set_local_events(
            TOOL_ID,
            code,
            sys.monitoring.events.INSTRUCTION,
        )

        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                self._enable_local_events(const)

    def set_stamp(self, stamp: int) -> None:
        self.stamp_supplied = stamp

    def add_cost(self, new_cost: int) -> None:
        self.cost += new_cost
        if self.cost > self.stamp_supplied or self.cost > MAX_STAMPS:
            self.stop()
            raise StampExceededError(
                "The cost has exceeded the stamp supplied!"
            )

    def get_stamp_used(self) -> int:
        return self.cost

    def is_started(self) -> bool:
        return self.started

    def _instruction_callback(
        self,
        code: types.CodeType,
        offset: int,
    ) -> None:
        self.call_count += 1
        if self.call_count > MAX_CALL_COUNT:
            self.stop()
            raise CallLimitExceededError(
                "Call count exceeded threshold! Infinite Loop?"
            )

        self.cost += CU_COSTS[code.co_code[offset]]
        if self.cost > self.stamp_supplied or self.cost > MAX_STAMPS:
            self.stop()
            raise StampExceededError(
                "The cost has exceeded the stamp supplied!"
            )
