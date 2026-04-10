from __future__ import annotations

from contracting.execution import tracer_common as common
from contracting.execution.python_tracer import PythonLineTracer

CU_COSTS = common.CU_COSTS
DEFAULT_TRACER_MODE = common.DEFAULT_TRACER_MODE
DEFAULT_COST = common.DEFAULT_COST
MAX_CALL_COUNT = common.MAX_CALL_COUNT
MAX_CHI = common.MAX_CHI
MIN_OPCODE_COST = common.MIN_OPCODE_COST
SUPPORTED_TRACER_MODES = common.SUPPORTED_TRACER_MODES
TRACER_POLICIES = common.TRACER_POLICIES
CallLimitExceededError = common.CallLimitExceededError
ChiExceededError = common.ChiExceededError
get_default_cost_opcodes = common.get_default_cost_opcodes
get_tracer_policy = common.get_tracer_policy
get_uncategorized_default_cost_opcodes = (
    common.get_uncategorized_default_cost_opcodes
)
resolve_tracer_mode = common.resolve_tracer_mode


def create_tracer(mode: str | None = None):
    selected = resolve_tracer_mode(mode)
    if selected == "python_line_v1":
        return PythonLineTracer()
    if selected == "native_instruction_v1":
        from contracting.execution.native_tracer import (
            NativeInstructionTracer,
        )

        return NativeInstructionTracer()
    raise ValueError(f"unsupported tracer mode: {selected}")


Tracer = PythonLineTracer

__all__ = [
    "CU_COSTS",
    "DEFAULT_COST",
    "DEFAULT_TRACER_MODE",
    "MAX_CALL_COUNT",
    "MAX_CHI",
    "MIN_OPCODE_COST",
    "SUPPORTED_TRACER_MODES",
    "TRACER_POLICIES",
    "CallLimitExceededError",
    "ChiExceededError",
    "PythonLineTracer",
    "Tracer",
    "create_tracer",
    "get_default_cost_opcodes",
    "get_tracer_policy",
    "get_uncategorized_default_cost_opcodes",
    "resolve_tracer_mode",
]
