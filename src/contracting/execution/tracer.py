from __future__ import annotations

from contracting.execution import tracer_common as common
from contracting.execution.python_tracer import PythonLineTracer

CU_COSTS = common.CU_COSTS
DEFAULT_TRACER_MODE = common.DEFAULT_TRACER_MODE
MAX_CALL_COUNT = common.MAX_CALL_COUNT
MAX_STAMPS = common.MAX_STAMPS
SUPPORTED_TRACER_MODES = common.SUPPORTED_TRACER_MODES
CallLimitExceededError = common.CallLimitExceededError
StampExceededError = common.StampExceededError
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
    "DEFAULT_TRACER_MODE",
    "MAX_CALL_COUNT",
    "MAX_STAMPS",
    "SUPPORTED_TRACER_MODES",
    "CallLimitExceededError",
    "StampExceededError",
    "PythonLineTracer",
    "Tracer",
    "create_tracer",
    "resolve_tracer_mode",
]
