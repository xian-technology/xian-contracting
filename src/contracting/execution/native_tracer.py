from __future__ import annotations

import sys
import types

from contracting.execution.tracer_common import (
    CU_COSTS,
    CallLimitExceededError,
    StampExceededError,
)

TOOL_ID = sys.monitoring.PROFILER_ID

_NATIVE_IMPORT_ERROR: Exception | None = None

try:
    from xian_native_tracer import InstructionMeter
except ImportError as exc:  # pragma: no cover - exercised via selection path
    _NATIVE_IMPORT_ERROR = exc
    InstructionMeter = None


class NativeInstructionTracer:
    """Instruction-granular metering backed by a Rust extension."""

    __slots__ = (
        "_backend",
        "_instruction_callback",
        "_pending_codes",
        "_registered_codes",
    )

    def __init__(self) -> None:
        if _NATIVE_IMPORT_ERROR is not None:
            raise ImportError(
                "native tracer backend unavailable; install "
                "xian-native-tracer to use native_instruction_v1"
            ) from _NATIVE_IMPORT_ERROR

        self._backend = InstructionMeter(
            CU_COSTS,
            StampExceededError,
            CallLimitExceededError,
        )
        self._instruction_callback = self._backend.instruction_callback
        self._pending_codes: list[types.CodeType] = []
        self._registered_codes: set[int] = set()

    def start(self) -> None:
        self._backend.start()

        try:
            sys.monitoring.use_tool_id(TOOL_ID, "contracting_native_tracer")
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
        if not self._backend.is_started():
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

        self._backend.stop()

    def reset(self) -> None:
        self.stop()
        self._backend.reset()
        self._pending_codes.clear()
        self._registered_codes.clear()

    def register_code(self, code: types.CodeType) -> None:
        if not self.is_started():
            self._pending_codes.append(code)
            return

        self._enable_local_events(code)

    def _enable_local_events(self, code: types.CodeType) -> None:
        code_id = id(code)
        if code_id in self._registered_codes:
            return

        self._registered_codes.add(code_id)
        self._backend.register_code(code)
        sys.monitoring.set_local_events(
            TOOL_ID,
            code,
            sys.monitoring.events.INSTRUCTION,
        )

        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                self._enable_local_events(const)

    def set_stamp(self, stamp: int) -> None:
        self._backend.set_stamp(stamp)

    def add_cost(self, new_cost: int) -> None:
        self._backend.add_cost(new_cost)

    def get_stamp_used(self) -> int:
        return self._backend.get_stamp_used()

    def is_started(self) -> bool:
        return self._backend.is_started()
