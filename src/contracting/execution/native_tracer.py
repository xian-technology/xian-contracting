from __future__ import annotations

import sys
import types

from contracting.execution.tracer_common import (
    CU_COSTS,
    CallLimitExceededError,
    StampExceededError,
    get_tracer_policy,
)

TOOL_ID = sys.monitoring.PROFILER_ID
_POLICY = get_tracer_policy("native_instruction_v1")

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
        "_enabled_codes",
        "_known_codes",
    )

    def __init__(self) -> None:
        if _NATIVE_IMPORT_ERROR is not None:
            raise ImportError(
                "native tracer backend unavailable; install "
                "xian-native-tracer to use native_instruction_v1"
            ) from _NATIVE_IMPORT_ERROR

        self._backend = InstructionMeter(
            CU_COSTS,
            _POLICY.max_stamps,
            _POLICY.max_events,
            StampExceededError,
            CallLimitExceededError,
        )
        self._instruction_callback = self._backend.instruction_callback
        self._enabled_codes: set[int] = set()
        self._known_codes: dict[int, types.CodeType] = {}

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

        self._enabled_codes.clear()
        for code in self._known_codes.values():
            self._enable_local_events(code)

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
        self._enabled_codes.clear()

    def reset(self, *, clear_metadata: bool = True) -> None:
        self.stop()
        self._backend.reset(clear_metadata=clear_metadata)
        self._enabled_codes.clear()
        if clear_metadata:
            self._known_codes.clear()

    def register_code(self, code: types.CodeType) -> None:
        self._register_known_code(code)
        if self.is_started():
            self._enable_local_events(code)

    def _register_known_code(self, code: types.CodeType) -> None:
        code_id = id(code)
        if code_id in self._known_codes:
            return

        self._known_codes[code_id] = code
        self._backend.register_code(code)

        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                self._register_known_code(const)

    def _enable_local_events(self, code: types.CodeType) -> None:
        code_id = id(code)
        if code_id in self._enabled_codes:
            return

        self._enabled_codes.add(code_id)
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
