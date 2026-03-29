"""Deterministic contract execution metering.

This tracer uses ``sys.monitoring`` (PEP 669) to meter registered contract
bytecode at line granularity using precomputed per-line bytecode costs. That
keeps consensus accounting deterministic without paying the runtime cost of a
Python callback for every single instruction.
"""

from __future__ import annotations

import dis
import sys
import types

from contracting.execution.tracer_common import (
    DEFAULT_COST,
    CallLimitExceededError,
    StampExceededError,
    _opcode_cost,
    get_tracer_policy,
)

TOOL_ID = sys.monitoring.PROFILER_ID
_POLICY = get_tracer_policy("python_line_v1")


def _instruction_line_number(instruction: dis.Instruction) -> int | None:
    positions = instruction.positions
    if positions is not None:
        lineno = getattr(positions, "lineno", None)
        if isinstance(lineno, int) and lineno > 0:
            return lineno

    starts_line = instruction.starts_line
    if isinstance(starts_line, int) and not isinstance(starts_line, bool):
        if starts_line > 0:
            return starts_line

    return None


class PythonLineTracer:
    """Deterministic per-line metering engine."""

    __slots__ = (
        "cost",
        "stamp_supplied",
        "started",
        "call_count",
        "_enabled_codes",
        "_known_codes",
        "_line_costs",
        "_max_events",
        "_max_stamps",
    )

    def __init__(self) -> None:
        self.cost = 0
        self.stamp_supplied = 0
        self.started = False
        self.call_count = 0
        self._enabled_codes: set[int] = set()
        self._known_codes: dict[int, types.CodeType] = {}
        self._line_costs: dict[int, dict[int, int]] = {}
        self._max_events = _POLICY.max_events
        self._max_stamps = _POLICY.max_stamps

    def start(self) -> None:
        self.cost = 0
        self.call_count = 0
        self.started = True

        try:
            sys.monitoring.use_tool_id(TOOL_ID, "contracting_python_tracer")
        except ValueError:
            pass

        sys.monitoring.register_callback(
            TOOL_ID,
            sys.monitoring.events.LINE,
            self._line_callback,
        )

        self._enabled_codes.clear()
        for code in self._known_codes.values():
            self._enable_local_events(code)

    def stop(self) -> None:
        if not self.started:
            return

        try:
            sys.monitoring.set_events(TOOL_ID, 0)
            sys.monitoring.register_callback(
                TOOL_ID,
                sys.monitoring.events.LINE,
                None,
            )
            sys.monitoring.free_tool_id(TOOL_ID)
        except ValueError:
            pass

        self.started = False
        self._enabled_codes.clear()

    def reset(self, *, clear_metadata: bool = True) -> None:
        self.stop()
        self.cost = 0
        self.stamp_supplied = 0
        self.call_count = 0
        self._enabled_codes.clear()
        if clear_metadata:
            self._known_codes.clear()
            self._line_costs.clear()

    def register_code(self, code: types.CodeType) -> None:
        code_id = id(code)
        self._known_codes.setdefault(code_id, code)
        if self.started:
            self._enable_local_events(code)

    def _enable_local_events(self, code: types.CodeType) -> None:
        code_id = id(code)
        if code_id in self._enabled_codes:
            return

        self._enabled_codes.add(code_id)
        sys.monitoring.set_local_events(
            TOOL_ID,
            code,
            sys.monitoring.events.LINE,
        )

        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                self._enable_local_events(const)

    def set_stamp(self, stamp: int) -> None:
        self.stamp_supplied = stamp

    def add_cost(self, new_cost: int) -> None:
        self.cost += new_cost
        if self.cost > self.stamp_supplied or self.cost > self._max_stamps:
            self.stop()
            raise StampExceededError(
                "The cost has exceeded the stamp supplied!"
            )

    def get_stamp_used(self) -> int:
        return self.cost

    def is_started(self) -> bool:
        return self.started

    def _line_callback(
        self,
        code: types.CodeType,
        line_number: int,
    ) -> None:
        self.call_count += 1
        if self.call_count > self._max_events:
            self.stop()
            raise CallLimitExceededError(
                "Call count exceeded threshold! Infinite Loop?"
            )

        self.cost += self._line_cost(code, line_number)
        if self.cost > self.stamp_supplied or self.cost > self._max_stamps:
            self.stop()
            raise StampExceededError(
                "The cost has exceeded the stamp supplied!"
            )

    def _line_cost(self, code: types.CodeType, line_number: int) -> int:
        code_id = id(code)
        line_costs = self._line_costs.get(code_id)
        if line_costs is None:
            line_costs = {}
            for instruction in dis.get_instructions(code):
                lineno = _instruction_line_number(instruction)
                if lineno is None:
                    continue
                line_costs[lineno] = line_costs.get(lineno, 0) + _opcode_cost(
                    instruction.opname
                )
            self._line_costs[code_id] = line_costs

        return line_costs.get(line_number, DEFAULT_COST)
