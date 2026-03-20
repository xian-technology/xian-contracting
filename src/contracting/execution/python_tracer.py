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
    MAX_CALL_COUNT,
    MAX_STAMPS,
    CallLimitExceededError,
    StampExceededError,
    _opcode_cost,
)

TOOL_ID = sys.monitoring.PROFILER_ID


class PythonLineTracer:
    """Deterministic per-line metering engine."""

    __slots__ = (
        "cost",
        "stamp_supplied",
        "started",
        "call_count",
        "_pending_codes",
        "_registered_codes",
        "_line_costs",
    )

    def __init__(self) -> None:
        self.cost = 0
        self.stamp_supplied = 0
        self.started = False
        self.call_count = 0
        self._pending_codes: list[types.CodeType] = []
        self._registered_codes: set[int] = set()
        self._line_costs: dict[int, dict[int, int]] = {}

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
                sys.monitoring.events.LINE,
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
        self._line_costs.clear()

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
            sys.monitoring.events.LINE,
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

    def _line_callback(
        self,
        code: types.CodeType,
        line_number: int,
    ) -> None:
        self.call_count += 1
        if self.call_count > MAX_CALL_COUNT:
            self.stop()
            raise CallLimitExceededError(
                "Call count exceeded threshold! Infinite Loop?"
            )

        self.cost += self._line_cost(code, line_number)
        if self.cost > self.stamp_supplied or self.cost > MAX_STAMPS:
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
                lineno = instruction.starts_line
                if instruction.positions is not None:
                    lineno = instruction.positions.lineno or lineno
                if lineno is None:
                    continue
                line_costs[lineno] = line_costs.get(lineno, 0) + _opcode_cost(
                    instruction.opname
                )
            self._line_costs[code_id] = line_costs

        return line_costs.get(line_number, DEFAULT_COST)
