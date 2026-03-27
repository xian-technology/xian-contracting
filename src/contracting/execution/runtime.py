import sys
import threading
from collections.abc import MutableMapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

from contracting import constants
from contracting.execution.tracer import (
    DEFAULT_TRACER_MODE,
    create_tracer,
    resolve_tracer_mode,
)

DEFAULT_BASE_STATE = {
    "this": None,
    "caller": None,
    "owner": None,
    "signer": None,
    "entry": None,
    "submission_name": None,
}


class Context:
    def __init__(self, base_state, maxlen=constants.RECURSION_LIMIT):
        self._state = []
        self._depth = []
        self._base_state = base_state
        self._maxlen = maxlen

    def _context_changed(self, contract):
        if self._get_state()["this"] == contract:
            return False
        return True

    def _get_state(self):
        if len(self._state) == 0:
            return self._base_state
        return self._state[-1]

    def _add_state(self, state: dict):
        if not self._context_changed(state["this"]):
            return False

        if len(self._state) >= self._maxlen:
            raise RecursionError("Maximum contract call depth exceeded.")

        self._state.append(state)
        self._depth.append(1)
        return True

    def _ins_state(self):
        if len(self._depth) > 0:
            self._depth[-1] += 1

    def _pop_state(self):
        if len(self._state) > 0:
            self._depth[-1] -= 1
            if self._depth[-1] == 0:
                self._state.pop(-1)
                self._depth.pop(-1)

    def _reset(self):
        self._state = []
        self._depth = []

    @property
    def this(self):
        return self._get_state()["this"]

    @property
    def caller(self):
        return self._get_state()["caller"]

    @property
    def signer(self):
        return self._get_state()["signer"]

    @property
    def owner(self):
        return self._get_state()["owner"]

    @property
    def entry(self):
        return self._get_state()["entry"]

    @property
    def submission_name(self):
        return self._get_state()["submission_name"]


class ContextProxy:
    def __init__(self, runtime):
        super().__setattr__("_runtime", runtime)

    def _target(self):
        return self._runtime._state().context

    def __getattr__(self, item):
        return getattr(self._target(), item)

    def __setattr__(self, key, value):
        setattr(self._target(), key, value)


class EnvProxy(MutableMapping):
    def __init__(self, runtime):
        self._runtime = runtime

    def _mapping(self):
        return self._runtime._state().env

    def __getitem__(self, key):
        return self._mapping()[key]

    def __setitem__(self, key, value):
        self._mapping()[key] = value

    def __delitem__(self, key):
        del self._mapping()[key]

    def __iter__(self):
        return iter(self._mapping())

    def __len__(self):
        return len(self._mapping())


@dataclass
class RuntimeState:
    tracer_mode: str
    tracer: object
    env: dict = field(default_factory=dict)
    stamps: int = 0
    writes: int = 0
    signer: str | None = None
    loaded_modules: list[str] = field(default_factory=list)
    contract_meter_frames: list[dict[str, int | str]] = field(
        default_factory=list
    )
    contract_meter_markers: list[bool] = field(default_factory=list)
    contract_costs: dict[str, int] = field(default_factory=dict)
    context: Context = field(
        default_factory=lambda: Context(dict(DEFAULT_BASE_STATE))
    )


WRITE_MAX = 1024 * 128


class Runtime:
    def __init__(self):
        self.execution_lock = threading.RLock()
        self._default_tracer_mode = DEFAULT_TRACER_MODE
        self._state_var: ContextVar[RuntimeState | None] = ContextVar(
            "contracting_runtime_state",
            default=None,
        )
        self._context_proxy = ContextProxy(self)
        self._env_proxy = EnvProxy(self)

    def _new_state(self, tracer_mode: str | None = None) -> RuntimeState:
        selected = resolve_tracer_mode(tracer_mode or self._default_tracer_mode)
        return RuntimeState(
            tracer_mode=selected,
            tracer=create_tracer(selected),
        )

    def _state(self) -> RuntimeState:
        state = self._state_var.get()
        if state is None:
            state = self._new_state()
            self._state_var.set(state)
        return state

    @property
    def env(self):
        return self._env_proxy

    @env.setter
    def env(self, value):
        self._state().env = dict(value)

    @property
    def tracer(self):
        return self._state().tracer

    @property
    def tracer_mode(self):
        return self._state().tracer_mode

    @property
    def signer(self):
        return self._state().signer

    @signer.setter
    def signer(self, value):
        self._state().signer = value

    @property
    def stamps(self):
        return self._state().stamps

    @stamps.setter
    def stamps(self, value):
        self._state().stamps = value

    @property
    def writes(self):
        return self._state().writes

    @writes.setter
    def writes(self, value):
        self._state().writes = value

    @property
    def loaded_modules(self):
        return self._state().loaded_modules

    @loaded_modules.setter
    def loaded_modules(self, value):
        self._state().loaded_modules = list(value)

    @property
    def context(self):
        return self._context_proxy

    @context.setter
    def context(self, value):
        self._state().context = value

    def set_tracer_mode(self, mode: str) -> None:
        state = self._state()
        selected = resolve_tracer_mode(mode)
        if state.tracer.is_started():
            raise RuntimeError(
                "cannot switch tracer mode during active execution"
            )

        state.tracer.reset()
        state.tracer_mode = selected
        state.tracer = create_tracer(selected)
        self._default_tracer_mode = selected

    def _reset_execution_state(
        self,
        state: RuntimeState,
        *,
        preserve_tracer_metadata: bool,
        preserve_context_base_state: bool,
        preserve_env: bool,
    ) -> None:
        state.tracer.reset(clear_metadata=not preserve_tracer_metadata)
        env = dict(state.env) if preserve_env else {}
        state.env = env
        state.stamps = 0
        state.writes = 0
        state.signer = None
        state.loaded_modules = []
        state.contract_meter_frames = []
        state.contract_meter_markers = []
        state.contract_costs = {}
        if preserve_context_base_state:
            base_state = dict(state.context._base_state)
        else:
            base_state = dict(DEFAULT_BASE_STATE)
        state.context = Context(base_state)

    def set_up(self, stmps, meter):
        state = self._state()
        self._reset_execution_state(
            state,
            preserve_tracer_metadata=True,
            preserve_context_base_state=True,
            preserve_env=True,
        )

        if meter:
            state.stamps = stmps
            state.tracer.set_stamp(stmps)
            state.tracer.start()

    def clean_up(self):
        state = self._state()

        state.tracer.stop()

        for mod in state.loaded_modules:
            if sys.modules.get(mod) is not None:
                del sys.modules[mod]

        self._reset_execution_state(
            state,
            preserve_tracer_metadata=True,
            preserve_context_base_state=False,
            preserve_env=False,
        )

    def deduct_read(self, key, value):
        if self.tracer.is_started():
            cost = len(key) + len(value)
            cost *= constants.READ_COST_PER_BYTE
            self.tracer.add_cost(cost)

    def deduct_write(self, key, value):
        if key is not None and self.tracer.is_started():
            cost = len(key) + len(value)
            self.writes += cost
            assert self.writes < WRITE_MAX, (
                "You have exceeded the maximum write capacity per transaction!"
            )

            stamp_cost = cost * constants.WRITE_COST_PER_BYTE
            self.tracer.add_cost(stamp_cost)

    def deduct_return_value(self, value):
        if not self.tracer.is_started():
            return

        from xian_runtime_types.encoding import encode

        encoded = encode(value).encode("utf-8")
        size = len(encoded)
        assert size <= constants.MAX_RETURN_VALUE_SIZE, (
            "Return value exceeds the maximum allowed size."
        )
        self.tracer.add_cost(size * constants.RETURN_VALUE_COST_PER_BYTE)

    def deduct_execution_cost(self, cost: int):
        if cost <= 0 or not self.tracer.is_started():
            return
        self.tracer.add_cost(cost)

    @contextmanager
    def push_context_state(self, state: dict):
        added = self.context._add_state(state)
        if not added:
            self.context._ins_state()
        try:
            yield
        finally:
            self.context._pop_state()

    def begin_contract_metering(self, contract: str) -> None:
        state = self._state()
        state.contract_meter_frames = [
            {
                "contract": contract,
                "start_cost": self.tracer.get_stamp_used(),
                "child_cost": 0,
            }
        ]
        state.contract_meter_markers = []
        state.contract_costs = {}

    def enter_contract_metering(self, contract: str) -> None:
        state = self._state()
        if not state.contract_meter_frames:
            state.contract_meter_frames.append(
                {
                    "contract": contract,
                    "start_cost": self.tracer.get_stamp_used(),
                    "child_cost": 0,
                }
            )
            state.contract_meter_markers.append(True)
            return

        pushed = state.contract_meter_frames[-1]["contract"] != contract
        if pushed:
            state.contract_meter_frames.append(
                {
                    "contract": contract,
                    "start_cost": self.tracer.get_stamp_used(),
                    "child_cost": 0,
                }
            )
        state.contract_meter_markers.append(pushed)

    def exit_contract_metering(self) -> None:
        state = self._state()
        if not state.contract_meter_markers:
            return
        if state.contract_meter_markers.pop():
            self._finalize_contract_meter_frame()

    def _finalize_contract_meter_frame(self) -> None:
        state = self._state()
        if not state.contract_meter_frames:
            return

        frame = state.contract_meter_frames.pop()
        current_cost = self.tracer.get_stamp_used()
        total_cost = max(current_cost - int(frame["start_cost"]), 0)
        exclusive_cost = max(total_cost - int(frame["child_cost"]), 0)
        contract = str(frame["contract"])
        state.contract_costs[contract] = (
            state.contract_costs.get(contract, 0) + exclusive_cost
        )

        if state.contract_meter_frames:
            parent = state.contract_meter_frames[-1]
            parent["child_cost"] = int(parent["child_cost"]) + total_cost

    def finalize_contract_metering(
        self,
        *,
        fixed_overhead_contract: str | None = None,
        fixed_overhead_units: int = 0,
    ) -> dict[str, int]:
        state = self._state()
        while state.contract_meter_frames:
            self._finalize_contract_meter_frame()

        if (
            fixed_overhead_contract is not None
            and fixed_overhead_units > 0
        ):
            state.contract_costs[fixed_overhead_contract] = (
                state.contract_costs.get(fixed_overhead_contract, 0)
                + fixed_overhead_units
            )

        result = dict(state.contract_costs)
        state.contract_meter_markers = []
        state.contract_costs = {}
        return result


rt = Runtime()
