import sys

from contracting import constants
from contracting.execution.tracer import (
    DEFAULT_TRACER_MODE,
    create_tracer,
    resolve_tracer_mode,
)


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
        if (
            self._context_changed(state["this"])
            and len(self._state) < self._maxlen
        ):
            self._state.append(state)
            self._depth.append(1)

    def _ins_state(self):
        if len(self._depth) > 0:
            self._depth[-1] += 1

    def _pop_state(self):
        if (
            len(self._state) > 0
        ):  # len(self._state) should equal len(self._depth)
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


_context = Context(
    {
        "this": None,
        "caller": None,
        "owner": None,
        "signer": None,
        "entry": None,
        "submission_name": None,
    }
)

WRITE_MAX = 1024 * 128


class Runtime:
    loaded_modules = []

    env = {}
    stamps = 0

    writes = 0

    tracer_mode = DEFAULT_TRACER_MODE
    tracer = create_tracer(DEFAULT_TRACER_MODE)

    signer = None

    context = _context

    @classmethod
    def set_tracer_mode(cls, mode: str) -> None:
        selected = resolve_tracer_mode(mode)
        if cls.tracer.is_started():
            raise RuntimeError(
                "cannot switch tracer mode during active execution"
            )

        cls.tracer.reset()
        cls.tracer = create_tracer(selected)
        cls.tracer_mode = selected

    @classmethod
    def set_up(cls, stmps, meter):
        if meter:
            cls.stamps = stmps
            cls.tracer.set_stamp(stmps)
            cls.tracer.start()

        cls.context._reset()

    @classmethod
    def clean_up(cls):
        cls.tracer.stop()
        cls.tracer.reset()
        cls.stamps = 0
        cls.writes = 0

        cls.signer = None

        for mod in cls.loaded_modules:
            if sys.modules.get(mod) is not None:
                del sys.modules[mod]

        cls.loaded_modules = []
        cls.env = {}

    @classmethod
    def deduct_read(cls, key, value):
        if cls.tracer.is_started():
            cost = len(key) + len(value)
            cost *= constants.READ_COST_PER_BYTE
            cls.tracer.add_cost(cost)

    @classmethod
    def deduct_write(cls, key, value):
        if key is not None and cls.tracer.is_started():
            cost = len(key) + len(value)
            cls.writes += cost
            assert cls.writes < WRITE_MAX, (
                "You have exceeded the maximum write capacity per transaction!"
            )

            stamp_cost = cost * constants.WRITE_COST_PER_BYTE
            cls.tracer.add_cost(stamp_cost)

    @classmethod
    def deduct_return_value(cls, value):
        if not cls.tracer.is_started():
            return

        from xian_runtime_types.encoding import encode

        encoded = encode(value).encode("utf-8")
        size = len(encoded)
        assert size <= constants.MAX_RETURN_VALUE_SIZE, (
            "Return value exceeds the maximum allowed size."
        )
        cls.tracer.add_cost(size * constants.RETURN_VALUE_COST_PER_BYTE)


rt = Runtime()
