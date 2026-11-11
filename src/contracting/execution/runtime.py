"""Context-local metadata shared by trusted native host helpers."""

import threading
from collections.abc import MutableMapping
from contextvars import ContextVar
from dataclasses import dataclass, field

DEFAULT_BASE_STATE = {
    "this": None,
    "caller": None,
    "owner": None,
    "signer": None,
    "entry": None,
    "submission_name": None,
}


class Context:
    """Explicit metadata for trusted host helpers."""

    def __init__(self, base_state):
        self._base_state = base_state

    def _get_state(self):
        return self._base_state

    @property
    def this(self):
        return self._base_state["this"]

    @property
    def caller(self):
        return self._base_state["caller"]

    @property
    def signer(self):
        return self._base_state["signer"]

    @property
    def owner(self):
        return self._base_state["owner"]

    @property
    def entry(self):
        return self._base_state["entry"]

    @property
    def submission_name(self):
        return self._base_state["submission_name"]


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
    env: dict = field(default_factory=dict)
    context: Context = field(default_factory=lambda: Context(dict(DEFAULT_BASE_STATE)))


WRITE_MAX = 1024 * 128


class Runtime:
    """Context-local host state shared by native execution and trusted helpers."""

    def __init__(self):
        self.execution_lock = threading.RLock()
        self._state_var: ContextVar[RuntimeState | None] = ContextVar(
            "contracting_runtime_state",
            default=None,
        )
        self._context_proxy = ContextProxy(self)
        self._env_proxy = EnvProxy(self)

    def _state(self) -> RuntimeState:
        state = self._state_var.get()
        if state is None:
            state = RuntimeState()
            self._state_var.set(state)
        return state

    @property
    def env(self):
        return self._env_proxy

    @env.setter
    def env(self, value):
        self._state().env = dict(value)

    @property
    def context(self):
        return self._context_proxy

    @context.setter
    def context(self, value):
        self._state().context = value


rt = Runtime()
