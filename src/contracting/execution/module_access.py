"""Contract imports expose public callable aliases, never foreign object graphs."""

import json
from functools import lru_cache
from pathlib import Path
from types import BuiltinFunctionType, FunctionType, MethodType, ModuleType

from contracting.compilation.ir import HOST_BINDINGS
from contracting.execution.format_policy import format_attribute
from contracting.execution.runtime import _contract_execution_active
from contracting.execution.sandbox import build_contract_builtins
from contracting.stdlib import env

_REJECTION = "module attribute is not an admitted public callable"
_STORAGE_CLASSES = frozenset({"Variable", "Hash", "ForeignVariable", "ForeignHash", "LogEvent"})
_CLASS_METHODS = json.loads(Path(__file__).with_name("public_callable_methods.json").read_text())


def _resolve(namespace, binding):
    value = namespace
    for part in binding.split("."):
        value = value[part] if isinstance(value, dict) else getattr(value, part)
    return value


def _host_functions(namespace):
    for spec in HOST_BINDINGS:
        binding = spec["binding"]
        if binding.split(".")[0] in _STORAGE_CLASSES:
            continue
        try:
            value = _resolve(namespace, binding)
        except (KeyError, AttributeError):
            continue
        if callable(value):
            yield value


def _class_functions(namespace):
    for binding, methods in _CLASS_METHODS.items():
        cls = _resolve(namespace, binding)
        for name in methods:
            yield format_attribute(cls, name)


@lru_cache(maxsize=1)
def _admitted_objects():
    namespace = build_contract_builtins(None)
    namespace.update(env.gather())
    functions = [
        value
        for name, value in namespace.items()
        if not name.startswith("_")
        and name not in _STORAGE_CLASSES
        and name not in {"rt", "ctx"}
        and callable(value)
    ]
    functions.extend(_host_functions(namespace))
    functions.extend(_class_functions(namespace))
    return tuple(functions)


def _same_callable(value, candidate):
    if value is candidate:
        return True
    if isinstance(value, MethodType) and isinstance(candidate, MethodType):
        return value.__self__ is candidate.__self__ and value.__func__ is candidate.__func__
    if isinstance(value, BuiltinFunctionType) and isinstance(candidate, BuiltinFunctionType):
        return value == candidate
    return False


def _exported_alias(value):
    if not isinstance(value, FunctionType):
        return False
    from contracting.stdlib.bridge.imports import _unwrap_exported_function

    try:
        _unwrap_exported_function(value)
    except AssertionError:
        return False
    return True


def admitted_public_callable(value):
    functions = _admitted_objects()
    return any(_same_callable(value, candidate) for candidate in functions) or _exported_alias(
        value
    )


def initialize_public_callable_catalog():
    # Snapshot trusted bridge identities before any contract module code runs.
    _admitted_objects()


class ContractModule(ModuleType):
    def __getattribute__(self, name):
        value = super().__getattribute__(name)
        if name.startswith("_") or not _contract_execution_active.get():
            return value
        if name.endswith("_") or not admitted_public_callable(value):
            raise AttributeError(_REJECTION)
        return value

    def __setattr__(self, name, value):
        if not name.startswith("_") and _contract_execution_active.get():
            raise AttributeError("imported module attributes are read-only")
        super().__setattr__(name, value)

    def __delattr__(self, name):
        if not name.startswith("_") and _contract_execution_active.get():
            raise AttributeError("imported module attributes are read-only")
        super().__delattr__(name)
