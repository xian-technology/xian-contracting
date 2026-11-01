"""Inert metadata used by contract-local interface predicates."""

import gc
from collections.abc import Iterator
from itertools import chain
from types import FunctionType, MappingProxyType, MethodType

_SUBJECT_TOKEN = object()


class InterfaceSubject:
    __slots__ = ("kind", "name", "args", "storage_type")

    def __init__(self, kind, name, args=None, storage_type=None, *, _token=None):
        from contracting.execution.runtime import _contract_execution_active

        if _contract_execution_active.get() and _token is not _SUBJECT_TOKEN:
            raise TypeError("InterfaceSubject has no public constructor")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "args", args)
        object.__setattr__(self, "storage_type", storage_type)

    def __setattr__(self, name, value):
        raise TypeError("InterfaceSubject is read-only")

    def __delattr__(self, name):
        raise TypeError("InterfaceSubject is read-only")

    def __repr__(self):
        return "<InterfaceSubject>"


def _closure_values(function):
    for cell in function.__closure__ or ():
        try:
            yield cell.cell_contents
        except ValueError:
            continue


def _children(value):
    if isinstance(value, dict):
        return (item for pair in value.items() for item in pair)
    if isinstance(value, (list, tuple, set, frozenset)):
        return iter(value)
    if isinstance(
        value, (Iterator, MappingProxyType, type({}.keys()), type({}.values()), type({}.items()))
    ):
        return gc.get_referents(value)
    return _object_children(value)


def _object_children(value):
    if isinstance(value, FunctionType):
        return chain(
            _closure_values(value), value.__defaults__ or (), (value.__kwdefaults__ or {}).values()
        )
    if isinstance(value, MethodType):
        return (value.__self__, value.__func__)
    if isinstance(value, BaseException):
        return value.args
    from contracting.stdlib.bridge.imports import Func, Var

    if isinstance(value, (Func, Var)):
        return vars(value).values()
    return ()


def _reject_subject(value, boundary):
    if isinstance(value, InterfaceSubject) or value is InterfaceSubject:
        raise TypeError(f"interface subjects cannot cross {boundary}")


def ensure_no_interface_subject(value, boundary="contract boundaries"):
    ensure_no_interface_subjects((value,), boundary)


def ensure_no_interface_subjects(values, boundary="contract boundaries"):
    """Check roots at depth zero without walking ambient function globals."""
    pending = [iter(values)]
    seen = set()
    nodes = 0
    while pending:
        try:
            current = next(pending[-1])
        except StopIteration:
            pending.pop()
            continue
        nodes += 1
        if nodes > 131072 or len(pending) > 129:
            raise ValueError("interface subject traversal limit exceeded")
        _reject_subject(current, boundary)
        if current is None or isinstance(current, (str, bytes, bytearray, int, float, bool, type)):
            continue
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        pending.append(iter(_children(current)))


def _storage_family(value):
    from contracting.stdlib.bridge.orm import exports

    for name in ("ForeignHash", "ForeignVariable", "Hash", "Variable", "LogEvent"):
        if isinstance(value, exports[name]):
            return name
    raise TypeError("unsupported interface storage family")


def charge_subject_match(subject):
    from contracting.execution.runtime import rt

    work = len(subject.name.encode()) + len((subject.storage_type or "").encode()) + 1
    if subject.args is not None:
        work += sum(len(arg.encode()) + 1 for arg in subject.args)
    rt.deduct_execution_cost(work)


def storage_subject_matches(subject, expected):
    if subject.kind != "storage":
        return False
    from contracting.stdlib.bridge.orm import exports

    return issubclass(exports[subject.storage_type], expected)


def make_interface_subject(attribute, name):
    from contracting.execution.runtime import rt
    from contracting.stdlib.bridge.imports import extract_closure

    if isinstance(attribute, FunctionType):
        function = extract_closure(attribute)
        code = function.__code__
        parameters = code.co_varnames[: code.co_argcount]
        work = len(code.co_name.encode()) + 1 + sum(len(arg.encode()) + 1 for arg in parameters)
        rt.deduct_execution_cost(work + len(name.encode()) + 4)
        return InterfaceSubject("function", code.co_name, parameters, _token=_SUBJECT_TOKEN)
    family = _storage_family(attribute)
    rt.deduct_execution_cost(len(family.encode()) + 1 + len(name.encode()) + 4)
    return InterfaceSubject("storage", name, storage_type=family, _token=_SUBJECT_TOKEN)
