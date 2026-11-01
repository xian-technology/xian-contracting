"""Subject boundary walks are bounded, inert, and preserve ordinary value limits."""

import builtins
from types import MappingProxyType

import pytest
from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet

from contracting.execution.interface_subject import (
    InterfaceSubject,
    ensure_no_interface_subject,
    ensure_no_interface_subjects,
)


def subject():
    return InterfaceSubject("function", "probe", ("value",))


def test_subject_free_graph_keeps_native_node_ceiling():
    ensure_no_interface_subject([None] * 131071)
    with pytest.raises(ValueError, match="traversal limit"):
        ensure_no_interface_subject([None] * 131072)


def test_subject_free_graph_keeps_native_depth_ceiling_and_cycles():
    value = None
    for _ in range(128):
        value = [value]
    ensure_no_interface_subject(value)
    with pytest.raises(ValueError, match="traversal limit"):
        ensure_no_interface_subject([value])
    cycle = []
    cycle.append(cycle)
    ensure_no_interface_subject(cycle)


def test_multiple_roots_share_native_node_budget_without_wrapper_nodes():
    ensure_no_interface_subjects(([None] * 65535, [None] * 65535))
    with pytest.raises(ValueError, match="traversal limit"):
        ensure_no_interface_subjects(([None] * 65535, [None] * 65536))


def test_multiple_roots_start_at_depth_zero():
    value = None
    for _ in range(128):
        value = [value]
    ensure_no_interface_subjects((value, "other root"))


def test_primitive_payloads_do_not_import_descriptor_classes(monkeypatch):
    original = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "contracting.stdlib.bridge.imports":
            raise AssertionError("primitive visitor imported descriptor classes")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    ensure_no_interface_subject([None, True, 7, 2.5, "text", b"data", bytearray(b"data"), int])


@pytest.mark.parametrize("wrapper", [ContractingSet, ContractingFrozenSet])
@pytest.mark.parametrize("nested", [False, True])
def test_persistent_wrappers_cannot_hide_subject_members(wrapper, nested):
    member = (subject(),) if nested else subject()
    with pytest.raises(TypeError, match="unhashable"):
        wrapper([member])


def test_failed_wrapper_mutation_preserves_original_members():
    value = ContractingSet([1])
    with pytest.raises(TypeError, match="unhashable"):
        value.add(subject())
    assert list(value) == [1]


@pytest.mark.parametrize("wrapper", [ContractingSet, ContractingFrozenSet])
def test_persistent_wrappers_reject_callable_captures(wrapper):
    def callback(value=subject()):
        return value

    with pytest.raises(TypeError, match="unhashable"):
        wrapper([callback])


@pytest.mark.parametrize("kind", ["map", "filter", "list_iterator", "dict_view", "proxy"])
def test_iterator_and_view_inspection_never_consumes_sources_or_calls_callbacks(kind):
    retained = subject()
    calls = []

    def callback(value):
        calls.append(value)
        return value

    if kind == "map":
        value = map(callback, [retained])
    elif kind == "filter":
        value = filter(callback, [retained])
    elif kind == "list_iterator":
        value = iter([retained])
    elif kind == "dict_view":
        value = {retained: 1}.keys()
    else:
        value = MappingProxyType({"retained": retained})
    with pytest.raises(TypeError, match="interface subjects cannot cross"):
        ensure_no_interface_subject(value)
    assert calls == []
    if kind in {"map", "filter", "list_iterator"}:
        assert next(value) is retained


def test_function_closure_and_default_captures_are_rejected_without_invocation():
    retained = subject()

    def closure():
        return retained

    def defaults(value=retained, *, named=retained):
        return value, named

    for value in [closure, defaults, ValueError(retained), {retained: "key"}]:
        with pytest.raises(TypeError, match="interface subjects cannot cross"):
            ensure_no_interface_subject(value)


def test_empty_trusted_host_closure_cell_is_not_an_invalid_subject():
    retained = 7

    def closure():
        return retained

    del closure.__closure__[0].cell_contents
    ensure_no_interface_subject(closure)


def test_subject_class_cannot_be_transferred_as_a_constructor():
    with pytest.raises(TypeError, match="interface subjects cannot cross"):
        ensure_no_interface_subject({"constructor": InterfaceSubject})


def test_active_storage_preserves_native_subject_free_value_node_limit(tmp_path):
    from contracting.execution.runtime import contract_execution_scope
    from contracting.storage.driver import Driver

    value = [None] * 131071
    with Driver(storage_home=tmp_path) as driver, contract_execution_scope():
        driver.set("con_subject_limit.value", value)
        assert driver.get("con_subject_limit.value") == value


def test_active_storage_preserves_native_subject_free_value_depth_limit(tmp_path):
    from contracting.execution.runtime import contract_execution_scope
    from contracting.storage.driver import Driver

    value = None
    for _ in range(128):
        value = [value]
    with Driver(storage_home=tmp_path) as driver, contract_execution_scope():
        driver.set("con_subject_limit.value", value)
        assert driver.get("con_subject_limit.value") == value
