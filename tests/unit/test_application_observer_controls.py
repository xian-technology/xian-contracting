"""Fault injection keeps historical application comparisons from falsely passing."""

import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest


@pytest.fixture
def observer(monkeypatch):
    directory = Path(__file__).resolve().parents[1] / "compatibility"
    monkeypatch.syspath_prepend(str(directory))
    spec = importlib.util.spec_from_file_location(
        "application_observer_controls", directory / "application_runner.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MemoryDriver:
    """Minimal storage protocol; execution effects are supplied by each test."""

    def __init__(self, data=None):
        self.data = deepcopy(data or {})
        self.committed = deepcopy(self.data)
        self.commits = 0

    def items(self, prefix=""):
        return deepcopy({k: v for k, v in self.data.items() if k.startswith(prefix)})

    def set(self, key, value):
        if value is None:
            self.data.pop(key, None)
        else:
            self.data[key] = deepcopy(value)

    def commit(self):
        self.committed = deepcopy(self.data)
        self.commits += 1

    def rollback(self):
        self.data = deepcopy(self.committed)


def failure(writes=None, events=None, message="insufficient funds"):
    return {
        "status_code": 1,
        "result": AssertionError(message),
        "writes": writes or {},
        "events": events or [],
    }


def observe_failure(observer, driver):
    return observer.observe(
        driver,
        {"id": "business-failure", "error": "insufficient funds"},
        "native",
        ["app"],
    )


@pytest.mark.parametrize(
    "writes,events",
    [
        ({"app.balance": 1}, []),
        ({"app.__code__": "leaked source"}, []),
        ({"unexpected.__owner__": "mallory"}, []),
        ({}, [{"event": "Leaked"}]),
    ],
)
def test_failed_transaction_rejects_all_returned_effects(observer, monkeypatch, writes, events):
    monkeypatch.setattr(observer, "invoke", lambda *_: failure(writes, events))
    with pytest.raises(AssertionError, match="leaked effects"):
        observe_failure(observer, MemoryDriver())


@pytest.mark.parametrize(
    "initial,key,value",
    [
        ({}, "app.balance", 1),
        ({}, "app.__code__", "leaked source"),
        ({}, "unexpected.__owner__", "mallory"),
        ({"app.balance": True}, "app.balance", 1),
    ],
)
def test_failed_transaction_rejects_hidden_state_changes(
    observer, monkeypatch, initial, key, value
):
    driver = MemoryDriver(initial)

    def broken_execution(*_):
        driver.set(key, value)
        return failure()

    monkeypatch.setattr(observer, "invoke", broken_execution)
    with pytest.raises(AssertionError, match="changed state"):
        observe_failure(observer, driver)


def test_failure_must_have_expected_business_reason(observer, monkeypatch):
    monkeypatch.setattr(observer, "invoke", lambda *_: failure(message="unsupported operation"))
    with pytest.raises(AssertionError, match="wrong business failure"):
        observe_failure(observer, MemoryDriver())


def test_expected_failure_cannot_silently_succeed(observer, monkeypatch):
    monkeypatch.setattr(
        observer,
        "invoke",
        lambda *_: {"status_code": 0, "result": None, "writes": {}, "events": []},
    )
    with pytest.raises(AssertionError, match="unexpected outcome"):
        observe_failure(observer, MemoryDriver())


def test_success_applies_writes_and_deletions_without_losing_nested_types(observer, monkeypatch):
    driver = MemoryDriver({"app.obsolete": 7})
    nested = {"second": (True, b"payload"), "first": [1, -0.0]}
    writes = {"app.value": nested, "app.obsolete": None}
    monkeypatch.setattr(
        observer,
        "invoke",
        lambda *_: {"status_code": 0, "result": nested, "writes": writes, "events": []},
    )
    result = observer.observe(driver, {"id": "success"}, "native", ["app"])
    assert driver.commits == 1
    assert driver.committed == {"app.value": nested}
    assert result["result"] == observer.encode(nested)
    assert result["state"] == observer.encode({"app.value": nested})
    assert result["writes"] == observer.encode(dict(sorted(writes.items())))


def test_unknown_sequence_cannot_pass_an_empty_comparison(observer, monkeypatch):
    monkeypatch.setattr(observer, "fixtures", lambda: ({}, {}, [{"id": "known"}]))
    with pytest.raises((ValueError, AssertionError), match="[Uu]nknown|not found"):
        observer.run_all("native", "typo")


def test_encoder_does_not_silently_reduce_unknown_values_to_repr(observer):
    with pytest.raises(TypeError, match="Unrecorded baseline value type"):
        observer.encode(object())


def test_observation_encoder_preserves_nested_types_and_mapping_order(observer):
    value = {"second": (True, b"payload"), 1: [1, -0.0], "last": None}
    assert observer.encode(value) == [
        "dict",
        [
            [["str", "second"], ["tuple", [["bool", True], ["bytes", "7061796c6f6164"]]]],
            [["int", 1], ["list", [["int", 1], ["float", "-0x0.0p+0"]]]],
            [["str", "last"], ["NoneType", None]],
        ],
    ]


def test_observation_encoder_preserves_raw_decimal_quantum_and_time_precision(observer):
    from decimal import Decimal

    from xian_runtime_types.time import Datetime

    assert observer.encode((Decimal("1.2300"), Decimal("-0E-7"))) == [
        "tuple",
        [["Decimal", "1.2300"], ["Decimal", "-0E-7"]],
    ]
    assert observer.encode(Datetime(2025, 1, 2, 3, 4, 5, 6)) == [
        "Datetime",
        "2025-01-02 03:04:05.000006",
    ]
