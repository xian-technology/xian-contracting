"""Behavioral checks for exact observations and fail-closed native oracles."""

import json
import struct
from decimal import Decimal

import pytest

from tests.determinism.observer import encode_exact, observe_case


def test_exact_float_bits_include_zero_sign_and_nan_payload():
    assert encode_exact(0.0) != encode_exact(-0.0)
    first = struct.unpack(">d", bytes.fromhex("7ff8000000000001"))[0]
    second = struct.unpack(">d", bytes.fromhex("7ff8000000000002"))[0]
    assert encode_exact(first) != encode_exact(second)
    assert "7ff8000000000001" in json.dumps(encode_exact(first), allow_nan=False)


@pytest.mark.parametrize(
    "left,right", [("1.0", "1.00"), ("0", "-0"), ("NaN1", "NaN2"), ("NaN", "sNaN")]
)
def test_exact_decimal_preserves_cohort_sign_and_nan_kind(left, right):
    assert encode_exact(Decimal(left)) != encode_exact(Decimal(right))


def test_exact_collections_keep_types_and_iteration_order():
    assert encode_exact([1, 2]) != encode_exact((1, 2))
    assert encode_exact({"b": 2, "a": 1}) != encode_exact({"a": 1, "b": 2})
    assert encode_exact(True) != encode_exact(1)
    assert encode_exact(bytes([1])) != encode_exact(bytearray([1]))


def test_exact_container_aliases_and_cycles_are_json_safe():
    inner = []
    shared = [inner, inner]
    independent = [[], []]
    assert encode_exact(shared) != encode_exact(independent)
    inner.append(inner)
    json.dumps(encode_exact(shared), allow_nan=False)


def test_unknown_values_fail_closed():
    with pytest.raises(TypeError, match="unsupported observation type"):
        encode_exact(object())


def test_unbounded_integer_observation_avoids_host_decimal_digit_limits():
    import sys

    previous = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(640)
        encoded = encode_exact((1 << 20000) + 7)
        json.dumps(encoded, allow_nan=False)
    finally:
        sys.set_int_max_str_digits(previous)


def test_exact_wrapper_sets_keep_observed_iteration_and_fixed_decimal_type():
    from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet
    from xian_runtime_types.decimal import ContractingDecimal

    mutable = ContractingSet([3, 1, 2])
    frozen = ContractingFrozenSet([3, 1, 2])
    assert encode_exact(mutable) != encode_exact(frozen)
    assert encode_exact(mutable)[-1] == [encode_exact(value) for value in mutable]
    assert encode_exact(ContractingDecimal("1")) != encode_exact(Decimal("1"))


@pytest.mark.optional_native
def test_observations_equal_across_fresh_homes_and_reopened_driver(tmp_path):
    case = {
        "id": "stateful",
        "vm_profile": "xian_vm_v1",
        "source": """value = Variable()
@export
def probe():
    value.set({'b': 2, 'a': 1})
    return [float('-0'), round(decimal('1.00'), 2)]
""",
    }
    first = observe_case(case, tmp_path / "first")
    second = observe_case(case, tmp_path / "second", reopen=True)
    assert first == second
    assert first["executions"][0]["chi_used"] > 0
    assert first["executions"][0]["raw_cost"] > 0
    assert first["executions"][0]["state_before"] != first["executions"][0]["state_after"]
    assert first["artifacts"][0]["source_sha256"]
    assert first["artifacts"][0]["ir_sha256"]
    json.dumps(first, allow_nan=False)


@pytest.mark.optional_native
def test_failure_rolls_back_state_and_events_then_followup_reads_success(tmp_path):
    case = {
        "id": "rollback",
        "source": """value = Variable(default_value=0)
Changed = LogEvent('Changed', {'value': {'type': int}})
@export
def save():
    value.set(7)
    return value.get()
@export
def fail():
    value.set(99)
    Changed({'value': 99})
    assert False, 'intentional failure'
@export
def probe():
    return value.get()
""",
        "steps": [
            {"function": "save", "expected_result": 7},
            {"function": "fail", "expected_failure": True, "expected_error": "intentional failure"},
            {"expected_result": 7},
        ],
    }
    result = observe_case(case, tmp_path, reopen=True)
    failed = result["executions"][1]
    assert failed["state_before"] == failed["state_after"]
    assert failed["error"]["type"]
    assert "intentional failure" in failed["error"]["message"]
    assert result["executions"][2]["result"] == encode_exact(7)


@pytest.mark.optional_native
@pytest.mark.parametrize(
    "expectation", [{"expected_failure": True}, {"expected_result": 2}, {"expected_result": True}]
)
def test_authored_expectation_prevents_universally_wrong_equivalence(tmp_path, expectation):
    case = {"id": "wrong", "source": "@export\ndef probe():\n    return 1\n", **expectation}
    with pytest.raises(AssertionError, match="expected"):
        observe_case(case, tmp_path)


@pytest.mark.optional_native
def test_admission_rejection_cannot_count_as_deterministic_success(tmp_path):
    with pytest.raises(AssertionError, match="admission"):
        observe_case({"id": "broken", "source": "def broken("}, tmp_path)


@pytest.mark.optional_native
def test_expected_error_rejects_incidental_failure(tmp_path):
    case = {
        "id": "error",
        "source": "@export\ndef probe():\n    assert False, 'actual failure'\n",
        "expected_failure": True,
        "expected_error": "different failure",
    }
    with pytest.raises(AssertionError, match="expected error"):
        observe_case(case, tmp_path)


@pytest.mark.optional_native
def test_failed_execution_leaking_writes_is_rejected(tmp_path, monkeypatch):
    from dataclasses import replace

    from tests.determinism import observer

    execute = observer._execute

    def leaking(*args):
        return replace(execute(*args), writes={"determinism_failure.value": 99})

    monkeypatch.setattr(observer, "_execute", leaking)
    case = {
        "id": "failure",
        "source": "@export\ndef probe():\n    assert False\n",
        "expected_failure": True,
    }
    with pytest.raises(AssertionError, match="returned writes/events"):
        observe_case(case, tmp_path)


@pytest.mark.optional_native
def test_successful_commit_that_drops_writes_is_rejected(tmp_path, monkeypatch):
    from contracting.storage.driver import Driver

    commit = Driver.commit

    def losing_commit(driver):
        if "determinism_commit.value" in driver.pending_writes:
            driver.pending_writes.clear()
        commit(driver)

    monkeypatch.setattr(Driver, "commit", losing_commit)
    case = {
        "id": "commit",
        "source": "value = Variable()\n@export\ndef probe():\n    value.set(9)\n    return 9\n",
        "expected_result": 9,
    }
    with pytest.raises(AssertionError, match="committed state differs"):
        observe_case(case, tmp_path)


@pytest.mark.optional_native
def test_meter_and_write_order_changes_are_observable(tmp_path, monkeypatch):
    from dataclasses import replace

    from tests.determinism import observer

    case = {
        "id": "ordered",
        "source": "a = Variable()\nb = Variable()\n@export\ndef probe():\n    a.set(1)\n    b.set(2)\n    return 3\n",
        "expected_result": 3,
    }
    execute = observer._execute

    def ordered(*args):
        output = execute(*args)
        return replace(output, writes=dict(sorted(output.writes.items())))

    monkeypatch.setattr(observer, "_execute", ordered)
    normal = observe_case(case, tmp_path / "normal")

    def altered(*args):
        output = ordered(*args)
        return replace(
            output, chi_used=output.chi_used + 1, writes=dict(reversed(list(output.writes.items())))
        )

    monkeypatch.setattr(observer, "_execute", altered)
    changed = observe_case(case, tmp_path / "changed")
    assert normal["final_state"] == changed["final_state"]
    assert normal["executions"][0]["chi_used"] != changed["executions"][0]["chi_used"]
    assert normal["executions"][0]["writes"] != changed["executions"][0]["writes"]


@pytest.mark.optional_native
def test_oracle_validation_survives_optimized_observer_compilation(tmp_path):
    from pathlib import Path

    from tests.determinism import observer

    # The package itself rejects python -O. Compile only the observer with
    # optimization enabled to prove its checks do not depend on assert bytecode.
    source = Path(observer.__file__).read_text()
    namespace = {"__name__": "optimized_observer"}
    exec(compile(source, observer.__file__, "exec", optimize=1), namespace)
    case = {
        "id": "optimized",
        "source": "@export\ndef probe():\n    return 1\n",
        "expected_result": 2,
    }
    with pytest.raises(AssertionError, match="expected result"):
        namespace["observe_case"](case, tmp_path)


@pytest.mark.optional_native
def test_large_integer_result_validation_avoids_ambient_digit_limit(tmp_path, monkeypatch):
    import sys
    from dataclasses import replace

    from tests.determinism import observer

    execute = observer._execute
    huge = 1 << 20000

    def huge_result(*args):
        return replace(execute(*args), result=huge)

    monkeypatch.setattr(observer, "_execute", huge_result)
    case = {
        "id": "huge",
        "source": "@export\ndef probe():\n    return 1\n",
        "expected_result": huge,
    }
    previous = sys.get_int_max_str_digits()
    try:
        sys.set_int_max_str_digits(640)
        observed = observe_case(case, tmp_path)
        json.dumps(observed, allow_nan=False)
    finally:
        sys.set_int_max_str_digits(previous)


@pytest.mark.optional_native
def test_failed_execution_cannot_leak_cache_state_into_followup(tmp_path, monkeypatch):
    from tests.determinism import observer

    execute = observer._execute

    def leaking(driver, name, step):
        output = execute(driver, name, step)
        driver.cache[name + ".value"] = 99
        return output

    monkeypatch.setattr(observer, "_execute", leaking)
    case = {
        "id": "cache_leak",
        "source": "value = Variable()\n@export\ndef probe():\n    assert False\n",
        "expected_failure": True,
    }
    with pytest.raises(AssertionError, match="visible state"):
        observe_case(case, tmp_path)


def test_exact_time_and_range_values_preserve_boundaries():
    from xian_runtime_types.time import Datetime, Timedelta

    assert encode_exact(Datetime(2026, 11, 3, microsecond=1)) != encode_exact(Datetime(2026, 11, 3))
    assert encode_exact(Timedelta(seconds=-1)) != encode_exact(Timedelta(seconds=1))
    assert encode_exact(range(1, 7, 2)) != encode_exact(range(1, 7, 3))


@pytest.mark.optional_native
def test_fixed_deployment_owner_timestamp_and_dependency_scope(tmp_path):
    from xian_runtime_types.time import Datetime

    case = {
        "id": "deployment",
        "dependencies": {"determinism_dep": "@export\ndef owner():\n    return ctx.owner\n"},
        "source": "import determinism_dep\n@export\ndef probe():\n    return [ctx.owner, determinism_dep.owner()]\n",
        "expected_result": ["alice", None],
    }
    observed = observe_case(case, tmp_path)
    state = dict(observed["deployed_state"])
    expected_time = encode_exact(Datetime(2026, 11, 3, 12, 34, 56, 789012))
    assert state["determinism_dep.__submitted__"] == expected_time
    assert state["determinism_deployment.__submitted__"] == expected_time
    assert state["determinism_deployment.__owner__"] == encode_exact("alice")
    assert len(observed["artifacts"]) == 2


@pytest.mark.optional_native
def test_reopen_mode_controls_driver_lifetime_without_changing_observation(tmp_path, monkeypatch):
    from tests.determinism import observer

    active = []
    execute = observer._execute

    def tracking(driver, *args):
        active.append(driver)
        return execute(driver, *args)

    monkeypatch.setattr(observer, "_execute", tracking)
    case = {
        "id": "lifetime",
        "source": "@export\ndef probe():\n    return 1\n",
        "steps": [{"expected_result": 1}, {"expected_result": 1}],
    }
    warm = observe_case(case, tmp_path / "warm")
    assert active[0] is active[1]
    active.clear()
    cold = observe_case(case, tmp_path / "cold", reopen=True)
    assert active[0] is not active[1]
    assert warm == cold


@pytest.mark.optional_native
def test_deployment_uses_canonical_native_artifacts_without_python_lowering(tmp_path, monkeypatch):
    import hashlib

    from contracting.artifacts import build_contract_artifacts
    from contracting.compilation.compiler import ContractingCompiler
    from contracting.storage.driver import Driver

    source = "@export\ndef probe():\n    value = 7\n    return f'{ {1: value} }'\n"
    expected = build_contract_artifacts(module_name="determinism_canonical", source=source)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Python reference lowering must not be used")

    monkeypatch.setattr(Driver, "set_contract_from_source", forbidden)
    monkeypatch.setattr(ContractingCompiler, "normalize_source", forbidden)
    monkeypatch.setattr(ContractingCompiler, "lower_to_ir_json", forbidden)
    observed = observe_case(
        {"id": "canonical", "source": source, "expected_result": "{1: 7}"}, tmp_path
    )
    artifact = observed["artifacts"][0]
    assert artifact["source_sha256"] == hashlib.sha256(expected["source"].encode()).hexdigest()
    assert artifact["ir_sha256"] == hashlib.sha256(expected["vm_ir_json"].encode()).hexdigest()
