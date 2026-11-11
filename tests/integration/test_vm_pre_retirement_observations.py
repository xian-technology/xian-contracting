"""Frozen Python observations keep provenance and per-test value ownership."""

import hashlib
from pathlib import Path

import pytest

from contracting.compilation.conformance import CONTRACT_LANGUAGE_CONFORMANCE_CASES
from tests.integration.pre_retirement_oracle import (
    oracle_case_key,
    recorded_python_observation,
)


def test_pre_retirement_observation_file_is_immutable():
    path = Path(__file__).parents[1] / "fixtures/pre_retirement_python/observations.json"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == (
        "6d8ac0c5fb37b1bea47c6cf7370bf960458cff1bc18088c14c961b5d8acb4d5d"
    )


def test_case_lookup_requires_the_complete_recorded_input():
    case = dict(CONTRACT_LANGUAGE_CONFORMANCE_CASES[0])
    case["source"] += "\n# changed input\n"
    with pytest.raises(AssertionError, match="No pre-retirement observation"):
        recorded_python_observation(case)


def test_observation_mutations_cannot_leak_to_the_next_test():
    case = CONTRACT_LANGUAGE_CONFORMANCE_CASES[0]
    first = recorded_python_observation(case)
    expected = recorded_python_observation(case)
    first["writes"]["unexpected"] = 9
    first["events"].append({"unexpected": 9})
    assert recorded_python_observation(case) == expected


def test_typed_inputs_have_distinct_observation_addresses():
    inputs = [None, False, 0, 0.0, -0.0, [1], (1,), {"a": 1, "b": 2}, {"b": 2, "a": 1}]
    keys = [oracle_case_key({"kwargs": {"value": value}}) for value in inputs]
    assert len(keys) == len(set(keys))


def test_unsupported_case_values_cannot_be_silently_stringified():
    with pytest.raises(TypeError, match="Unsupported oracle value type"):
        oracle_case_key({"kwargs": {"value": object()}})
