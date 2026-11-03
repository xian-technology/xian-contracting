"""Reviewed historical differences cannot become blanket comparison exceptions."""

import importlib
import json
from copy import deepcopy
from pathlib import Path

import pytest


@pytest.fixture
def policy_module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "compatibility"))
    return importlib.import_module("application_expectations")


def sample():
    observations = {
        "sample": [
            {
                "id": "step",
                "result": ["tuple", [["Decimal", "1.000"], ["int", 7]]],
                "state": [],
            }
        ]
    }
    deviations = {
        "policies": {"approved": {"reason": "Explicit test policy"}},
        "replacements": [
            {
                "scenario": "sample",
                "step": "step",
                "path": ["result", 1, 0, 1],
                "historical": "1.000",
                "current": "1.00",
                "policy": "approved",
            }
        ],
    }
    return observations, deviations


def test_policy_applies_exactly_one_leaf_without_mutating_historical_evidence(policy_module):
    original, deviations = sample()
    saved = deepcopy(original)
    current, count = policy_module.expected_current(original, deviations)
    assert original == saved
    assert count == 1
    assert current == {
        "sample": [
            {
                "id": "step",
                "result": ["tuple", [["Decimal", "1.00"], ["int", 7]]],
                "state": [],
            }
        ]
    }


@pytest.mark.parametrize("fault", ["historical", "duplicate", "undocumented"])
def test_policy_rejects_stale_or_ambiguous_replacements(policy_module, fault):
    original, deviations = sample()
    replacement = deviations["replacements"][0]
    if fault == "historical":
        replacement["historical"] = "1.0"
    elif fault == "duplicate":
        deviations["replacements"].append(deepcopy(replacement))
    else:
        replacement["policy"] = "unreviewed"
    with pytest.raises(ValueError):
        policy_module.expected_current(original, deviations)


@pytest.mark.parametrize("field", ["other_result", "type", "state"])
def test_policy_keeps_unreviewed_differences_observable(policy_module, field):
    comparison = importlib.import_module("application_runner").comparison
    original, deviations = sample()
    expected, _ = policy_module.expected_current(original, deviations)
    actual = deepcopy(expected)
    if field == "other_result":
        actual["sample"][0]["result"][1][0][1] = "1.000000001"
    elif field == "type":
        actual["sample"][0]["result"][1][0][0] = "ContractingDecimal"
    else:
        actual["sample"][0]["state"] = ["unexpected write"]
    assert comparison(actual) != comparison(expected)


def test_checked_in_policy_is_limited_to_reviewed_constructor_and_liquidity_fields():
    root = Path(__file__).resolve().parents[1] / "compatibility" / "applications"
    historical = json.loads((root / "legacy_baseline.json").read_text())["observations"]
    deviations = json.loads((root / "current_policy_deviations.json").read_text())
    numeric_pairs = {
        "con_pairs.pairs:1:balances:alice": (
            "999.999999989999999999999999999999",
            "999.99999999",
        ),
        "con_pairs.pairs:1:totalSupply": (
            "999.999999999999999999999999999999",
            "1E+3",
        ),
    }
    assert set(deviations["policies"]) == {"constructor_child_context", "fixed_scale_square_root"}
    for change in deviations["replacements"]:
        step = next(s for s in historical[change["scenario"]] if s["id"] == change["step"])
        path = change["path"]
        if change["policy"] == "constructor_child_context":
            assert path[0] in {"writes", "state"}
            assert path[1] == 1 and path[3:] == [0, 1]
            module, suffix = change["historical"].split(".", 1)
            assert suffix == "excluded:submission"
            assert change["current"] == module + ".excluded:" + module
        else:
            assert change["scenario"] == "dex_liquidity_swap"
            if path[0] == "result":
                assert change["step"] == "addLiquidity"
                assert path == ["result", 1, 2, 1]
                key = "con_pairs.pairs:1:balances:alice"
            else:
                assert path[0] in {"writes", "state"}
                assert path[1] == 1 and path[3:] == [1, 1]
                key = step[path[0]][1][path[2]][0][1]
            assert (change["historical"], change["current"]) == numeric_pairs[key]
