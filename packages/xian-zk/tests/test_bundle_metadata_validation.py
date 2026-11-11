"""Bundle metadata validation has bounded work and strict JSON integer types."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from xian_zk.bundles import validate_shielded_bundle_payload


def bundle_payload(bundle_type):
    actions = {
        "note": ["deposit", "transfer", "withdraw"],
        "command": ["deposit", "command", "withdraw"],
        "scheduler-auth": ["action"],
    }[bundle_type]
    payload = {
        "circuit_family": "fixture",
        "warning": "metadata-only fixture",
        "setup_mode": "insecure-dev",
        "contract_name": "con_fixture",
        "tree_depth": 2,
        "leaf_capacity": 4,
        "max_inputs": 2,
        "max_outputs": 2,
    }
    for action in actions:
        payload[action] = {
            "vk_id": action,
            "circuit_name": action,
            "version": "1",
            "vk_hex": "0x00",
            "pk_hex": "0x00",
        }
    return payload


@pytest.mark.parametrize("bundle_type", ["note", "command", "scheduler-auth"])
@pytest.mark.parametrize("field", ["tree_depth", "leaf_capacity", "max_inputs", "max_outputs"])
@pytest.mark.parametrize("value", [False, True])
def test_bundle_metadata_requires_integers_instead_of_json_booleans(bundle_type, field, value):
    payload = bundle_payload(bundle_type)
    payload[field] = value
    with pytest.raises(ValueError, match=field + ".*integer"):
        validate_shielded_bundle_payload(payload, bundle_type=bundle_type)


@pytest.mark.parametrize("bundle_type", ["note", "command"])
def test_unbounded_tree_depth_is_rejected_without_constructing_exponential_capacity(bundle_type):
    payload = bundle_payload(bundle_type)
    payload["tree_depth"] = 10**1000
    signal = pytest.importorskip("signal")
    if not hasattr(signal, "alarm"):
        pytest.skip("the isolated resource regression requires POSIX alarm support")
    script = """
import json, signal, sys
from xian_zk.bundles import validate_shielded_bundle_payload
# Bound the regression itself: the rejected input must not exhaust the test host.
signal.alarm(2)
try:
    validate_shielded_bundle_payload(json.loads(sys.stdin.read()), bundle_type=sys.argv[1])
except ValueError as error:
    assert "leaf_capacity" in str(error) and "tree_depth" in str(error)
    signal.alarm(0)
else:
    raise AssertionError("invalid tree capacity was accepted")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, bundle_type],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=10,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "python")},
    )
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    "depth,capacity,accepted",
    [
        (1, 1, False),
        (1, 2, True),
        (1, 3, True),
        (2, 3, False),
        (2, 4, True),
        (2, 5, True),
        (128, 2**128 - 1, False),
        (128, 2**128, True),
    ],
)
def test_capacity_check_preserves_exact_power_boundary(depth, capacity, accepted):
    payload = bundle_payload("note")
    payload.update(tree_depth=depth, leaf_capacity=capacity)
    if accepted:
        normalized = validate_shielded_bundle_payload(payload, bundle_type="note")
        assert normalized["tree_depth"] == depth
        assert normalized["leaf_capacity"] == capacity
    else:
        with pytest.raises(ValueError, match="leaf_capacity.*tree_depth"):
            validate_shielded_bundle_payload(payload, bundle_type="note")


@pytest.mark.parametrize("bundle_type", ["note", "command", "scheduler-auth"])
def test_valid_json_bundle_preserves_public_and_private_metadata(bundle_type):
    payload = bundle_payload(bundle_type)
    normalized = validate_shielded_bundle_payload(json.dumps(payload), bundle_type=bundle_type)
    assert normalized == {**payload, "setup_ceremony": ""}
    public_only = {**payload}
    for action in (
        ("action",)
        if bundle_type == "scheduler-auth"
        else ("deposit", "withdraw", "command" if bundle_type == "command" else "transfer")
    ):
        public_only[action] = {
            key: value for key, value in payload[action].items() if key != "pk_hex"
        }
    public_normalized = validate_shielded_bundle_payload(
        public_only, bundle_type=bundle_type, require_private_keys=False
    )
    assert public_normalized == {**public_only, "setup_ceremony": ""}


@pytest.mark.parametrize(
    "field,value",
    [
        ("tree_depth", -1),
        ("max_inputs", "2"),
        ("max_outputs", None),
        ("leaf_capacity", 1.5),
        ("max_inputs", 0),
    ],
)
def test_invalid_note_dimensions_are_rejected(field, value):
    payload = bundle_payload("note")
    payload[field] = value
    with pytest.raises(ValueError, match=field):
        validate_shielded_bundle_payload(payload, bundle_type="note")


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("setup_mode", None, "setup_mode"),
        ("setup_mode", "ceremony-import", "setup_ceremony"),
        ("contract_name", " ", "contract_name"),
        ("deposit", None, "deposit"),
        ("deposit.vk_hex", "00", "start with 0x"),
        ("deposit.vk_hex", "0x", "even-length"),
        ("deposit.vk_hex", "0x0", "even-length"),
        ("deposit.vk_hex", "0xzz", "valid hex"),
        ("deposit.vk_id", "withdraw", "duplicate vk_id"),
        ("deposit.circuit_name", "withdraw", "duplicate circuit_name"),
        ("deposit.version", "2", "versions"),
    ],
)
def test_malformed_bundle_metadata_fails_with_validation_error(field, value, message):
    payload = bundle_payload("note")
    if "." in field:
        action, attribute = field.split(".")
        payload[action][attribute] = value
    else:
        payload[field] = value
    with pytest.raises(ValueError, match=message):
        validate_shielded_bundle_payload(payload, bundle_type="note")


@pytest.mark.parametrize("payload,message", [("{", "valid JSON"), ([], "JSON object")])
def test_malformed_bundle_document_is_rejected(payload, message):
    with pytest.raises(ValueError, match=message):
        validate_shielded_bundle_payload(payload, bundle_type="note")


def test_scheduler_auth_allows_zero_dimensions_and_defaults():
    payload = bundle_payload("scheduler-auth")
    for field in ("tree_depth", "leaf_capacity", "max_inputs", "max_outputs"):
        payload.pop(field)
    normalized = validate_shielded_bundle_payload(payload, bundle_type="scheduler-auth")
    assert [
        normalized[field] for field in ("tree_depth", "leaf_capacity", "max_inputs", "max_outputs")
    ] == [0, 0, 0, 0]
