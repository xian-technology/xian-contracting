"""The block host's zk syscalls (Rust) against the Python zk bridge.

The Rust block executor serves the contract zk syscalls in vm-core
(``block_host/zk.rs``); the Python path serves them with
``contracting.stdlib.bridge.zk`` through ``NativeVmHost.handle_syscall``.
This fuzz sends the same calls, as the VM sends them (every argument bound
positionally), through both over the same chain state: a ``zk_registry``
with good and broken keys, some committed and some only in the block
overlay. Every call must return the same value (after the V2 boundary) or
raise the same exception with the same text, and none may be handed back.
"""

from __future__ import annotations

import copy
import json
import random
from pathlib import Path

import pytest
from xian_runtime_types.decimal import ContractingDecimal

from contracting.execution.runtime import rt
from contracting.local import ContractingClient
from contracting.stdlib.bridge import zk as zk_bridge

pytestmark = pytest.mark.optional_native

native = pytest.importorskip("xian_vm_core._native")
NativeVmHost = pytest.importorskip("xian_vm_core").NativeVmHost

DEMO = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "packages/xian-zk/tests/fixtures/groth16_bn254_demo.json"
    ).read_text()
)
# The exception types whose category the VM keeps (python_bindings
# `builtin_exception_name`).
KEPT_TYPES = (AssertionError, TypeError, ValueError, RuntimeError, Exception, KeyError, IndexError)


def field(value: int) -> str:
    return "0x" + format(value, "064x")


REGISTRY = {
    # vk_id: (vk_hex, scheme, curve, vk_hash, active), committed
    "demo": (DEMO["vk_hex"], "groth16", "bn254", "hash-demo", True),
    "inactive": (DEMO["vk_hex"], "groth16", "bn254", "hash-inactive", False),
    "int_active": (DEMO["vk_hex"], "groth16", "bn254", "hash-int", 1),
    "plonk": (DEMO["vk_hex"], "plonk", "bn254", "hash-plonk", True),
    "bls": (DEMO["vk_hex"], "groth16", "bls12_381", "hash-bls", True),
    "nohash": (DEMO["vk_hex"], "groth16", "bn254", "", True),
    "int_hash": (DEMO["vk_hex"], "groth16", "bn254", 5, True),
    "odd_hex": ("0x1", "groth16", "bn254", "hash-odd", True),
    "garbage": ("0x1234", "groth16", "bn254", "hash-garbage", True),
    "bare": (DEMO["vk_hex"], None, None, None, None),
}
PENDING = {"pending": (DEMO["vk_hex"], "groth16", "bn254", "hash-pending", True)}
METADATA = {"circuit_name": "square", "tree_depth": 20, "deprecated": True, "version": "1"}

VK_IDS = [*REGISTRY, *PENDING, "unknown", "", 5, None, "é" * 129, "😀" * 128, ["demo"]]
HEXES = [
    DEMO["vk_hex"],
    "0x00",
    "12",
    "",
    "0x",
    "0x0",
    "0xzz",
    "0x0é",
    "0x" + "0" * 8200,
    5,
    None,
    ["0x00"],
]
PROOFS = [DEMO["proof_hex"], DEMO["proof_hex"], "0x00", "0xab", "0x" + "0" * 4098, "0x1", 7]
FIELDS = [field(0), field(1), field(5), "0x" + "ff" * 32, "0x00", "0xzz", 7, None]
INPUTS = [
    DEMO["public_inputs"],
    DEMO["public_inputs"],
    [field(5)],
    [],
    [field(1)] * 33,
    ["0x00"],
    tuple(DEMO["public_inputs"]),
    DEMO["public_inputs"][0],
    [5],
    ["0x" + "ff" * 32],
    None,
]
INTS = [0, 5, 1000, -1, 2**64 - 1, 2**64, 2**200, True, False, ContractingDecimal("1"), "5", None]
NAMES = ["con_token", "con_token", "", 5, None, "bob"]
PAYLOADS = ["", None, "0x1234", "0x", "0x1", "zz", 5, "0x" + "ab" * 100]


def _fields(rng, lowest=0, highest=5):
    return [rng.choice(FIELDS[:3]) for _ in range(rng.randint(lowest, highest))]


def _maybe(rng, value, pool):
    return value if rng.random() < 0.85 else rng.choice(pool)


def _request(rng):
    request = {
        "vk_id": rng.choice(VK_IDS[:4] + ["unknown", 5]),
        "proof_hex": rng.choice(PROOFS),
        "public_inputs": rng.choice(INPUTS[:4]),
    }
    if rng.random() < 0.1:
        request.pop(rng.choice(list(request)))
    return request if rng.random() < 0.95 else rng.choice(["x", 5, None])


def _outputs(rng):
    commitments = _fields(rng)
    hashes = [rng.choice(FIELDS[:2]) for _ in commitments]
    if rng.random() < 0.15:
        hashes = _fields(rng)
    return _maybe(rng, commitments, [None, "x"]), _maybe(rng, hashes, [None, 5])


def _proof(rng, key, keys):
    """A proof call: often the demo proof, else any arguments."""
    if rng.random() < 0.3:
        return [key, DEMO["proof_hex"], rng.choice(INPUTS[:3])]
    return [rng.choice(keys), rng.choice(PROOFS), rng.choice(INPUTS)]


CALLS = {
    "is_available": lambda rng: [],
    "has_verifying_key": lambda rng: [rng.choice(VK_IDS)],
    "get_vk_info": lambda rng: [rng.choice(VK_IDS)],
    "verify_groth16_bn254": lambda rng: _proof(rng, DEMO["vk_hex"], HEXES),
    "verify_groth16": lambda rng: _proof(rng, "demo", VK_IDS),
    "clear_verified_proof_cache": lambda rng: [],
    "clear_prepared_vk_cache": lambda rng: [],
    "warm_verified_proofs": lambda rng: [
        _maybe(rng, [_request(rng) for _ in range(rng.randint(0, 4))], [None, {}, "x"])
    ],
    "shielded_note_append_commitments": lambda rng: [
        rng.choice([0, 0, 1, 3, -1, 2**64, True, "1"]),
        _maybe(rng, [field(0)] * rng.choice([20, 20, 1, 0, 65]), [None, (field(0),)]),
        _maybe(rng, _fields(rng, 0, 3), [None, [field(0)] * 33]),
    ],
    "shielded_command_nullifier_digest": lambda rng: [
        _maybe(rng, _fields(rng, 0, 6), [None, [field(1)] * 33])
    ],
    "shielded_command_binding": lambda rng: [
        *(_maybe(rng, rng.choice(FIELDS[:3]), FIELDS) for _ in range(8)),
        rng.choice(INTS),
        rng.choice(INTS),
    ],
    "shielded_command_execution_tag": lambda rng: [
        _maybe(rng, rng.choice(FIELDS[:3]), FIELDS),
        _maybe(rng, rng.choice(FIELDS[:3]), FIELDS),
    ],
    "shielded_output_payload_hash": lambda rng: [rng.choice(PAYLOADS)],
    "shielded_output_payload_hashes": lambda rng: [
        _maybe(rng, [rng.choice(PAYLOADS) for _ in range(rng.randint(0, 4))], [None, "0x12"])
    ],
    "shielded_deposit_public_inputs": lambda rng: [
        rng.choice(NAMES),
        _maybe(rng, field(0), FIELDS),
        rng.choice(INTS),
        *_outputs(rng),
    ],
    "shielded_transfer_public_inputs": lambda rng: [
        rng.choice(NAMES),
        _maybe(rng, field(0), FIELDS),
        _maybe(rng, _fields(rng, 1, 4), [[], None, _fields(rng, 5, 6)]),
        *_outputs(rng),
    ],
    "shielded_withdraw_public_inputs": lambda rng: [
        rng.choice(NAMES),
        _maybe(rng, field(0), FIELDS),
        rng.choice(INTS),
        rng.choice(NAMES),
        _maybe(rng, _fields(rng, 1, 4), [[], None]),
        *_outputs(rng),
    ],
    "shielded_command_public_inputs": lambda rng: [
        rng.choice(NAMES),
        _maybe(rng, field(0), FIELDS),
        _maybe(rng, field(3), FIELDS),
        _maybe(rng, field(4), FIELDS),
        rng.choice(INTS),
        rng.choice(INTS),
        _maybe(rng, _fields(rng, 1, 4), [[], None]),
        *_outputs(rng),
    ],
}


def _register(driver, entries):
    for vk_id, (vk_hex, scheme, curve, vk_hash, active) in entries.items():
        fields = {"vk_hex": vk_hex, "scheme": scheme, "curve": curve, "vk_hash": vk_hash}
        fields.update(active=active, **METADATA)
        for name, value in fields.items():
            if value is not None:
                driver.set(f"zk_registry.verifying_keys:{vk_id}:{name}", value)


@pytest.fixture
def driver(tmp_path):
    client = ContractingClient(vm_profile="xian_vm_v2", storage_home=tmp_path)
    driver = client.raw_driver
    _register(driver, REGISTRY)
    driver.commit()
    _register(driver, PENDING)
    yield driver
    driver.close()


def _python_exception(error):
    if type(error) in KEPT_TYPES:
        return (type(error).__name__, list(error.args))
    return None


def python_outcomes(driver, calls):
    """What the VM receives from the Python path for each call."""
    previous = dict(rt.env)  # rt.env is a live proxy
    rt.env = {"__Driver": driver}
    outcomes = []
    try:
        for syscall_id, args in calls:
            try:
                result = NativeVmHost.handle_syscall(None, syscall_id, copy.deepcopy(args), {})
            except Exception as error:  # noqa: BLE001 - every raise is an outcome
                outcomes.append(
                    ("raised", f"{type(error).__qualname__}: {error}", _python_exception(error))
                )
                continue
            outcomes.append(("ok", native._vm_value_debug(result)))
    finally:
        rt.env = previous
    return outcomes


def rust_outcomes(driver, calls):
    environment, overlay = driver.committed_storage()
    return [tuple(outcome) for outcome in native._zk_syscalls_debug(environment, overlay, calls)]


def _calls(seed, count):
    rng = random.Random(seed)
    names = sorted(CALLS)
    return [(f"zk.{name}", CALLS[name](rng)) for name in (rng.choice(names) for _ in range(count))]


@pytest.mark.parametrize("seed", range(6))
def test_zk_syscalls_serve_what_the_python_bridge_serves(driver, seed):
    calls = _calls(seed, 400)
    expected = python_outcomes(driver, calls)
    zk_bridge.clear_verified_proof_cache()
    zk_bridge.clear_prepared_vk_cache()
    actual = rust_outcomes(driver, calls)
    for call, left, right in zip(calls, actual, expected, strict=True):
        assert left == right, call
    kinds = {(call[0], outcome[0]) for call, outcome in zip(calls, expected, strict=True)}
    assert ("zk.verify_groth16", "ok") in kinds
    assert ("zk.verify_groth16", "raised") in kinds


def test_the_fuzz_reaches_every_outcome_of_every_syscall(driver):
    calls = _calls(99, 3000)
    outcomes = python_outcomes(driver, calls)
    reached = {(call[0], outcome[0]) for call, outcome in zip(calls, outcomes, strict=True)}
    # has_verifying_key answers False for any key it cannot use.
    always_ok = {
        "zk.is_available",
        "zk.has_verifying_key",
        "zk.clear_verified_proof_cache",
        "zk.clear_prepared_vk_cache",
    }
    for name in CALLS:
        assert (f"zk.{name}", "ok") in reached, name
        if f"zk.{name}" not in always_ok:
            assert (f"zk.{name}", "raised") in reached, name
    texts = {outcome[1] for outcome in outcomes if outcome[0] == "raised"}
    assert "OverflowError: int too big to convert" in texts
    assert any(text.startswith("ValueError: ") for text in texts)
    assert any("must use Groth16" in text for text in texts)


def test_a_key_registered_in_the_block_overlay_verifies(driver):
    calls = [("zk.verify_groth16", ["pending", DEMO["proof_hex"], DEMO["public_inputs"]])]
    assert rust_outcomes(driver, calls) == [("ok", "Bool(true)")]
    assert python_outcomes(driver, calls) == [("ok", "Bool(true)")]


def test_warming_fills_the_cache_both_paths_verify_from(driver):
    # The cache key holds the key's id and hash, not its bytes: a proof
    # warmed under a key verifies from the cache after the bytes changed.
    zk_bridge.clear_verified_proof_cache()
    rt.env["__Driver"] = driver
    try:
        assert zk_bridge.warm_verified_proofs(
            [
                {
                    "vk_id": "demo",
                    "proof_hex": DEMO["proof_hex"],
                    "public_inputs": DEMO["public_inputs"],
                }
            ]
        ) == [True]
    finally:
        rt.env.pop("__Driver", None)
    driver.set("zk_registry.verifying_keys:demo:vk_hex", "0x1234")
    calls = [("zk.verify_groth16", ["demo", DEMO["proof_hex"], DEMO["public_inputs"]])]
    assert rust_outcomes(driver, calls) == [("ok", "Bool(true)")]
    assert python_outcomes(driver, calls) == [("ok", "Bool(true)")]
    zk_bridge.clear_verified_proof_cache()
    refused = rust_outcomes(driver, calls)[0]
    assert refused[1].startswith("AssertionError: invalid verifying key bytes"), refused
