"""A contract pays for the proof verification its zk calls make the host do.

Each Groth16 BN254 verification costs a validator milliseconds of CPU, so
every zk syscall that verifies proofs is charged per proof before the host
verifies any: a call that made the host verify proofs it was not charged for
would let one cheap transaction stall every validator.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from xian_runtime_types.time import Datetime

pytestmark = pytest.mark.optional_native

DEMO = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "packages/xian-zk/tests/fixtures/groth16_bn254_demo.json"
    ).read_text()
)

SOURCE = """
def requests(vk_id: str, proof_hex: str, n: int, salt: int):
    built = []
    for i in range(n):
        digits = hex(salt * 1000000 + i + 7)[2:]
        built.append(
            {
                "vk_id": vk_id,
                "proof_hex": proof_hex,
                "public_inputs": ["0x" + "0" * (64 - len(digits)) + digits],
            }
        )
    return built

@export
def build(vk_id: str, proof_hex: str, n: int, salt: int):
    return len(requests(vk_id, proof_hex, n, salt))

@export
def warm(vk_id: str, proof_hex: str, n: int, salt: int):
    return len(zk.warm_verified_proofs(requests(vk_id, proof_hex, n, salt)))

@export
def verify(vk_id: str, proof_hex: str, n: int, salt: int):
    results = []
    for request in requests(vk_id, proof_hex, n, salt):
        results.append(
            zk.verify_groth16(request["vk_id"], request["proof_hex"], request["public_inputs"])
        )
    return len(results)
"""


@pytest.fixture(scope="module")
def driver(tmp_path_factory):
    from contracting.storage.driver import Driver

    with Driver(storage_home=tmp_path_factory.mktemp("zk-metering")) as driver:
        driver.set_contract_from_source("con_zk_work", SOURCE, owner=None)
        registry = {
            "vk_hex": DEMO["vk_hex"],
            "scheme": "groth16",
            "curve": "bn254",
            "vk_hash": "hash-demo",
            "active": True,
        }
        for name, value in registry.items():
            driver.set(f"zk_registry.verifying_keys:demo:{name}", value)
        driver.commit()
        yield driver


def chi_used(driver, function, n, salt):
    from tests.vm_calls import execute_contract

    output = execute_contract(
        driver=driver,
        contract_name="con_zk_work",
        function_name=function,
        kwargs={"vk_id": "demo", "proof_hex": DEMO["proof_hex"], "n": n, "salt": salt},
        context={
            "signer": "alice",
            "caller": "alice",
            "this": "con_zk_work",
            "entry": ("con_zk_work", function),
            "now": Datetime(2026, 1, 2, 3, 4, 5),
            "block_num": 1,
            "block_hash": "h",
            "chain_id": "c",
            "__input_hash": f"{function}-{n}-{salt}",
        },
        meter=True,
        chi_budget_raw=1_000_000_000,
    )
    assert output.status_code == 0, output.result
    assert output.result == n
    return output.chi_used


def test_warming_proofs_costs_what_verifying_them_costs(driver):
    n = 8
    built = chi_used(driver, "build", n, salt=1)
    verified = chi_used(driver, "verify", n, salt=2) - built
    warmed = chi_used(driver, "warm", n, salt=3) - built
    # Each proof is charged as zk.verify_groth16 charges it (750 chi and
    # more), whether the host verifies it alone or warms it with others.
    assert verified >= n * 750
    assert warmed >= n * 750
    # Warming never costs more than verifying the proofs one by one.
    assert warmed <= verified
