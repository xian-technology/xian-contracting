from __future__ import annotations

import pytest
from xian_runtime_types.time import Datetime

from contracting.artifacts import compile_contract_source
from contracting.execution.runtime import rt
from contracting.stdlib.bridge import random as random_bridge
from contracting.storage.driver import OWNER_KEY, SOURCE_KEY, XIAN_VM_V1_IR_KEY

pytestmark = pytest.mark.optional_native

CONTRACT_NAME = "con_random_native"
CONTRACT_SOURCE = """
@export
def probe():
    random.seed("alpha")
    items = [1, 2, 3, 4]
    random.shuffle(items)
    return {
        "items": items,
        "randbits": random.getrandbits(8),
        "randrange": random.randrange(10),
        "randint": random.randint(5, 9),
        "choice": random.choice(["a", "b", "c"]),
        "choices": random.choices(["x", "y"], 3),
    }
""".strip()


class FakeDriver:
    def __init__(self):
        artifacts = compile_contract_source(
            module_name=CONTRACT_NAME,
            source=CONTRACT_SOURCE,
            lint=True,
            vm_profile="xian_vm_v1",
        )
        self.values = {
            self.make_key(CONTRACT_NAME, SOURCE_KEY): artifacts["source"],
            self.make_key(CONTRACT_NAME, XIAN_VM_V1_IR_KEY): artifacts["vm_ir_json"],
            self.make_key(CONTRACT_NAME, OWNER_KEY): "alice",
        }

    def make_key(self, contract: str, variable: str, args=None) -> str:
        key = f"{contract}.{variable}"
        for arg in args or ():
            key = f"{key}:{arg}"
        return key

    def get(self, key: str):
        return self.values.get(key)

    def items(self, prefix: str = "") -> dict[str, object]:
        return {
            key: value
            for key, value in self.values.items()
            if key.startswith(prefix)
        }

    def get_contract_ir(self, name: str, *, vm_profile: str = "xian_vm_v1"):
        assert vm_profile == "xian_vm_v1"
        return self.values.get(self.make_key(name, XIAN_VM_V1_IR_KEY))

    def get_owner(self, name: str):
        return self.values.get(self.make_key(name, OWNER_KEY))


def _context() -> dict[str, object]:
    return {
        "signer": "alice",
        "caller": "alice",
        "this": CONTRACT_NAME,
        "entry": (CONTRACT_NAME, "probe"),
        "owner": "alice",
        "submission_name": None,
        "now": Datetime(2026, 4, 13, 12, 0, 0),
        "block_num": 7,
        "block_hash": "abcd1234",
        "chain_id": "xian-test",
    }


def _expected_random_result(context: dict[str, object]) -> dict[str, object]:
    previous_env = dict(rt.env)
    rt.env = {**previous_env, **context}
    random_bridge.clear_random_state()
    try:
        random_bridge.seed("alpha")
        items = [1, 2, 3, 4]
        random_bridge.shuffle(items)
        return {
            "items": items,
            "randbits": random_bridge.getrandbits(8),
            "randrange": random_bridge.randrange(10),
            "randint": random_bridge.randint(5, 9),
            "choice": random_bridge.choice(["a", "b", "c"]),
            "choices": random_bridge.choices(["x", "y"], 3),
        }
    finally:
        random_bridge.clear_random_state()
        rt.env = previous_env


def test_native_vm_random_syscalls_match_stdlib_bridge():
    import xian_vm_core

    context = _context()
    output = xian_vm_core.execute_contract(
        driver=FakeDriver(),
        contract_name=CONTRACT_NAME,
        function_name="probe",
        context=context,
        meter=False,
    )

    assert output.status_code == 0
    assert output.result == _expected_random_result(context)
    assert sorted(output.result["items"]) == [1, 2, 3, 4]
