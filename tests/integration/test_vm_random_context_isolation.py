"""Native host effects depend on explicit transaction context, never ambient state."""

import hashlib

import pytest

from contracting.execution.runtime import rt
from contracting.stdlib.bridge import random as random_bridge
from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native

SOURCE = """state = Variable()
@export
def probe(fail: bool = False):
    random.seed()
    value = random.getrandbits(64)
    state.set(value)
    assert not fail, 'deliberate rollback'
    return value
"""


def expected_random(context):
    seed = (
        f"chain_id={context.get('chain_id') or ''}|"
        f"block_num={context.get('block_num') or 0}|"
        f"block_hash={context.get('block_hash') or '0'}|"
        f"input_hash={context.get('__input_hash') or '0'}|0"
    )
    return int.from_bytes(hashlib.sha3_256(seed.encode()).digest()[:8], "big")


@pytest.mark.parametrize("explicit_seed", [False, True])
@pytest.mark.parametrize("meter", [False, True])
def test_random_uses_only_explicit_context_and_restores_environment(tmp_path, explicit_seed, meter):
    from xian_vm_core import execute_contract

    context = {"signer": "alice", "caller": "alice", "this": "con_rng"}
    if explicit_seed:
        context.update(chain_id="local", block_num=17, block_hash="abc", __input_hash="tx-one")
    previous = dict(rt.env)
    try:
        with Driver(storage_home=tmp_path) as driver:
            driver.set_contract_from_source("con_rng", SOURCE, owner=None)
            driver.commit()
            for tag in ("ambient-a", "ambient-b"):
                ambient = {
                    "chain_id": tag,
                    "block_num": 999,
                    "block_hash": tag,
                    "__input_hash": tag,
                    "unrelated_host_value": object(),
                }
                rt.env = ambient
                for fail in (False, True, False):
                    result = execute_contract(
                        driver=driver,
                        contract_name="con_rng",
                        function_name="probe",
                        kwargs={"fail": fail},
                        context=context,
                        meter=meter,
                        chi_budget_raw=100_000_000,
                    )
                    assert dict(rt.env) == ambient
                    assert random_bridge._RANDOM_STATE.get() is None
                    if fail:
                        assert result.status_code == 1
                        assert result.writes == {} and result.events == []
                    else:
                        assert result.status_code == 0, result.result
                        assert result.result == expected_random(context)
                        assert result.writes == {"con_rng.state": expected_random(context)}
    finally:
        rt.env = previous


def test_protocol_maps_are_ordered_without_reordering_authored_values(tmp_path):
    from xian_vm_core import execute_contract

    child = """state = Variable()
@export
def save():
    state.set({'z': 1, 'a': 2})
"""
    caller = """import con_a
import con_z
values = Hash()
state = Variable()
@export
def probe():
    con_z.save()
    con_a.save()
    state.set({'z': 1, 'a': 2})
    for key in ['z', 'a', 'm', 'b']:
        values[key] = {'z': 1, 'a': 2}
    return {'z': 1, 'a': 2}
"""
    with Driver(storage_home=tmp_path) as driver:
        for name, source in (("con_z", child), ("con_a", child), ("con_m", caller)):
            driver.set_contract_from_source(name, source, owner=None)
        driver.commit()
        for _ in range(4):
            result = execute_contract(
                driver=driver,
                contract_name="con_m",
                function_name="probe",
                context={"signer": "alice", "caller": "alice", "this": "con_m"},
                meter=True,
                chi_budget_raw=100_000_000,
            )
            assert result.status_code == 0, result.result
            assert list(result.writes) == sorted(result.writes)
            assert list(result.contract_costs) == sorted(result.contract_costs)
            assert set(result.contract_costs) == {"con_a", "con_m", "con_z"}
            assert list(result.result) == ["z", "a"]
            assert all(list(value) == ["z", "a"] for value in result.writes.values())


def test_nested_contract_keeps_transaction_seed_without_inheriting_host_state(tmp_path):
    from xian_vm_core import execute_contract

    child = """@export
def draw():
    random.seed()
    return random.getrandbits(64)
"""
    caller = """import con_rng_child
@export
def probe():
    random.seed()
    first = random.getrandbits(64)
    nested = con_rng_child.draw()
    random.seed()
    return [first, nested, random.getrandbits(64)]
"""
    context = {
        "signer": "alice",
        "caller": "alice",
        "this": "con_rng_parent",
        "chain_id": "local",
        "block_num": 17,
        "block_hash": "abc",
        "__input_hash": "nested-tx",
    }
    previous = dict(rt.env)
    try:
        rt.env = {"__input_hash": "unrelated-host-state"}
        with Driver(storage_home=tmp_path) as driver:
            driver.set_contract_from_source("con_rng_child", child, owner=None)
            driver.set_contract_from_source("con_rng_parent", caller, owner=None)
            driver.commit()
            output = execute_contract(
                driver=driver,
                contract_name="con_rng_parent",
                function_name="probe",
                context=context,
            )
            assert output.status_code == 0, output.result
            assert output.result == [expected_random(context)] * 3
            assert dict(rt.env) == {"__input_hash": "unrelated-host-state"}
    finally:
        rt.env = previous
