"""Native persistence reloads typed wrapper members and rejects invalid effects."""

from decimal import Decimal

import pytest
from xian_runtime_types.encoding import TYPES

from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native

SOURCE = """
state=Variable()
@export
def seed():
    prototype=round(decimal('1'),0)
    state.set(set([('tuple',7),frozenset([('inside',2)]),round(decimal('1.2300'),4),
        prototype.from_float(float('5e-324')),float('-0.0'),b'x',
        datetime.datetime(2026,1,2,3,4,5,6),datetime.timedelta(seconds=-90001)]))
    return 1
@export
def probe():
    values=state.get()
    raw=[]
    floats=[]
    times=[]
    durations=[]
    for item in values:
        if isinstance(item,float):
            floats.append(item.hex())
        elif isinstance(item,datetime.datetime):
            times.append(str(item))
        elif isinstance(item,datetime.timedelta):
            durations.append(item.seconds)
        elif not isinstance(item,(tuple,frozenset,bytes)):
            raw.append([str(item),item.as_tuple().exponent])
    return [('tuple',7) in values,frozenset([('inside',2)]) in values,b'x' in values,
        raw,floats,times,durations]
"""


def _execute(driver, function, meter):
    from xian_vm_core import execute_contract

    return execute_contract(
        driver=driver,
        contract_name="con_set_codec",
        function_name=function,
        kwargs={},
        context={"caller": "alice", "signer": "alice", "this": "con_set_codec"},
        meter=meter,
        chi_budget_raw=100_000_000,
        vm_profile=driver.vm_profile,
    )


@pytest.mark.parametrize("meter", [False, True])
def test_native_members_keep_types_and_quantum_after_lmdb_reopen(tmp_path, meter):
    with Driver(storage_home=tmp_path, vm_profile="xian_vm_v1") as driver:
        driver.set_contract_from_source("con_set_codec", SOURCE, owner=None)
        driver.commit()
        result = _execute(driver, "seed", meter)
        assert result.status_code == 0, result.result
        for key, value in result.writes.items():
            driver.set(key, value)
        driver.commit()
    with Driver(storage_home=tmp_path, vm_profile="xian_vm_v1") as driver:
        result = _execute(driver, "probe", meter)
        assert result.status_code == 0, result.result
        smallest = Decimal.from_float(5e-324)
        assert result.result == [
            True,
            True,
            True,
            [[str(smallest), smallest.as_tuple().exponent], ["1.2300", -4]],
            ["-0x0.0p+0"],
            ["2026-01-02 03:04:05.000006"],
            [-90001],
        ]


def _assert_rejected_then_recovers(home, expression, meter, fragment, *, vm_profile="xian_vm_v2"):
    source = (
        "state=Variable()\n@export\ndef fail():\n    state.set(1)\n    state.set("
        + expression
        + ")\n    return 0\n@export\ndef recover():\n    assert state.get() is None\n    state.set(set([(1,2)]))\n    return 7\n"
    )
    with Driver(storage_home=home, vm_profile=vm_profile) as driver:
        driver.set_contract_from_source("con_set_codec", source, owner=None)
        driver.commit()
        failed = _execute(driver, "fail", meter)
        assert failed.status_code == 1 and fragment in str(failed.result), failed.result
        assert failed.writes == {} and failed.events == []
        recovered = _execute(driver, "recover", meter)
        assert recovered.status_code == 0 and recovered.result == 7, recovered.result


@pytest.mark.parametrize("meter", [False, True])
@pytest.mark.parametrize(
    "member", ["float('nan')", "float('inf')", "round(decimal('1'),0).from_float(float('inf'))"]
)
def test_nonfinite_persistent_set_members_fail_even_without_metering(tmp_path, meter, member):
    _assert_rejected_then_recovers(
        tmp_path, "set([(" + member + ",)])", meter, "finite", vm_profile="xian_vm_v1"
    )


@pytest.mark.parametrize("meter", [False, True])
@pytest.mark.parametrize("tag", sorted(TYPES))
def test_nested_reserved_dictionary_tags_cannot_impersonate_runtime_values(tmp_path, meter, tag):
    _assert_rejected_then_recovers(
        tmp_path, "{'nested':[{" + repr(tag) + ":'1'}]}", meter, "reserved"
    )


@pytest.mark.parametrize("meter", [False, True])
def test_multiple_valid_wrapper_roots_share_native_storage_work_budget(tmp_path, meter):
    from xian_runtime_types.collections import ContractingSet

    source = """
members=Variable()
state=Variable()
@export
def fail():
    values=members.get()
    state.set(1)
    state.set([values,values,values])
    return 0
@export
def recover():
    assert state.get() is None
    state.set(7)
    return len(members.get())
"""
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_set_codec", source, owner=None)
        # Each root is independently admissible; only the complete payload exceeds
        # the aggregate 8,388,608 work cap: 3 * 1,700**2 == 8,670,000.
        driver.set("con_set_codec.members", ContractingSet(range(1700)))
        driver.commit()
        failed = _execute(driver, "fail", meter)
        assert failed.status_code == 1, failed.result
        assert "normalization work" in str(failed.result)
        assert failed.writes == {} and failed.events == []
        recovered = _execute(driver, "recover", meter)
        assert recovered.status_code == 0 and recovered.result == 1700, recovered.result
