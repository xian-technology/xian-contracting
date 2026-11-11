"""Bulk storage behavior follows the current ORM, with bounded native execution."""

import json
from pathlib import Path

import pytest

from tests.integration.pre_retirement_oracle import recorded_python_observation
from tests.integration.test_vm_language_conformance import _run_native_case

pytestmark = pytest.mark.optional_native

CASES = json.loads(Path(__file__).with_name("storage_bulk_cases.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_bulk_storage_matches_current_orm(tmp_path, case):
    expected = recorded_python_observation(case)
    if case["id"] not in {
        "hash_clone_reject_variable",
        "hash_clear_rollback",
        "hash_clone_rollback",
    }:
        assert expected["status_code"] == 0, expected
    actual = _run_native_case(case, tmp_path / "native")
    if expected["status_code"] != 0:
        assert actual["status_code"] == expected["status_code"]
        assert actual["writes"] == expected["writes"] == {}
        assert actual["events"] == expected["events"] == []
    else:
        assert actual == expected


def test_clear_records_transaction_tombstones(tmp_path):
    from contracting.storage.driver import Driver
    from contracting.storage.orm import Hash

    with Driver(storage_home=tmp_path) as driver:
        values = Hash("con_clear", "h", driver=driver)
        values["keep"] = 1
        values["remove", "one"] = 2
        values.clear("remove")
        assert driver.transaction_writes["con_clear.h:remove:one"] is None
        assert driver.transaction_writes["con_clear.h:keep"] == 1


@pytest.mark.parametrize("expression", ["h.all('a')", "[h['a', 'one'],h['a']]"])
def test_clear_prefix_and_default_value(tmp_path, expression):
    case = {
        "id": "bulk_default",
        "source": "h=Hash(default_value=7)\n@export\ndef probe():\n    h['a']=3\n    h['a','one']=1\n    h.clear('a')\n    return "
        + expression
        + "\n",
        "function_name": "probe",
        "kwargs": {},
    }
    assert _run_native_case(case, tmp_path / "native") == recorded_python_observation(case)


@pytest.mark.parametrize("operation", ["h.clear()", "g.clone_from(h)"])
@pytest.mark.parametrize("count", [100, 2000])
def test_bulk_scan_is_metered_and_rolls_back(tmp_path, operation, count):
    from unittest.mock import patch

    from xian_vm_core import execute_contract

    from contracting.storage.driver import Driver

    source = (
        "h=Hash()\ng=Hash()\nprogress=Variable()\n@export\ndef probe():\n    progress.set(1)\n    "
        + operation
        + "\n"
    )
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_bulk", source, owner=None)
        for i in range(count):
            driver.set_var("con_bulk", "h", [str(i)], i)
        driver.commit()
        consumed = []
        original = driver._store.iter_items

        def observe(prefix):
            for item in original(prefix):
                consumed.append(item)
                yield item

        with patch.object(driver._store, "iter_items", side_effect=observe):
            output = execute_contract(
                driver=driver,
                contract_name="con_bulk",
                function_name="probe",
                kwargs={},
                context={"caller": "alice", "signer": "alice", "this": "con_bulk"},
                meter=True,
                chi_budget_raw=30_000,
            )
        assert output.status_code == 1 and "Out of chi" in str(output.result)
        assert output.writes == {} and output.events == []
        assert 0 < len(consumed) < 1000


@pytest.mark.parametrize("fail", [False, True])
def test_nested_clear_and_foreign_clone_observe_pending_writes(tmp_path, fail):
    child = """h=Hash(default_value=0)
@export
def seed():
    h['a']=1
    h['a','b']=2
@export
def clear():
    h.clear()
    return h['a']
"""
    source = """import con_bulk_child
f=ForeignHash(foreign_contract='con_bulk_child',foreign_name='h')
g=Hash()
@export
def probe():
    con_bulk_child.seed()
    before=f['a']
    g.clone_from(f)
    cleared=con_bulk_child.clear()
    after=f['a']
"""
    source += (
        "    raise Exception('rollback')\n"
        if fail
        else "    return [before,cleared,after,g['a'],g['a','b']]\n"
    )
    case = {
        "id": "bulk_nested",
        "source": source,
        "function_name": "probe",
        "kwargs": {},
        "dependencies": [{"name": "con_bulk_child", "source": child, "owner": None}],
    }
    expected = recorded_python_observation(case)
    actual = _run_native_case(case, tmp_path / "native")
    if fail:
        assert actual["status_code"] == expected["status_code"] == 1
        assert actual["writes"] == expected["writes"] == {}
        assert actual["events"] == expected["events"] == []
    else:
        assert expected["result"] == [1, 0, None, 1, 2]
        assert actual == expected


def test_foreign_variable_observes_nested_deletion(tmp_path):
    child = "v=Variable()\n@export\ndef put(value: Any):\n    v.set(value)\n"
    case = {
        "id": "bulk_foreign_variable",
        "source": "import con_bulk_child\nf=ForeignVariable(foreign_contract='con_bulk_child',foreign_name='v')\n@export\ndef probe():\n    con_bulk_child.put(value=1)\n    before=f.get()\n    con_bulk_child.put(value=None)\n    return [before,f.get()]\n",
        "function_name": "probe",
        "kwargs": {},
        "dependencies": [{"name": "con_bulk_child", "source": child, "owner": None}],
    }
    expected = recorded_python_observation(case)
    assert expected["result"] == [1, None]
    assert _run_native_case(case, tmp_path / "native") == expected
