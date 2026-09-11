"""Consensus ordering and bounded work for all native storage-scan surfaces."""

from pathlib import Path
from unittest.mock import patch

import pytest

from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native


def execute(driver, *, budget=10_000_000):
    import xian_vm_core

    return xian_vm_core.execute_contract(
        driver=driver,
        contract_name="con_scan",
        function_name="probe",
        kwargs={"target": "con_scan"},
        context={"signer": "alice", "caller": "alice", "this": "con_scan", "owner": None},
        meter=True,
        chi_budget_raw=budget,
    )


@pytest.mark.parametrize("scan", ["values.all()", "foreign.all()", "dynamic.all()"])
def test_scan_order_is_identical_across_executors_caches_and_overlays(tmp_path: Path, scan):
    source = f"""\nvalues = Hash()\nresult = Variable()\nforeign = ForeignHash(foreign_contract='con_scan', foreign_name='values')\n@export\ndef probe(target: str):\n    values['d'] = 4\n    values['b'] = 2\n    values['a'] = 1\n    values['c'] = 3\n    values['deleted'] = None\n    dynamic = ForeignHash(foreign_contract=target, foreign_name='values')\n    scanned = {scan}\n    result.set(scanned)\n    return scanned\n"""
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_scan", source, owner=None)
        for key, value in [("z", 5), ("deleted", 99), ("a", 9)]:
            driver.set_var("con_scan", "values", [key], value)
        driver.commit()
        for index in range(24):
            driver.cache.clear()
            # Different cache insertion histories must not change list order.
            for key in ["z", "a"] if index % 2 else ["a", "z"]:
                driver.get_var("con_scan", "values", [key])
            output = execute(driver)
            assert output.status_code == 0, output.result
            assert output.result == [1, 2, 3, 4, 5]
            assert output.writes["con_scan.result"] == [1, 2, 3, 4, 5]


@pytest.mark.parametrize("scan", ["values.all()", "foreign.all()", "dynamic.all()"])
def test_scan_stops_reading_when_chi_is_exhausted(tmp_path: Path, scan):
    source = f"""\nvalues = Hash()\nforeign = ForeignHash(foreign_contract='con_scan', foreign_name='values')\n@export\ndef probe(target: str):\n    dynamic = ForeignHash(foreign_contract=target, foreign_name='values')\n    return {scan}\n"""
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_scan", source, owner=None)
        for index in range(4000):
            driver.set_var("con_scan", "values", [str(index)], index)
        driver.commit()
        consumed = []
        original = driver._store.iter_items

        def observe(prefix):
            for key, value in original(prefix):
                consumed.append(key)
                yield key, value

        with patch.object(driver._store, "iter_items", side_effect=observe):
            output = execute(driver, budget=100_000)
        assert output.status_code != 0
        assert "Out of chi" in str(output.result)
        assert 0 < len(consumed) < 2000
        assert output.writes == {}


@pytest.mark.parametrize("scan", ["values.all()", "foreign.all()", "dynamic.all()"])
def test_scan_has_bounded_result_allocation(tmp_path, scan):
    source = f"""
values = Hash()
foreign = ForeignHash(foreign_contract='con_scan', foreign_name='values')
@export
def probe(target: str):
    dynamic = ForeignHash(foreign_contract=target, foreign_name='values')
    return {scan}
"""
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_scan", source, owner=None)
        for index in range(1000):
            driver.set_var("con_scan", "values", [str(index)], "x" * 256)
        driver.commit()
        output = execute(driver)
        assert output.status_code != 0
        assert "hash scan result exceeds allocation limit" in str(output.result)
        assert output.writes == {}


def test_scan_order_survives_fresh_process_hash_seeds(tmp_path):
    import json
    import os
    import subprocess
    import sys

    script = r"""
import json, sys
from pathlib import Path
from contracting.storage.driver import Driver
from xian_vm_core import execute_contract
source = '''
h = Hash()
result = Variable()
@export
def probe():
    h['d'] = 4
    h['b'] = 2
    h['c'] = 3
    h['a'] = 1
    result.set(h.all())
    return h.all()
'''
with Driver(storage_home=Path(sys.argv[1])) as driver:
    driver.set_contract_from_source('con_scan', source, owner=None)
    driver.commit()
    output = execute_contract(driver=driver, contract_name='con_scan', function_name='probe',
        kwargs={}, context={'signer':'alice','caller':'alice','this':'con_scan','owner':None},
        meter=True, chi_budget_raw=10000000)
    assert output.status_code == 0, output.result
    print(json.dumps(output.writes['con_scan.result']))
"""
    for seed in range(8):
        result = subprocess.run(
            [sys.executable, "-c", script, str(tmp_path / str(seed))],
            env={**os.environ, "PYTHONHASHSEED": str(seed)},
            capture_output=True,
            text=True,
            check=True,
        )
        assert json.loads(result.stdout.strip()) == [1, 2, 3, 4]


@pytest.mark.parametrize("scan", ["foreign.all()", "dynamic.all()"])
def test_foreign_scan_does_not_resurrect_cached_entries_after_nested_delete(tmp_path, scan):
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source(
            "con_data",
            """
values = Hash()
@export
def change():
    values['a'] = None
    values['b'] = 20
""",
            owner=None,
        )
        driver.set_contract_from_source(
            "con_scan",
            f"""
import con_data
foreign = ForeignHash(foreign_contract='con_data', foreign_name='values')
@export
def probe(target: str):
    dynamic = ForeignHash(foreign_contract='con_data', foreign_name='values')
    before = {scan}
    con_data.change()
    return [before, {scan}]
""",
            owner=None,
        )
        driver.set_var("con_data", "values", ["a"], 1)
        driver.set_var("con_data", "values", ["b"], 2)
        driver.commit()
        output = execute(driver)
        assert output.status_code == 0, output.result
        assert output.result == [[1, 2], [20]]
