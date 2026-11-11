"""Recursive authored contracts fail atomically without terminating the host."""

import subprocess
import sys
from pathlib import Path

import pytest

from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native


def _exercise(home, vm_profile, meter, mode):
    from xian_runtime_types.time import Datetime
    from xian_vm_core import execute_contract

    nested = "1 + (" * 20 + "recurse()" + ")" * 20
    sources = {
        "local": "def recurse():\n    return recurse()\n",
        "expression": f"def recurse():\n    return {nested}\n",
        "block": "def recurse():\n"
        + "".join("    " * (depth + 1) + "if True:\n" for depth in range(20))
        + "    " * 21
        + "return recurse()\n",
        "iterator": "def recurse():\n    cursor = [1]\n"
        "    for i in range(128):\n        cursor = map(abs, cursor)\n"
        "    return list(cursor)\n",
        "cross_contract": "import con_other\ndef recurse():\n    return con_other.probe()\n",
    }
    if mode == "constructor":
        child = (
            "@construct\ndef seed(depth: int):\n"
            "    if depth > 0:\n"
            "        importlib.import_module('submission').spawn(depth - 1)\n"
            "@export\ndef read():\n    return 1\n"
        )
        source = (
            f"CHILD = {child!r}\n"
            "@export\ndef spawn(depth: int):\n"
            "    Contract.deploy(name='con_depth_' + str(depth), code=CHILD, "
            "constructor_args={'depth': depth})\n"
            "    return 1\n"
            "def recurse():\n    return spawn(100)\n"
        )
        name = "submission"
    else:
        source = sources[mode]
        name = "con_depth"
    source += (
        "value = Variable()\n"
        "@export\ndef probe():\n    value.set(1)\n    return recurse()\n"
        "@export\ndef safe():\n    return 7\n"
    )
    with Driver(storage_home=home, vm_profile=vm_profile) as driver:
        if mode == "cross_contract":
            driver.set_contract_from_source(
                "con_other",
                "import con_depth\n@export\ndef probe():\n    return con_depth.probe()\n",
                owner=None,
            )
        driver.set_contract_from_source(name, source, owner=None)
        driver.commit()

        def invoke(function):
            return execute_contract(
                driver=driver,
                vm_profile=vm_profile,
                contract_name=name,
                function_name=function,
                kwargs={},
                context={
                    "caller": "alice",
                    "signer": "alice",
                    "this": name,
                    "now": Datetime(2026, 11, 11),
                },
                meter=meter,
                chi_budget_raw=50_000_000_000,
            )

        failed = invoke("probe")
        assert failed.status_code == 1, failed.result
        assert "VM execution depth limit exceeded" in str(failed.result), failed.result
        assert failed.writes == {}
        assert failed.events == []
        assert driver.get(name + ".value") is None
        assert not driver.has_contract("con_depth_100")
        recovered = invoke("safe")
        assert recovered.status_code == 0, recovered.result
        assert recovered.result == 7


@pytest.mark.parametrize("vm_profile", ["xian_vm_v1", "xian_vm_v2"])
@pytest.mark.parametrize("meter", [False, True])
@pytest.mark.parametrize(
    "mode", ["local", "expression", "block", "iterator", "cross_contract", "constructor"]
)
def test_shared_execution_depth_and_recovery(tmp_path, vm_profile, meter, mode):
    completed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            str(tmp_path),
            vm_profile,
            str(int(meter)),
            mode,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


if __name__ == "__main__":
    _exercise(Path(sys.argv[1]), sys.argv[2], bool(int(sys.argv[3])), sys.argv[4])
