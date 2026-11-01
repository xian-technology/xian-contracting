"""Imported callable metadata keeps module initialization and authority intact."""

import pytest

from contracting.compilation.compiler import ContractingCompiler
from contracting.compilation.lowering import IrLoweringError
from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native


def execute(driver, contract="con_alias_probe", *, meter=False, budget=100_000_000):
    from xian_vm_core import execute_contract

    return execute_contract(
        driver=driver,
        contract_name=contract,
        function_name="probe",
        kwargs={},
        context={"caller": "alice", "signer": "alice", "this": contract},
        meter=meter,
        chi_budget_raw=budget,
    )


@pytest.mark.parametrize("meter", [False, True])
@pytest.mark.parametrize("static", [False, True])
def test_alias_cache_observes_final_initialized_binding(tmp_path, meter, static):
    target = "alias = abs\nalias = len\n@export\ndef noop():\n    return 0\n"
    prefix = "import con_alias_target as target\n" if static else ""
    lookup = "" if static else "    target = importlib.import_module('con_alias_target')\n"
    caller = prefix + "@export\ndef probe():\n" + lookup + "    return target.alias([1,2,3])\n"
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_alias_target", target, owner=None)
        driver.set_contract_from_source("con_alias_probe", caller, owner=None)
        driver.commit()
        result = execute(driver, meter=meter)
        assert result.status_code == 0, result.result
        assert result.result == 3


@pytest.mark.parametrize("meter", [False, True])
def test_active_caller_alias_lookup_uses_initialized_metadata(tmp_path, meter):
    target = """@export
def inspect_caller():
    caller = importlib.import_module(ctx.caller)
    return caller.alias([1,2,3,4])
"""
    caller = """alias = len
@export
def probe():
    target = importlib.import_module('con_alias_target')
    return [target.inspect_caller(), target.inspect_caller()]
"""
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_alias_target", target, owner=None)
        driver.set_contract_from_source("con_alias_probe", caller, owner=None)
        driver.commit()
        result = execute(driver, meter=meter)
        assert result.status_code == 0, result.result
        assert result.result == [4, 4]


@pytest.mark.parametrize("meter", [False, True])
@pytest.mark.parametrize("owner", ["con_alias_probe", "bob"])
def test_export_alias_retains_canonical_target_owner_and_context(tmp_path, meter, owner):
    target = """initial = [ctx.this, ctx.caller, ctx.owner, ctx.signer]
@export
def identify():
    return [initial, ctx.this, ctx.caller, ctx.owner, ctx.signer]
alias = identify
"""
    caller = """@export
def probe():
    target = importlib.import_module('con_alias_target')
    return target.alias()
"""
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_alias_target", target, owner=owner)
        driver.set_contract_from_source("con_alias_probe", caller, owner=None)
        driver.commit()
        result = execute(driver, meter=meter)
        if owner == "bob":
            assert result.status_code == 1, result.result
            assert "Caller is not the owner" in str(result.result)
            assert result.writes == {} and result.events == []
        else:
            assert result.status_code == 0, result.result
            assert result.result == [
                ["con_alias_target", "con_alias_probe", owner, "alice"],
                "con_alias_target",
                "con_alias_probe",
                owner,
                "alice",
            ]


def test_circular_alias_initialization_fails_and_independent_call_recovers(tmp_path):
    first = """alias = importlib.import_module('con_alias_cycle_b').alias
@export
def probe():
    return 1
"""
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_alias_cycle_a", first, owner=None)
        driver.set_contract_from_source(
            "con_alias_cycle_b", first.replace("con_alias_cycle_b", "con_alias_cycle_a"), owner=None
        )
        driver.set_contract_from_source(
            "con_alias_probe", "@export\ndef probe():\n    return 7\n", owner=None
        )
        driver.commit()
        failed = execute(driver, "con_alias_cycle_a")
        assert failed.status_code == 1 and "circular module initialization" in str(failed.result)
        assert failed.writes == {} and failed.events == []
        recovered = execute(driver)
        assert recovered.status_code == 0 and recovered.result == 7


def test_function_cannot_rebind_module_globals_after_metadata_is_cached():
    source = "alias = len\n@export\ndef probe():\n    global alias\n    alias = abs\n"
    with pytest.raises(IrLoweringError, match="[Gg]lobal"):
        ContractingCompiler(module_name="con_alias_global").lower_to_ir(source)


def test_alias_catalog_and_repeated_lookups_are_bounded_by_chi(tmp_path):
    names = [f"alias{index:04d}" for index in range(256)]
    target = "\n".join(f"{name} = len" for name in names) + "\n"
    target += "@export\ndef noop():\n    return 0\n"
    caller = """state = Variable()
@export
def probe():
    state.set(1)
    target = importlib.import_module('con_alias_target')
    result = 0
    for index in range(128):
        result += target.alias0255([1,2,3])
    return result
"""
    # Independent lower bound from names and descriptor payloads, without using
    # measured execution totals. Each len descriptor copies four bytes of work;
    # the one exported function names its sixteen-byte owning module.
    metadata_work = (
        sum(len(name) + 1 + len("len") + 1 for name in names)
        + len("noop")
        + len("con_alias_target")
        + 2
        + 1
    ) * (len(names) + 1 + 1).bit_length()
    lookup_work = 128 * (len("alias0255") + len("len") + 1)
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_alias_target", target, owner=None)
        driver.set_contract_from_source("con_alias_probe", caller, owner=None)
        driver.set_contract_from_source(
            "con_alias_recovery", "@export\ndef probe():\n    return 7\n", owner=None
        )
        driver.commit()
        completed = execute(driver, meter=True)
        assert completed.status_code == 0 and completed.result == 384, completed.result
        assert completed.raw_cost >= metadata_work + lookup_work
        failed = execute(driver, meter=True, budget=metadata_work + lookup_work - 1)
        assert failed.status_code == 1 and "Out of chi" in str(failed.result), failed.result
        assert failed.writes == {} and failed.events == []
        recovered = execute(driver, "con_alias_recovery", meter=True)
        assert recovered.status_code == 0 and recovered.result == 7
