"""Real native transactions enforce the V2 entry policy (V1 no longer executes)."""

import hashlib

import pytest
from xian_vm_core import runtime_info
from tests.vm_calls import execute_contract

from contracting import constants
from contracting.artifacts import compile_contract_source
from contracting.local import ContractingClient
from contracting.storage.driver import Driver

PROFILES = ("xian_vm_v2",)
ENTRY_SOURCE = """stored = Variable()
@construct
def seed(initial: int = 7):
    stored.set(initial)
def hidden():
    stored.set(99)
    return stored.get()
@export
def through_helper():
    return hidden()
@export
def read():
    return stored.get()
"""
HASH_SOURCE = """marker = Variable()
@export
def positional(target: str, kind: Any = None):
    marker.set(1)
    return importlib.code_hash(target, kind)
@export
def keyword(target: str, kind: Any = None):
    marker.set(1)
    return importlib.code_hash(target, kind=kind)
@export
def omitted(target: str):
    marker.set(1)
    return importlib.code_hash(target)
"""


@pytest.fixture
def native_store(tmp_path, profile):
    with Driver(storage_home=tmp_path / "native", vm_profile=profile) as driver:
        for name, source in (
            ("con_entry", ENTRY_SOURCE),
            ("con_probe", HASH_SOURCE),
            ("con_target", "@export\ndef answer():\n    return 17\n"),
        ):
            compiled = compile_contract_source(module_name=name, source=source, vm_profile=profile)
            driver.set_contract(
                name=name, source=compiled["source"], vm_ir_json=compiled["vm_ir_json"]
            )
        driver.set_var("con_entry", "stored", value=7)
        driver.set_var("con_probe", "marker", value=0)
        driver.commit()
        yield driver


def execute(driver, contract, function, *, caller="alice", **kwargs):
    return execute_contract(
        driver=driver,
        contract_name=contract,
        function_name=function,
        kwargs=kwargs,
        context={"caller": caller, "signer": caller},
    )


def assert_rejected(result):
    assert result.status_code == 1
    assert result.writes == {}
    assert result.events == []


def test_only_the_v2_profile_has_an_execution_revision():
    assert runtime_info("xian_vm_v2")["execution_revision"] == "xvm-execution-14"
    # V1 execution was removed from current code (it replays on its pinned release).
    with pytest.raises(ValueError, match="unknown VM profile"):
        runtime_info("xian_vm_v1")


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("function", ["hidden", "seed"])
def test_external_private_and_constructor_entries_follow_profile_policy(
    native_store, profile, function
):
    kwargs = {"initial": 123} if function == "seed" else {}
    result = execute(native_store, "con_entry", function, **kwargs)
    assert_rejected(result)
    assert "not exported" in str(result.result)
    assert result.chi_used == constants.TRANSACTION_BASE_CHI
    assert result.contract_costs == {}
    assert native_store.get_var("con_entry", "stored") == 7


@pytest.mark.parametrize("profile", PROFILES)
def test_exported_entrypoint_can_call_a_private_helper(native_store, profile):
    result = execute(native_store, "con_entry", "through_helper")
    assert result.status_code == 0, result.result
    assert result.result == 99
    assert result.writes["con_entry.stored"] == 99
    native_store.apply_writes(result.writes)
    native_store.commit()
    assert execute(native_store, "con_entry", "read").result == 99


@pytest.mark.parametrize("profile", PROFILES)
def test_unknown_function_is_rejected_without_writes(native_store, profile):
    result = execute(native_store, "con_entry", "missing")
    assert_rejected(result)
    assert native_store.get_var("con_entry", "stored") == 7


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("function", ["read", "hidden", "seed"])
def test_owner_denial_precedes_visibility_checks(native_store, profile, function):
    native_store.set_var("con_entry", "__owner__", value="owner")
    native_store.commit()
    result = execute(native_store, "con_entry", function, caller="intruder")
    assert_rejected(result)
    assert str(result.result) == "Caller is not the owner!"
    permitted = execute(native_store, "con_entry", "read", caller="owner")
    assert permitted.status_code == 0, permitted.result
    assert permitted.result == 7


def test_v2_trusted_deployment_runs_constructor_and_internal_helper(tmp_path):
    with ContractingClient(storage_home=tmp_path / "client") as client:
        client.submit(ENTRY_SOURCE, name="con_deployed", constructor_args={"initial": 17})
        contract = client.get_contract_proxy("con_deployed")
        assert contract.read() == 17
        assert contract.through_helper() == 99
        assert contract.read() == 99


def expected_hash(driver, target, kind):
    if target == "con_missing":
        return None
    text = (
        driver.get_contract_source(target) if kind == "source" else driver.get_contract_ir(target)
    )
    return hashlib.sha3_256(text.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("target", ["con_target", "con_missing"])
@pytest.mark.parametrize("function", ["positional", "keyword"])
@pytest.mark.parametrize("kind", [None, "runtime", "ir", "source"])
def test_code_hash_supported_selectors_match_persisted_artifacts(
    native_store, profile, target, function, kind
):
    result = execute(native_store, "con_probe", function, target=target, kind=kind)
    assert result.status_code == 0, result.result
    assert result.result == expected_hash(native_store, target, kind)
    assert result.writes["con_probe.marker"] == 1
    assert native_store.get_var("con_probe", "marker") == 0


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("target", ["con_target", "con_missing"])
def test_code_hash_omitted_selector_uses_ir(native_store, profile, target):
    result = execute(native_store, "con_probe", "omitted", target=target)
    assert result.status_code == 0, result.result
    assert result.result == expected_hash(native_store, target, "ir")
    assert result.writes["con_probe.marker"] == 1


@pytest.mark.parametrize("profile", ["xian_vm_v2"])
@pytest.mark.parametrize("target", ["con_target", "con_missing"])
@pytest.mark.parametrize("function", ["positional", "keyword"])
@pytest.mark.parametrize("kind", ["compiled", "", False, 0, 1, [], {}])
def test_v2_invalid_hash_selectors_roll_back_preceding_writes(
    native_store, profile, target, function, kind
):
    result = execute(native_store, "con_probe", function, target=target, kind=kind)
    assert_rejected(result)
    assert "Hash kind must be 'ir' or 'source'!" in str(result.result)
    assert native_store.get_var("con_probe", "marker") == 0
