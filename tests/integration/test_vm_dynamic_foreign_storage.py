"""Function-local foreign reads execute in the VM without writable capabilities."""

import pytest

from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native


DATA_SOURCE = """
metadata = Hash()
value = Variable()

@export
def change():
    metadata['standard'] = 'updated'
    value.set(9)
"""


def _data_driver(storage_home, profile):
    driver = Driver(storage_home=storage_home, vm_profile=profile)
    driver.set_contract_from_source("con_data", DATA_SOURCE, owner=None)
    driver.set_var("con_data", "metadata", ["standard"], "XSC-0005")
    driver.set_var("con_data", "metadata", ["nested"], [1, 2])
    driver.set_var("con_data", "metadata", ["group", "a"], 3)
    driver.set_var("con_data", "value", value=7)
    driver.commit()
    return driver


@pytest.fixture
def driver(tmp_path):
    with _data_driver(tmp_path / "native", "xian_vm_v2") as driver:
        yield driver


def run(driver, body, *, meter=False, budget=10000000, kwargs=None):
    source = "@export\ndef probe(contract: str):\n" + "\n".join(
        "    " + line for line in body.splitlines()
    )
    driver.set_contract_from_source("con_probe", source, owner="alice", overwrite=True)
    driver.commit()
    params = {"contract": "con_data", **(kwargs or {})}
    context = {"signer": "alice", "caller": "alice", "this": "con_probe", "owner": "alice"}
    import xian_vm_core

    return xian_vm_core.execute_contract(
        driver=driver,
        contract_name="con_probe",
        function_name="probe",
        kwargs=params,
        context=context,
        meter=meter,
        chi_budget_raw=budget,
    )


@pytest.mark.parametrize(
    "body,expected",
    [
        (
            "h = ForeignHash(foreign_contract=contract, foreign_name='metadata')\nreturn h['standard']",
            "XSC-0005",
        ),
        (
            "h = ForeignHash(foreign_contract=contract, foreign_name='metadata')\nreturn h['missing']",
            None,
        ),
        (
            "h = ForeignHash(foreign_contract=contract, foreign_name='metadata')\nreturn h['group', 'a']",
            3,
        ),
        (
            "h = ForeignHash(foreign_contract=contract, foreign_name='metadata')\nreturn h.all('group')",
            [3],
        ),
        ("v = ForeignVariable(foreign_contract=contract, foreign_name='value')\nreturn v.get()", 7),
        (
            "v = ForeignVariable(foreign_contract=contract, foreign_name='missing')\nreturn v.get()",
            None,
        ),
        (
            "h = ForeignHash(foreign_contract=contract, foreign_name='metadata')\na = h\nh = ForeignHash(foreign_contract=contract, foreign_name='other')\nreturn [a['standard'], h['standard']]",
            ["XSC-0005", None],
        ),
        (
            "h = ForeignHash(foreign_contract=contract, foreign_name='metadata')\na = h['nested']\na.append(3)\nreturn [a, h['nested']]",
            [[1, 2, 3], [1, 2]],
        ),
    ],
)
def test_dynamic_reads_match_independent_expectations(driver, body, expected):
    native = run(driver, body)
    assert native.status_code == 0, native.result
    assert native.result == expected
    assert native.writes == {}


def test_reference_aliases_in_containers(driver):
    output = run(
        driver,
        "h = ForeignHash(foreign_contract=contract, foreign_name='metadata')\nrefs = [h]\nreturn refs[0]['standard']",
    )
    assert output.status_code == 0, output.result
    assert output.result == "XSC-0005"


def test_repeated_reads_observe_cross_contract_writes(driver):
    output = run(
        driver,
        "h = ForeignHash(foreign_contract=contract, foreign_name='metadata')\nv = ForeignVariable(foreign_contract=contract, foreign_name='value')\nold = [h['standard'], v.get()]\nmodule = importlib.import_module(contract)\nmodule.change()\nreturn [old, h['standard'], v.get()]",
    )
    assert output.status_code == 0, output.result
    assert output.result == [["XSC-0005", 7], "updated", 9]


@pytest.mark.parametrize(
    "operation",
    [
        "h['standard'] = 'bad'",
        "h['group', 'a'] += 1",
        "h.clear()",
        "h.clone_from(h)",
        "v.set(99)",
        "v.append(99)",
    ],
)
def test_foreign_writes_fail_without_state_changes(driver, operation):
    output = run(
        driver,
        "h = ForeignHash(foreign_contract=contract, foreign_name='metadata')\nv = ForeignVariable(foreign_contract=contract, foreign_name='value')\n"
        + operation,
    )
    assert output.status_code == 1
    assert "cannot write to foreign storage" in str(output.result)
    assert output.writes == {}
    assert output.events == []
    assert driver.get_var("con_data", "metadata", ["standard"]) == "XSC-0005"
    assert driver.get_var("con_data", "value") == 7


@pytest.mark.parametrize(
    "target", ["", "con_data.metadata", "con_data:metadata", "../con_data", "con_data\x00"]
)
def test_targets_cannot_escape_storage_namespace(driver, target):
    output = run(
        driver,
        "h = ForeignHash(foreign_contract=contract, foreign_name='metadata')\nreturn h['standard']",
        kwargs={"contract": target},
    )
    assert output.status_code == 1
    assert "invalid foreign_contract identifier" in str(output.result)
    assert output.writes == {}


def test_read_charges_and_budget_are_enforced(driver):
    single = (
        "h = ForeignHash(foreign_contract=contract, foreign_name='metadata')\nreturn h['standard']"
    )
    double = "h = ForeignHash(foreign_contract=contract, foreign_name='metadata')\na = h['standard']\nreturn h['standard']"
    first = run(driver, single, meter=True)
    second = run(driver, double, meter=True)
    assert first.status_code == second.status_code == 0
    assert second.raw_cost > first.raw_cost > 0
    exhausted = run(driver, double, meter=True, budget=first.raw_cost)
    assert exhausted.status_code == 1
    assert exhausted.writes == {}


@pytest.mark.parametrize("operation", ["h['nested'].append(3)", "h['nested'][0] = 9"])
def test_foreign_read_returns_a_mutable_detached_copy(driver, operation):
    body = (
        "h = ForeignHash(foreign_contract=contract, foreign_name='metadata')\n"
        + operation
        + "\nreturn h['nested']"
    )
    actual = run(driver, body)
    assert actual.status_code == 0
    assert actual.result == [1, 2]
    assert actual.writes == {}
    assert driver.get_var("con_data", "metadata", ["nested"]) == [1, 2]
