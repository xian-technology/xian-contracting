"""Native declarations cannot grant foreign write authority."""

import pytest

from contracting.local import ContractingClient
from contracting.storage.driver import Driver
from contracting.storage.orm import Hash, Variable

TARGET = """balance = Variable(default_value=0)
ledger = Hash(default_value=0)
@export
def read_balance():
    return balance.get()
"""


def run_native(tmp_path, source, *, dependencies=None):
    with ContractingClient(storage_home=tmp_path, metering=False) as client:
        for name, dependency in (dependencies or {}).items():
            client.submit(dependency, name=name)
        output = client.get_contract_proxy("submission").submit_contract(
            name="con_probe", code=source, return_full_output=True
        )
        if output["status_code"] == 0:
            output = client.get_contract_proxy("con_probe").probe(return_full_output=True)
        return output


@pytest.mark.parametrize(
    ("storage_type", "name", "arguments", "mutation"),
    [
        ("Variable", "balance", "", "foreign.set(99)"),
        ("Hash", "ledger", "", "foreign['alice'] = 99"),
        (
            "ForeignVariable",
            "balance",
            ", foreign_contract='con_descriptor_target', foreign_name='balance'",
            "foreign.get()",
        ),
        (
            "ForeignHash",
            "ledger",
            ", foreign_contract='con_descriptor_target', foreign_name='ledger'",
            "foreign['alice']",
        ),
        ("LogEvent", "Event", ", event='Forged', params={'value': int}", "foreign({'value': 99})"),
    ],
)
def test_descriptor_class_cannot_construct_foreign_writable_storage(
    tmp_path, storage_type, name, arguments, mutation
):
    output = run_native(
        tmp_path,
        "@export\ndef probe():\n"
        f"    factory = importlib.Var('x', {storage_type}).type\n"
        f"    foreign = factory(contract='con_descriptor_target', name='{name}'{arguments})\n"
        f"    {mutation}\n    return True\n",
        dependencies={"con_descriptor_target": TARGET},
    )
    assert output["status_code"] == 1, output
    assert output["writes"] == {}
    assert output["events"] == []


def test_declared_storage_and_readonly_foreign_storage_remain_usable(tmp_path):
    output = run_native(
        tmp_path,
        """balance = Variable(default_value=0)
ledger = Hash(default_value=0)
foreign_balance = ForeignVariable(foreign_contract='con_descriptor_target', foreign_name='balance')
foreign_ledger = ForeignHash(foreign_contract='con_descriptor_target', foreign_name='ledger')
Changed = LogEvent(event='Changed', params={'value': int})
@export
def probe():
    balance.set(7)
    ledger['alice'] = 3
    Changed({'value': 7})
    return [balance.get(), ledger['alice'], foreign_balance.get(), foreign_ledger['alice']]
""",
        dependencies={"con_descriptor_target": TARGET},
    )
    assert output["status_code"] == 0, output
    assert output["result"] == [7, 3, None, None]
    assert output["writes"] == {"con_probe.balance": 7, "con_probe.ledger:alice": 3}
    assert len(output["events"]) == 1


def test_trusted_host_can_construct_storage_directly(tmp_path):
    with Driver(storage_home=tmp_path) as driver:
        variable = Variable(contract="host_setup", name="value", driver=driver)
        ledger = Hash(contract="host_setup", name="ledger", driver=driver)
        variable.set(11)
        ledger["alice"] = 13
        assert variable.get() == 11
        assert ledger["alice"] == 13


@pytest.mark.parametrize("stage", ["module", "constructor", "function", "argument"])
def test_dynamic_storage_creation_never_receives_declaration_authority(tmp_path, stage):
    attack = "    factory = importlib.Var('x', Variable).type\n"
    attack += "    foreign = factory(contract='victim', name='value')\n    foreign.set(99)\n"
    if stage == "module":
        source = attack.replace("    ", "") + "@export\ndef probe():\n    return True\n"
    elif stage == "constructor":
        source = "@construct\ndef seed():\n" + attack + "@export\ndef probe():\n    return True\n"
    elif stage == "argument":
        source = "def attempt():\n" + attack + "    return 0\n"
        source += "value = Variable(default_value=attempt())\n@export\ndef probe():\n    return value.get()\n"
    else:
        source = "@export\ndef probe():\n" + attack + "    return True\n"
    output = run_native(tmp_path, source)
    assert output["status_code"] == 1, output
    assert output["writes"] == {}
    assert output["events"] == []
    with Driver(storage_home=tmp_path) as driver:
        assert driver.get_var("victim", "value") is None


def test_authored_source_cannot_name_private_declaration_helper(tmp_path):
    source = "@export\ndef probe():\n    return __xian_orm_declaration__(Variable, 'victim', 'x')\n"
    with ContractingClient(storage_home=tmp_path) as client:
        with pytest.raises(Exception, match="underscore|private"):
            client.submit(source, name="con_forged_permit")
        assert not client.raw_driver.has_contract("con_forged_permit")


@pytest.mark.parametrize("mutate", [False, True])
def test_function_local_foreign_references_preserve_readonly_own_state(tmp_path, mutate):
    source = "value = Variable()\nledger = Hash()\n@export\ndef probe():\n"
    source += "    value.set(7)\n    ledger['alice'] = 9\n"
    source += "    v = ForeignVariable(foreign_contract=ctx.this, foreign_name='value')\n"
    source += "    h = ForeignHash(foreign_contract=ctx.this, foreign_name='ledger')\n"
    source += "    v.set(99)\n" if mutate else "    return [v.get(), h['alice']]\n"
    output = run_native(tmp_path, source)
    if mutate:
        assert output["status_code"] == 1, output
        assert output["writes"] == {}
    else:
        assert output["status_code"] == 0, output
        assert output["result"] == [7, 9]


def test_dynamic_foreign_declaration_cannot_override_compiler_ownership(tmp_path):
    output = run_native(
        tmp_path,
        "@export\ndef probe():\n"
        "    h = ForeignHash(foreign_contract='victim', foreign_name='value', "
        "contract='victim', name='owned')\n    h['x'] = 99\n    return h['x']\n",
    )
    assert output["status_code"] == 1, output
    assert output["writes"] == {}
