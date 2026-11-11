"""Storage class metadata must not grant arbitrary contract write access."""

import pytest

from contracting.compilation.compiler import ContractingCompiler
from contracting.execution.executor import Executor
from contracting.execution.runtime import contract_execution_scope, orm_declaration_scope, rt
from contracting.stdlib.bridge import orm
from contracting.storage.contract import Contract
from contracting.storage.driver import Driver
from tests.compatibility.runner import encode, run_case

TARGET = """
balance = Variable(default_value=0)
ledger = Hash(default_value=0)

@export
def read_balance():
    return balance.get()
"""


@pytest.mark.parametrize("native", [False, pytest.param(True, marks=pytest.mark.optional_native)])
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
    tmp_path, native, storage_type, name, arguments, mutation
):
    actual = run_case(
        {
            "id": "orm_descriptor_escape",
            "dependencies": {"con_descriptor_target": TARGET},
            "source": "@export\ndef probe():\n"
            f"    factory = importlib.Var('x', {storage_type}).type\n"
            f"    foreign = factory(contract='con_descriptor_target', name='{name}'{arguments})\n"
            f"    {mutation}\n"
            "    return True\n",
        },
        tmp_path,
        native=native,
    )
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 1, actual
    assert actual["writes"] == encode({}), actual


@pytest.mark.parametrize("native", [False, pytest.param(True, marks=pytest.mark.optional_native)])
def test_declared_storage_and_readonly_foreign_storage_remain_usable(tmp_path, native):
    actual = run_case(
        {
            "id": "orm_declared_storage",
            "dependencies": {"con_descriptor_target": TARGET},
            "source": """
balance = Variable(default_value=0)
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
        },
        tmp_path,
        native=native,
    )
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode([7, 3, None, None]), actual


def test_trusted_host_can_construct_storage_directly(tmp_path):
    driver = Driver(storage_home=tmp_path)
    variable = orm.V(contract="host_setup", name="value", driver=driver)
    ledger = orm.H(contract="host_setup", name="ledger", driver=driver)
    variable.set(11)
    ledger["alice"] = 13
    assert variable.get() == 11
    assert ledger["alice"] == 13


@pytest.mark.parametrize("storage_class", [orm.V, orm.H, orm.FV, orm.FH, orm.LE])
def test_unpermitted_constructor_aliases_are_rejected(storage_class):
    factory = storage_class
    with contract_execution_scope(), pytest.raises(TypeError, match="module declarations"):
        factory(contract="foreign_contract", name="value")


def test_declaration_permit_is_single_use_and_bound_to_the_declaration(tmp_path, monkeypatch):
    monkeypatch.setattr(rt.context, "_base_state", {**rt.context._base_state, "this": "own"})
    driver = Driver(storage_home=tmp_path)
    with contract_execution_scope(), orm_declaration_scope(orm.V, "own", "value"):
        with pytest.raises(TypeError, match="module declarations"):
            orm.H(contract="own", name="value", driver=driver)
        with pytest.raises(TypeError, match="module declarations"):
            orm.V(contract="foreign", name="value", driver=driver)
        with pytest.raises(TypeError, match="module declarations"):
            orm.V(contract="own", name="different", driver=driver)
        variable = orm.V(contract="own", name="value", driver=driver)
        variable.set(7)
        with pytest.raises(TypeError, match="module declarations"):
            orm.V(contract="own", name="value", driver=driver)
    assert variable.get() == 7


def test_failed_declaration_cannot_leave_authority_for_later_calls(tmp_path):
    driver = Driver(storage_home=tmp_path)
    with contract_execution_scope():
        with pytest.raises(TypeError, match="unexpected keyword"):
            orm.declare_orm(orm.V, "own", "value", driver=driver, invalid=True)
        with pytest.raises(TypeError, match="module declarations"):
            orm.V(contract="own", name="value", driver=driver)
    # Both contexts are cleaned up on failure; host setup is still usable.
    variable = orm.V(contract="host", name="value", driver=driver)
    variable.set(9)
    assert variable.get() == 9


@pytest.mark.parametrize(
    "source",
    [
        # Module initialization must not itself confer declaration authority.
        "factory = importlib.Var('x', Variable).type\n"
        "foreign = factory(contract='victim', name='value')\n"
        "@export\ndef probe():\n    return True\n",
        # Old compiled artifacts have no authenticated declaration helper.
        "value = Variable(contract='legacy', name='value')\n"
        "@__export('legacy')\ndef probe():\n    return True\n",
    ],
)
def test_module_loading_rejects_dynamic_and_unguarded_legacy_storage(tmp_path, source):
    driver = Driver(storage_home=tmp_path, vm_profile="xian_vm_v1")
    driver.set_contract("legacy", source=source)
    output = Executor(driver=driver, metering=False).execute(
        sender="alice", contract_name="legacy", function_name="probe", kwargs={}
    )
    assert output["status_code"] == 1, output
    assert "module declarations" in str(output["result"])
    assert output["writes"] == {}


def test_deployment_constructor_cannot_create_dynamic_storage(tmp_path):
    driver = Driver(storage_home=tmp_path, vm_profile="xian_vm_v1")
    source = """
@construct
def seed():
    factory = importlib.Var('x', Variable).type
    foreign = factory(contract='victim', name='value')
    foreign.set(99)

@export
def probe():
    return True
"""
    with pytest.raises(TypeError, match="module declarations"):
        Contract(driver=driver).submit(name="con_dynamic_constructor", code=source)
    assert driver.get_var("victim", "value") is None
    assert not driver.has_contract("con_dynamic_constructor")


def test_declaration_arguments_run_without_a_permit(tmp_path):
    # An argument may call contract code before the private helper is invoked.
    source = """
def attempt():
    factory = importlib.Var('x', Variable).type
    foreign = factory(contract='victim', name='value')
    foreign.set(99)
    return 0

value = Variable(default_value=attempt())

@export
def probe():
    return value.get()
"""
    driver = Driver(storage_home=tmp_path, vm_profile="xian_vm_v1")
    driver.set_contract("con_argument_attack", source=source)
    output = Executor(driver=driver, metering=False).execute(
        sender="alice", contract_name="con_argument_attack", function_name="probe", kwargs={}
    )
    assert output["status_code"] == 1, output
    assert "module declarations" in str(output["result"])
    assert output["writes"] == {}


def test_only_direct_module_storage_declarations_receive_permits():
    source = """
value = Variable()
@export
def probe():
    other = Variable()
    return other.get()
"""
    transformed = ContractingCompiler(module_name="con_scope").parse_to_code(
        source, lint=False, vm_profile="xian_vm_v1"
    )
    assert transformed.count("__xian_orm_declaration__(") == 1
    assert "other = Variable(" in transformed


def test_authored_source_cannot_name_private_declaration_helper():
    from contracting.compilation.linter import LintingError

    source = "@export\ndef probe():\n    return __xian_orm_declaration__(Variable, 'victim', 'x')\n"
    with pytest.raises(LintingError):
        ContractingCompiler(module_name="con_forged_permit").parse(source, vm_profile="xian_vm_v1")


def test_declaration_helper_rejects_nonstorage_callables():
    invoked = []

    def fake_storage(*args, **kwargs):
        invoked.append((args, kwargs))

    with contract_execution_scope(), pytest.raises(TypeError, match="Invalid storage"):
        orm.declare_orm(fake_storage, "victim", "value")
    assert invoked == []


def test_legacy_declaration_works_only_with_verified_local_ownership(tmp_path):
    driver = Driver(storage_home=tmp_path, vm_profile="xian_vm_v1")
    driver.set_contract(
        "legacy",
        source="__value = Variable(contract='legacy', name='value')\n"
        "@__export('legacy')\ndef probe():\n    __value.set(23)\n    return __value.get()\n",
    )
    output = Executor(driver=driver, metering=False).execute(
        sender="alice", contract_name="legacy", function_name="probe", kwargs={}
    )
    assert output["status_code"] == 0, output
    assert output["result"] == 23
    assert output["writes"] == {"legacy.value": 23}


@pytest.mark.parametrize(
    "declaration",
    [
        "__value = Variable(contract='victim', name='value')",
        "__value = Variable(contract='legacy', name='other')",
        "__value = Variable(contract='legacy', name=7)",
        "__value = Variable(contract='legacy', **{'name': 'value'})",
        "__value = alias = Variable(contract='legacy', name='value')",
        "factory = Variable\n__value = factory(contract='legacy', name='value')",
    ],
)
def test_legacy_metadata_cannot_authorize_forged_declarations(tmp_path, declaration):
    driver = Driver(storage_home=tmp_path, vm_profile="xian_vm_v1")
    driver.set_contract(
        "legacy",
        source=declaration + "\n@__export('legacy')\ndef probe():\n    return True\n",
    )
    output = Executor(driver=driver, metering=False).execute(
        sender="alice", contract_name="legacy", function_name="probe", kwargs={}
    )
    assert output["status_code"] == 1, output
    assert "module declarations" in str(output["result"])
    assert output["writes"] == {}


@pytest.mark.parametrize("native", [False, pytest.param(True, marks=pytest.mark.optional_native)])
@pytest.mark.parametrize("mutate", [False, True])
def test_function_local_foreign_references_preserve_readonly_own_state(tmp_path, native, mutate):
    source = "value = Variable()\nledger = Hash()\n@export\ndef probe():\n"
    source += (
        "    value.set(7)\n    ledger['alice'] = 9\n"
        "    v = ForeignVariable(foreign_contract=ctx.this, foreign_name='value')\n"
        "    h = ForeignHash(foreign_contract=ctx.this, foreign_name='ledger')\n"
    )
    source += "    v.set(99)\n" if mutate else "    return [v.get(), h['alice']]\n"
    actual = run_case({"id": "local_foreign_reference", "source": source}, tmp_path, native=native)
    assert actual["admission"] == "accepted", actual
    if mutate:
        assert actual["status_code"] == 1, actual
        assert actual["writes"] == encode({}), actual
    else:
        assert actual["status_code"] == 0, actual
        assert actual["result"] == encode([7, 9]), actual


@pytest.mark.parametrize("storage_class", [orm.V, orm.H, orm.LE])
def test_dynamic_foreign_helper_cannot_be_redirected_to_writable_classes(storage_class):
    with contract_execution_scope(), pytest.raises(TypeError, match="read-only foreign"):
        orm.declare_foreign_orm(storage_class, "victim", "value")


def test_dynamic_foreign_declaration_cannot_override_compiler_ownership(tmp_path):
    actual = run_case(
        {
            "id": "foreign_owner_override",
            "source": "@export\ndef probe():\n"
            "    h = ForeignHash(foreign_contract='victim', foreign_name='value', "
            "contract='victim', name='owned')\n    return h['x']\n",
        },
        tmp_path,
        native=False,
    )
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 1, actual
    assert actual["writes"] == encode({}), actual
