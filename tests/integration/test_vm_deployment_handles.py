"""Deployment helpers preserve submission authority and constructor atomicity."""

import pytest
from xian_runtime_types.time import Datetime

from contracting.local import ContractingClient
from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native


CHILD = """seen = Variable()
@construct
def seed(label: str = 'created'):
    seen.set([ctx.this, ctx.caller, ctx.signer, ctx.owner, label])
@export
def read():
    return seen.get()
"""


def execute(home, body, *, module="submission", child=CHILD, target=None):
    source = f"state = Variable()\nCHILD = {child!r}\n@export\ndef probe():\n" + "".join(
        "    " + line + "\n" for line in body.splitlines()
    )
    if target is not None:
        source = "import con_target\n" + source
    with Driver(storage_home=home, vm_profile="xian_vm_v2") as driver:
        if target is not None:
            driver.set_contract_from_source("con_target", target, owner=None)
        driver.set_contract_from_source(module, source, owner=None)
        driver.commit()
        context = {
            "caller": "alice",
            "signer": "alice",
            "this": module,
            "entry": (module, "probe"),
            "now": Datetime(2026, 11, 1),
            "owner": None,
            "block_num": 1,
            "chain_id": "deployment-test",
        }
        from tests.vm_calls import execute_contract

        result = execute_contract(
            driver=driver,
            contract_name=module,
            function_name="probe",
            kwargs={},
            context=context,
            meter=False,
        )
        return result.status_code, result.result, result.writes


@pytest.mark.parametrize(
    "call",
    [
        "Contract.deploy(name='con_child', code=CHILD)",
        "Contract().submit('con_child', CHILD)",
        "Contract.submit(Contract(), 'con_child', CHILD)",
        "helper = Contract()\nsubmit = helper.submit\nsubmit('con_child', CHILD)",
        "Contract.deploy(name='con_child', code=CHILD, deployer='mallory', initiator='mallory')",
    ],
)
def test_ordinary_contract_cannot_deploy(tmp_path, call):
    status, result, writes = execute(tmp_path, call, module="con_probe")
    assert status == 1
    assert "restricted to submission" in str(result)
    assert writes == {}


@pytest.mark.parametrize("metadata", [None, "", "explicit"])
def test_only_none_defaults_deployment_metadata(tmp_path, metadata):
    body = (
        "Contract.deploy(name='con_child', code=CHILD, "
        f"developer={metadata!r}, deployer={metadata!r}, initiator={metadata!r})\nreturn Contract.get_info('con_child')"
    )
    status, result, writes = execute(tmp_path, body)
    assert status == 0, result
    expected = "alice" if metadata is None else metadata
    for key in ("developer", "deployer", "initiator"):
        assert result[key] == expected
    assert writes["con_child.seen"] == ["con_child", expected, expected, None, "created"]


def test_native_public_client_runs_constructor_with_explicit_signer(tmp_path):
    with ContractingClient(storage_home=tmp_path, signer="host") as client:
        client.submit(CHILD, name="con_child")
        assert client.raw_driver.get("con_child.seen") == [
            "con_child",
            "host",
            "host",
            None,
            "created",
        ]
        assert client.raw_driver.has_contract("con_child")


@pytest.mark.parametrize(
    "call",
    [
        "Contract().submit('con_child', CHILD)",
        "helper = Contract()\nsubmit = helper.submit\nsubmit(name='con_child', code=CHILD)",
        "Contract.submit(Contract(), 'con_child', CHILD)",
        "submit = Contract.submit\nsubmit(self=Contract(), name='con_child', code=CHILD)",
    ],
)
def test_submission_helper_reuses_deployment_path(tmp_path, call):
    status, result, writes = execute(tmp_path, call + "\nreturn Contract.get_info('con_child')")
    assert status == 0, result
    assert result["deployer"] == "alice"
    assert result["initiator"] == "alice"
    assert writes["con_child.seen"] == ["con_child", "alice", "alice", None, "created"]


def test_submit_all_positional_metadata_and_none_return(tmp_path):
    body = "helper = Contract()\nresult = helper.submit('con_child', CHILD, 'owner', {'label':'explicit'}, 'dev', 'creator', 'origin')\nreturn [result, helper.get_info('con_child')]"
    status, result, writes = execute(tmp_path, body)
    assert status == 0, result
    assert result[0] is None
    assert result[1]["developer"] == "dev"
    assert writes["con_child.seen"] == ["con_child", "creator", "origin", "owner", "explicit"]


def test_handle_identity_keys_classinfo_and_method_metadata(tmp_path):
    body = """a = Contract()
b = Contract()
keys = {a:1, b:2}
args = ('self','name','code','owner','constructor_args','developer','deployer','initiator')
check = importlib.Func('submit', args)
return [a is a, a == a, a == b, len(keys), keys[a], keys[b], len(keys.keys() | keys.keys()), isinstance(a,Contract), issubclass(Contract,Contract), check.is_of(a.submit), check.is_of(Contract.submit), importlib.Func('submit',()).is_of(a.submit), a.submit == a.submit, a.submit == b.submit, Contract.submit is Contract.submit]
"""
    status, result, _ = execute(tmp_path, body)
    assert status == 0, result
    assert result == [
        True,
        True,
        False,
        2,
        1,
        2,
        2,
        True,
        True,
        True,
        True,
        False,
        True,
        False,
        True,
    ]


@pytest.mark.parametrize(
    "call",
    [
        "Contract().submit()",
        "Contract().submit('con_child')",
        "Contract().submit('con_child', CHILD, name='duplicate')",
        "Contract().submit('con_child', CHILD, unknown=1)",
        "Contract().submit('con_child', CHILD, None, None, None, None, None, None)",
        "Contract.submit({}, 'con_child', CHILD)",
        "Contract.submit(name='con_child', code=CHILD)",
    ],
)
def test_submit_invalid_signatures_have_no_writes(tmp_path, call):
    status, _, writes = execute(tmp_path, call)
    assert status == 1
    assert writes == {}


@pytest.mark.parametrize("failure", ["parent", "constructor", "nested_deploy", "collision"])
def test_failed_deployment_is_atomic_and_constructor_has_no_submission_authority(tmp_path, failure):
    child = CHILD
    body = "Contract().submit('con_child', CHILD)"
    if failure == "parent":
        body += "\nassert False, 'parent failed'"
    elif failure == "constructor":
        child = "@construct\ndef seed():\n    assert False, 'constructor failed'\n@export\ndef read():\n    return 1\n"
    elif failure == "nested_deploy":
        grandchild = "@export\ndef read():\n    return 1\n"
        child = f"@construct\ndef seed():\n    Contract().submit('con_grandchild', {grandchild!r})\n@export\ndef read():\n    return 1\n"
    else:
        body += "\nContract().submit('con_child', CHILD)"
    status, result, writes = execute(tmp_path, body, child=child)
    assert status == 1
    assert writes == {}
    if failure == "nested_deploy":
        assert "restricted to submission" in str(result)


@pytest.mark.optional_native
@pytest.mark.parametrize(
    "body", ["return Contract()", "state.set(Contract())", "state.set({'nested':[Contract()]})"]
)
def test_handles_cannot_cross_external_boundaries(tmp_path, body):
    status, result, writes = execute(tmp_path, body)
    assert status == 1
    assert writes == {}
    assert "boundary" in str(result)


@pytest.mark.optional_native
@pytest.mark.parametrize("value", ["helper", "[helper]", "{'nested': helper}", "helper.submit"])
def test_deployment_capability_cannot_cross_shared_calls(tmp_path, value):
    target = "@export\ndef take(value: Any):\n    return 1\n"
    body = f"helper = Contract()\nreturn con_target.take({value})"
    status, result, writes = execute(tmp_path, body, target=target)
    assert status == 1
    assert "cannot cross contract boundaries" in str(result)
    assert writes == {}


@pytest.mark.parametrize(
    "call",
    [
        "Contract(1)",
        "Contract(driver='spoofed')",
        "Contract(unknown=None)",
        "Contract(None, driver=None)",
        "Contract(None, None)",
    ],
)
def test_contract_cannot_receive_host_driver_from_contract_code(tmp_path, call):
    status, result, writes = execute(tmp_path, call)
    assert status == 1
    assert writes == {}


@pytest.mark.parametrize("constructor", ["Contract()", "Contract(None)", "Contract(driver=None)"])
def test_contract_default_driver_spellings(tmp_path, constructor):
    body = f"helper = {constructor}\nhelper.submit('con_child', CHILD)\nreturn helper.get_info('con_child')['deployer']"
    status, result, _ = execute(tmp_path, body)
    assert status == 0, result
    assert result == "alice"


def test_native_public_clients_own_their_deployment_storage(tmp_path):
    with (
        ContractingClient(storage_home=tmp_path / "one", signer="host") as one,
        ContractingClient(storage_home=tmp_path / "two", signer="host") as two,
    ):
        two.submit(CHILD, name="con_child")
        assert two.raw_driver.has_contract("con_child")
        assert not one.raw_driver.has_contract("con_child")
