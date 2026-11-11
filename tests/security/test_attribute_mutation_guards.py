"""Native contracts cannot mutate shared helpers or escape interface descriptors."""

import json
import os
import subprocess
import sys

import pytest

from contracting.local import ContractingClient


def test_descriptor_targets_keep_order_and_single_evaluation(tmp_path):
    source = """def receiver(events: list, item: Any, label: str):
    events.append(label)
    return item

def value(events: list, label: str, item: Any):
    events.append(label)
    return item

@export
def probe():
    events = []
    a = importlib.Func('a')
    b = importlib.Func('b')
    receiver(events, a, 'a').name = receiver(events, b, 'b').name = value(events, 'chain', 'x')
    receiver(events, a, 'aug').name += value(events, 'aug_rhs', 'y')
    (receiver(events, a, 'unpack_a').args, receiver(events, b, 'unpack_b').args) = value(events, 'unpack_rhs', (1, 2))
    return [events, a.name, b.name, a.args, b.args]
"""
    with ContractingClient(storage_home=tmp_path) as client:
        client.submit(source, name="con_descriptors")
        assert client.get_contract_proxy("con_descriptors").probe() == [
            ["chain", "a", "b", "aug", "aug_rhs", "unpack_rhs", "unpack_a", "unpack_b"],
            "xy",
            "x",
            1,
            2,
        ]


def test_var_descriptor_fields_remain_mutable(tmp_path):
    source = """@export
def probe():
    descriptor = importlib.Var('balance', Variable)
    descriptor.name = 'renamed'
    descriptor.type = importlib.Var('ledger', Hash).type
    return [descriptor.name, descriptor.type == importlib.Var('ledger', Hash).type]
"""
    with ContractingClient(storage_home=tmp_path) as client:
        client.submit(source, name="con_descriptor")
        assert client.get_contract_proxy("con_descriptor").probe() == ["renamed", True]


PROCESS_PROBE = r"""
import json, sys
from pathlib import Path
from contracting.local import ContractingClient
from contracting.storage.contract import Contract
from contracting.storage.orm import Variable
assignment, fail, constructor, storage = json.loads(sys.argv[1])
original = (Contract.set_owner, Variable.set)
source = "@export\ndef hidden(value: Any = None):\n    return 731\n"
source += ("@construct\ndef seed():\n" if constructor else "@export\ndef poison():\n")
source += "    " + assignment + "\n"
source += "    assert False, 'rollback'\n" if fail else "    return True\n"
with ContractingClient(storage_home=Path(storage), metering=False) as client:
    before = client.raw_driver.items()
    output = client.get_contract_proxy('submission').submit_contract(
        name='con_poison', code=source, return_full_output=True)
    if output['status_code'] == 0:
        output = client.get_contract_proxy('con_poison').poison(return_full_output=True)
    assert output['status_code'] == 1, output
    assert output['writes'] == {}, output
    assert output['events'] == [], output
    assert original == (Contract.set_owner, Variable.set)
    if constructor:
        assert not client.raw_driver.has_contract('con_poison')
        assert client.raw_driver.items() == before
    print(json.dumps({'status': output['status_code'], 'message': str(output['result']),
                      'unchanged': original == (Contract.set_owner, Variable.set)}))
"""


@pytest.mark.parametrize(
    "assignment",
    [
        "Contract.submit = hidden",
        "importlib.Func.is_of = hidden",
        "hidden.marker = 7",
        "importlib.import_module.marker = 7",
    ],
)
@pytest.mark.parametrize("fail", [False, True])
@pytest.mark.parametrize("constructor", [False, True])
def test_helper_poisoning_cannot_survive_transaction_or_constructor(
    tmp_path, assignment, fail, constructor
):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            PROCESS_PROBE,
            json.dumps([assignment, fail, constructor, str(tmp_path / "state")]),
        ],
        env=dict(os.environ, HOME=str(tmp_path / "home")),
        capture_output=True,
        text=True,
        check=True,
    )
    observation = json.loads(result.stdout)
    assert observation["status"] == 1, observation
    assert observation["unchanged"], observation


@pytest.mark.parametrize(
    "statement",
    [
        "descriptor._hidden = 1",
        "Contract.marker = 7",
        "Contract.marker += 1",
        "del Contract.marker",
    ],
)
def test_non_descriptor_and_private_attribute_targets_are_rejected(tmp_path, statement):
    source = "@export\ndef probe():\n    descriptor = importlib.Func('x')\n"
    source += f"    {statement}\n    return True\n"
    with ContractingClient(storage_home=tmp_path) as client:
        output = client.get_contract_proxy("submission").submit_contract(
            name="con_attribute_guard", code=source, return_full_output=True
        )
        if output["status_code"] == 0:
            output = client.get_contract_proxy("con_attribute_guard").probe(return_full_output=True)
        assert output["status_code"] == 1, output
        assert output["writes"] == {}
        assert output["events"] == []


def test_authored_source_cannot_name_private_guard(tmp_path):
    source = "@export\ndef probe():\n    return __xian_attribute_target__(Contract, 'submit')\n"
    with ContractingClient(storage_home=tmp_path) as client:
        with pytest.raises(Exception, match="underscore|private"):
            client.submit(source, name="con_private_guard")
        assert not client.raw_driver.has_contract("con_private_guard")
