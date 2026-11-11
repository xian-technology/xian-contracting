"""Native imports resolve contract handles without exposing host Python modules."""

from pathlib import Path

import pytest

from contracting.local import ContractingClient


@pytest.mark.parametrize("fixture", ["builtin_lib.s.py", "mathtime.s.py"])
def test_host_builtin_modules_are_rejected_on_admission(tmp_path, fixture):
    source = (Path(__file__).parent / "test_contracts" / fixture).read_text()
    with ContractingClient(storage_home=tmp_path) as client:
        with pytest.raises(Exception):
            client.submit(source, name="con_builtin")
        assert not client.raw_driver.has_contract("con_builtin")


def test_static_import_cannot_reach_the_host_contracting_package(tmp_path):
    source = (
        "import contracting\n@export\ndef probe():\n    return contracting.ContractingClient()\n"
    )
    with ContractingClient(storage_home=tmp_path) as client:
        client.submit(source, name="con_host_import")
        output = client.get_contract_proxy("con_host_import").probe(return_full_output=True)
        assert output["status_code"] == 1
        assert output["writes"] == {}


def test_dynamic_import_resolves_only_deployed_contract_functions(tmp_path):
    source = """@export
def probe(name: str):
    target = importlib.import_module(name)
    return target.hello()
"""
    with ContractingClient(storage_home=tmp_path) as client:
        client.submit(source, name="con_dynamic_import")
        probe = client.get_contract_proxy("con_dynamic_import")
        output = probe.probe(name="contracting", return_full_output=True)
        assert output["status_code"] == 1
        assert output["writes"] == {}
        client.submit("@export\ndef hello():\n    return 'hello'", name="con_hello")
        assert probe.probe(name="con_hello") == "hello"


def test_binary_float_annotations_are_rejected_for_v2(tmp_path):
    source = (Path(__file__).parent / "test_contracts/float_issue.s.py").read_text()
    with ContractingClient(storage_home=tmp_path) as client:
        with pytest.raises(Exception, match="float"):
            client.submit(source, name="con_float_issue")
        assert not client.raw_driver.has_contract("con_float_issue")
