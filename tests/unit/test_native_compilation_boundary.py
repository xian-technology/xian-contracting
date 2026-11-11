"""Native artifact tooling does not expose a CPython execution pipeline."""

import ast
import builtins
import json

import pytest

from contracting.compilation.compiler import ContractingCompiler
from contracting.storage.contract import Contract
from contracting.storage.driver import Driver


@pytest.mark.parametrize("method", ["parse", "compile", "parse_legacy_runtime"])
def test_compiler_has_no_python_ast_or_bytecode_entrypoint(method):
    with pytest.raises(AttributeError):
        getattr(ContractingCompiler(), method)


def test_storage_has_no_executable_python_runtime_surface():
    for owner, method in [
        (Driver, "get_local_contract_runtime"),
        (Contract, "deploy"),
        (Contract, "submit"),
    ]:
        with pytest.raises(AttributeError):
            getattr(owner, method)


def test_archival_v1_storage_compiles_ir_without_generating_python_bytecode(monkeypatch):
    python_compile = builtins.compile

    def analysis_only(source, filename, mode, flags=0, *args, **kwargs):
        assert flags & ast.PyCF_ONLY_AST, "artifact storage attempted executable Python compilation"
        return python_compile(source, filename, mode, flags, *args, **kwargs)

    with Driver(vm_profile="xian_vm_v1") as driver:
        with monkeypatch.context() as patch:
            patch.setattr(builtins, "compile", analysis_only)
            driver.set_contract_from_source("con_archive", "@export\ndef read():\n    return 7")
        assert "def read" in driver.get_contract_source("con_archive")
        module = json.loads(driver.get_contract_ir("con_archive"))
        assert module["vm_profile"] == "xian_vm_v1"
        assert module["functions"][0]["body"][0]["value"]["value"] == 7


@pytest.mark.parametrize(
    ("artifacts", "error", "message"),
    [
        ({}, TypeError, "at least one contract artifact"),
        ({"source": 7}, TypeError, "source must be a string"),
        ({"vm_ir_json": "[]"}, ValueError, "IR must target xian_vm_v2"),
        ({"vm_ir_json": '{"vm_profile":"xian_vm_v1"}'}, ValueError, "IR must target xian_vm_v2"),
    ],
)
def test_storage_rejects_invalid_artifact_shapes_before_staging(artifacts, error, message):
    with Driver() as driver:
        with pytest.raises(error, match=message):
            driver.set_contract("con_invalid", **artifacts)
        assert not driver.has_contract("con_invalid")


def test_v2_source_storage_derives_ir_before_staging():
    with Driver() as driver:
        driver.set_contract("con_native", source="@export\ndef read():\n    return 11")
        module = json.loads(driver.get_contract_ir("con_native"))
        assert module["vm_profile"] == "xian_vm_v2"
        assert module["functions"][0]["body"][0]["value"]["value"] == 11


def test_archival_source_storage_preserves_pre_ir_source_without_executing_it():
    with Driver(vm_profile="xian_vm_v1") as driver:
        source = "@export\ndef read():\n    return 7"
        driver.set_contract("con_archive", source=source)
        assert driver.get_contract_source("con_archive") == source
        assert driver.get_contract_ir("con_archive") is None
