"""The compiler facade produces source and native IR without executing source."""

import json

import pytest
from xian_compiler_core import CompilerError

from contracting.compilation.compiler import ContractingCompiler
from contracting.compilation.linter import LintingError

FORWARD_REFERENCE = """
@export
def run():
    return helper()

def helper():
    return 1
"""


def test_forward_private_references_keep_authored_names_in_native_ir():
    module = ContractingCompiler(module_name="con_test").lower_to_ir(FORWARD_REFERENCE)
    functions = {function["name"]: function for function in module["functions"]}
    assert functions["run"]["visibility"] == "export"
    assert functions["helper"]["visibility"] == "private"
    assert functions["run"]["body"][0]["value"]["func"]["id"] == "helper"


def test_failed_admission_does_not_change_the_next_contract():
    compiler = ContractingCompiler(module_name="con_test")
    with pytest.raises(CompilerError, match="xian.syntax.unsupported_statement.class_def"):
        compiler.lower_to_ir("class Bad:\n    pass\n")
    source = "@export\ndef run(helper: int):\n    return helper + 1"
    module = compiler.lower_to_ir(source)
    assert [function["name"] for function in module["functions"]] == ["run"]
    assert module["functions"][0]["parameters"][0]["name"] == "helper"


@pytest.mark.parametrize("profile", [None, "xian_vm_v2"])
def test_default_compiler_preserves_exact_v2_literals(profile):
    literal = "0.123456789012345678901234567891"
    source = f"@export\ndef amount():\n    return {literal}"
    compiler = ContractingCompiler(module_name="con_exact")
    assert literal in compiler.normalize_source(source, vm_profile=profile)
    module = compiler.lower_to_ir(source, vm_profile=profile)
    assert module["vm_profile"] == "xian_vm_v2"
    assert module["functions"][0]["body"][0]["value"]["value"] == literal
    assert json.loads(compiler.lower_to_ir_json(source, vm_profile=profile)) == module


def test_explicit_native_v1_artifact_compilation_remains_available():
    module = ContractingCompiler(module_name="con_archive").lower_to_ir(
        "@export\ndef amount():\n    return 1.25", vm_profile="xian_vm_v1"
    )
    assert module["vm_profile"] == "xian_vm_v1"
    assert module["functions"][0]["name"] == "amount"


def test_native_ir_preserves_exact_default_argument_literals():
    literal = "0.123456789012345678901234567891"
    source = f"@export\ndef configure(*, rate: decimal = {literal}):\n    return rate"
    function = ContractingCompiler(module_name="con_default").lower_to_ir(source)["functions"][0]
    assert literal in json.dumps(function["parameters"])


@pytest.mark.parametrize(
    "method", ["normalize_source", "parse_to_code", "lower_to_ir", "lower_to_ir_json"]
)
def test_archival_source_analysis_preserves_lint_failures(method):
    with pytest.raises(LintingError):
        getattr(ContractingCompiler(), method)("class Bad:\n    pass", vm_profile="xian_vm_v1")


def test_archival_ir_json_defaults_to_stable_sorted_keys():
    compiler = ContractingCompiler(module_name="con_archive")
    source = "@export\ndef read():\n    return 7"
    module = compiler.lower_to_ir(source, vm_profile="xian_vm_v1")
    assert compiler.lower_to_ir_json(source, vm_profile="xian_vm_v1") == json.dumps(
        module, indent=2, sort_keys=True
    )
