"""Tests for the ContractingCompiler AST transformer."""

from unittest import TestCase

from contracting.compilation.compiler import ContractingCompiler
from contracting.compilation.linter import LintingError

PRIVATE_HELPER_WITH_LINT_ERROR = """
class Bad:
    pass

def helper():
    return 1

@export
def run():
    return helper()
"""

CONTRACT_WITH_HELPER_ARGUMENT = """
@export
def do_thing(helper: int):
    return helper + 1
"""

FORWARD_REFERENCE_CONTRACT = """
@export
def run():
    return helper()

def helper():
    return 1
"""


class TestCompilerPrivatization(TestCase):
    def setUp(self):
        self.compiler = ContractingCompiler(module_name="con_test")

    def test_forward_references_to_private_functions_are_privatized(self):
        code = self.compiler.parse_to_code(FORWARD_REFERENCE_CONTRACT, vm_profile="xian_vm_v1")

        self.assertIn("def __helper():", code)
        self.assertIn("return __helper()", code)

    def test_failed_parse_does_not_leak_private_names(self):
        with self.assertRaises(LintingError):
            self.compiler.parse_to_code(PRIVATE_HELPER_WITH_LINT_ERROR, vm_profile="xian_vm_v1")

        code = self.compiler.parse_to_code(CONTRACT_WITH_HELPER_ARGUMENT, vm_profile="xian_vm_v1")

        self.assertNotIn("__helper", code)
        self.assertIn("helper + 1", code)

    def test_failed_parse_resets_collected_state(self):
        with self.assertRaises(LintingError):
            self.compiler.parse_to_code(PRIVATE_HELPER_WITH_LINT_ERROR, vm_profile="xian_vm_v1")

        self.assertEqual(self.compiler.private_names, set())
        self.assertEqual(self.compiler.orm_names, set())
        self.assertEqual(self.compiler.visited_names, set())
        self.assertIsNone(self.compiler.lint_alerts)


def test_host_ast_and_bytecode_require_an_explicit_legacy_profile():
    import pytest

    compiler = ContractingCompiler(module_name="con_float")
    source = "@export\ndef amount():\n    return 0.123456789012345678901234567891"
    for entry in (compiler.parse, compiler.compile):
        with pytest.raises(ValueError, match="lower_to_ir"):
            entry(source)
        with pytest.raises(ValueError, match="lower_to_ir"):
            entry(source, vm_profile=None)
        assert entry(source, vm_profile="xian_vm_v1") is not None
    assert "0.123456789012345678901234567891" in compiler.normalize_source(source)
    assert compiler.lower_to_ir(source, vm_profile=None)["vm_profile"] == "xian_vm_v2"
