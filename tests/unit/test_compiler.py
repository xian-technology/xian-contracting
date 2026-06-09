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
        code = self.compiler.parse_to_code(FORWARD_REFERENCE_CONTRACT)

        self.assertIn("def __helper():", code)
        self.assertIn("return __helper()", code)

    def test_failed_parse_does_not_leak_private_names(self):
        with self.assertRaises(LintingError):
            self.compiler.parse_to_code(PRIVATE_HELPER_WITH_LINT_ERROR)

        code = self.compiler.parse_to_code(CONTRACT_WITH_HELPER_ARGUMENT)

        self.assertNotIn("__helper", code)
        self.assertIn("helper + 1", code)

    def test_failed_parse_resets_collected_state(self):
        with self.assertRaises(LintingError):
            self.compiler.parse_to_code(PRIVATE_HELPER_WITH_LINT_ERROR)

        self.assertEqual(self.compiler.private_names, set())
        self.assertEqual(self.compiler.orm_names, set())
        self.assertEqual(self.compiler.visited_names, set())
        self.assertIsNone(self.compiler.lint_alerts)
