from unittest import TestCase

from contracting.compilation.compiler import ContractingCompiler
from contracting.compilation.linter import ErrorCode
from contracting.compilation.vm import (
    XIAN_VM_V1_PROFILE,
    VmCompatibilityChecker,
    VmCompatibilityError,
)


class TestVmCompatibilityChecker(TestCase):
    def setUp(self):
        self.checker = VmCompatibilityChecker()

    def test_vm_profile_accepts_basic_contract(self):
        source = """
values = Hash(default_value=0)

@export
def total(items: list[int]) -> int:
    running = 0
    for index in range(0, len(items)):
        running += items[index]
    values["count"] = len(items)
    return running
"""

        report = self.checker.check(source, profile=XIAN_VM_V1_PROFILE)

        self.assertTrue(report.compatible)
        self.assertEqual(report.feature_counts["range_calls"], 1)
        self.assertEqual(report.feature_counts["len_calls"], 2)

    def test_vm_profile_rejects_while_loops(self):
        source = """
@export
def countdown(value: int):
    while value > 0:
        value -= 1
    return value
"""

        report = self.checker.check(source, profile=XIAN_VM_V1_PROFILE)

        self.assertFalse(report.compatible)
        self.assertIn(ErrorCode.E022, {error.code for error in report.errors})
        self.assertEqual(report.feature_counts["while_loops"], 1)

    def test_vm_profile_rejects_comprehensions(self):
        source = """
@export
def compact(items: list[int]) -> list[int]:
    return [item for item in items if item > 0]
"""

        report = self.checker.check(source, profile=XIAN_VM_V1_PROFILE)

        self.assertFalse(report.compatible)
        self.assertIn(ErrorCode.E022, {error.code for error in report.errors})
        self.assertEqual(report.feature_counts["list_comprehensions"], 1)

    def test_vm_profile_rejects_set_usage(self):
        source = """
@export
def unique(value: str):
    seen = set()
    return value in seen
"""

        report = self.checker.check(source, profile=XIAN_VM_V1_PROFILE)

        self.assertFalse(report.compatible)
        self.assertIn(ErrorCode.E023, {error.code for error in report.errors})
        self.assertEqual(report.feature_counts["set_calls"], 1)

    def test_vm_profile_preserves_base_lint_errors(self):
        source = """
class Bad:
    pass
"""

        report = self.checker.check(source, profile=XIAN_VM_V1_PROFILE)

        self.assertFalse(report.compatible)
        self.assertIn(ErrorCode.E006, {error.code for error in report.errors})


class TestCompilerVmCompatibility(TestCase):
    def test_compiler_exposes_vm_compatibility_reports(self):
        compiler = ContractingCompiler()
        source = """
@export
def render(values: list[int]):
    return dict(total=len(values))
"""

        report = compiler.check_vm_compatibility(
            source, profile=XIAN_VM_V1_PROFILE
        )

        self.assertTrue(report.compatible)
        self.assertEqual(report.feature_counts["dict_calls"], 1)
        self.assertEqual(report.feature_counts["len_calls"], 1)

    def test_compiler_vm_profile_can_raise(self):
        compiler = ContractingCompiler()
        source = """
@export
def render(values: list[int]):
    return [value for value in values]
"""

        with self.assertRaises(VmCompatibilityError):
            compiler.parse_to_code(
                source,
                vm_profile=XIAN_VM_V1_PROFILE,
            )
