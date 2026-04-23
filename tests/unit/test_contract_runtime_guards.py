from unittest import TestCase

from contracting import constants
from contracting.compilation.compiler import ContractingCompiler
from contracting.compilation.linter import ErrorCode, Linter
from contracting.stdlib import env
from contracting.stdlib.builtins import (
    safe_bytearray,
    safe_bytes,
    safe_mul,
    safe_range,
)


class TestAllocationBuiltins(TestCase):
    def test_env_exports_safe_builtin_overrides(self):
        exports = env.gather()
        self.assertIs(exports["range"], safe_range)
        self.assertIs(exports["bytes"], safe_bytes)
        self.assertIs(exports["bytearray"], safe_bytearray)
        self.assertIs(exports["__xian_mul__"], safe_mul)

    def test_range_rejects_oversized_length(self):
        with self.assertRaisesRegex(AssertionError, "range\\(\\) exceeds"):
            safe_range(constants.MAX_SEQUENCE_LENGTH + 1)

    def test_bytes_rejects_oversized_integer_allocation(self):
        with self.assertRaisesRegex(AssertionError, "bytes\\(\\) exceeds"):
            safe_bytes(constants.MAX_BINARY_ALLOCATION_BYTES + 1)

    def test_bytearray_rejects_oversized_integer_allocation(self):
        with self.assertRaisesRegex(
            AssertionError,
            "bytearray\\(\\) exceeds",
        ):
            safe_bytearray(constants.MAX_BINARY_ALLOCATION_BYTES + 1)

    def test_safe_binary_constructors_remain_isinstance_compatible(self):
        self.assertIsInstance(safe_bytes("abc", "utf-8"), safe_bytes)
        self.assertIsInstance(safe_bytearray(b"abc"), safe_bytearray)
        self.assertNotIsInstance(bytearray(b"abc"), safe_bytes)
        self.assertNotIsInstance(b"abc", safe_bytearray)

    def test_mul_rejects_oversized_string_repeat(self):
        with self.assertRaisesRegex(
            AssertionError,
            "string repetition exceeds",
        ):
            safe_mul("ab", constants.MAX_BINARY_ALLOCATION_BYTES)

    def test_mul_rejects_oversized_sequence_repeat(self):
        with self.assertRaisesRegex(
            AssertionError,
            "sequence repetition exceeds",
        ):
            safe_mul([1], constants.MAX_SEQUENCE_LENGTH + 1)

    def test_mul_preserves_numeric_multiplication(self):
        self.assertEqual(safe_mul(6, 7), 42)


class TestCompilerGuards(TestCase):
    def test_compiler_rewrites_multiplication_to_guarded_helper(self):
        compiler = ContractingCompiler(module_name="guarded")
        code = """
@export
def repeat(n: int):
    return "a" * n
"""

        runtime_code = compiler.parse_to_code(code)

        self.assertIn("__xian_mul__", runtime_code)

    def test_linter_rejects_augmented_multiplication(self):
        errors = Linter().check(
            """
@export
def repeat(n: int):
    value = "a"
    value *= n
    return value
"""
        )

        self.assertIsNotNone(errors)
        self.assertIn(ErrorCode.E001, {error.code for error in errors})
