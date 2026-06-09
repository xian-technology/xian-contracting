import os
import subprocess
import sys
from unittest import TestCase

from contracting import constants
from contracting.compilation.compiler import ContractingCompiler
from contracting.compilation.linter import ErrorCode, Linter
from contracting.stdlib import env
from contracting.stdlib.builtins import (
    safe_bytearray,
    safe_bytes,
    safe_int,
    safe_lshift,
    safe_mul,
    safe_pow,
    safe_range,
    safe_rshift,
)


class TestAllocationBuiltins(TestCase):
    def test_env_exports_safe_builtin_overrides(self):
        exports = env.gather()
        self.assertIs(exports["range"], safe_range)
        self.assertIs(exports["bytes"], safe_bytes)
        self.assertIs(exports["bytearray"], safe_bytearray)
        self.assertIs(exports["__xian_int__"], safe_int)
        self.assertIs(exports["__xian_mul__"], safe_mul)
        self.assertIs(exports["__xian_pow__"], safe_pow)
        self.assertIs(exports["__xian_lshift__"], safe_lshift)
        self.assertIs(exports["__xian_rshift__"], safe_rshift)

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

    def test_mul_rejects_oversized_integer_result(self):
        with self.assertRaisesRegex(AssertionError, "integer multiplication exceeds"):
            safe_mul(1 << constants.MAX_INTEGER_BITS, 2)

    def test_pow_preserves_small_integer_and_modular_pow(self):
        self.assertEqual(safe_pow(10, 18), 10**18)
        self.assertEqual(safe_pow(7, 3, 13), pow(7, 3, 13))

    def test_pow_rejects_oversized_integer_result(self):
        with self.assertRaisesRegex(AssertionError, "integer exponentiation exceeds"):
            safe_pow(2, constants.MAX_INTEGER_BITS)

    def test_pow_rejects_oversized_modular_exponent_bits(self):
        with self.assertRaisesRegex(
            AssertionError,
            "modular exponentiation exponent exceeds",
        ):
            safe_pow(2, 1 << constants.MAX_MODULAR_POW_EXPONENT_BITS, 13)

    def test_left_shift_rejects_oversized_integer_result(self):
        with self.assertRaisesRegex(AssertionError, "left shift exceeds"):
            safe_lshift(1, constants.MAX_INTEGER_BITS)

    def test_right_shift_rejects_oversized_shift_count(self):
        with self.assertRaisesRegex(AssertionError, "right shift count exceeds"):
            safe_rshift(1, constants.MAX_INTEGER_BITS + 1)

    def test_int_rejects_oversized_string_input(self):
        with self.assertRaisesRegex(AssertionError, "int\\(\\) input exceeds"):
            safe_int("9" * (constants.MAX_INT_STRING_CHARS + 1))

    def test_int_and_pow_are_safe_in_contract_builtins(self):
        # The compiler rewrites the syntactic forms `int(...)` and `pow(...)`
        # to the guarded helpers, but indirect references — `foo = int`,
        # `(pow,)[0]`, `[int][0]` — would still resolve through the contract's
        # __builtins__. Override the bare names there so those indirections
        # also hit the guarded wrappers.
        from contracting.execution.sandbox import build_contract_builtins

        builtins_dict = build_contract_builtins(lambda *a, **k: None)
        self.assertIs(builtins_dict["int"], safe_int)
        self.assertIs(builtins_dict["pow"], safe_pow)

    def test_print_is_not_available_in_contract_builtins(self):
        from contracting.execution.sandbox import build_contract_builtins

        builtins_dict = build_contract_builtins(lambda *a, **k: None)
        self.assertNotIn("print", builtins_dict)

    def test_indirect_int_reference_still_guarded(self):
        from contracting.execution.sandbox import build_contract_builtins

        scope = {"__builtins__": build_contract_builtins(lambda *a, **k: None)}
        oversize = "9" * (constants.MAX_INT_STRING_CHARS + 1)

        with self.assertRaisesRegex(AssertionError, "int\\(\\) input exceeds"):
            exec(f'foo = int\nfoo("{oversize}")', dict(scope))

    def test_indirect_pow_reference_still_guarded(self):
        from contracting.execution.sandbox import build_contract_builtins

        scope = {"__builtins__": build_contract_builtins(lambda *a, **k: None)}
        oversize_exponent = constants.MAX_INTEGER_BITS

        with self.assertRaisesRegex(
            AssertionError, "integer exponentiation exceeds"
        ):
            exec(
                f"foo = pow\nfoo(2, {oversize_exponent})",
                dict(scope),
            )


class TestCompilerGuards(TestCase):
    def test_contracting_package_refuses_optimized_python(self):
        env_vars = os.environ.copy()
        env_vars["PYTHONOPTIMIZE"] = "1"

        result = subprocess.run(
            [sys.executable, "-c", "import contracting"],
            capture_output=True,
            text=True,
            env=env_vars,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "xian-contracting refuses to run with PYTHONOPTIMIZE",
            result.stderr,
        )

    def test_compiler_rewrites_multiplication_to_guarded_helper(self):
        compiler = ContractingCompiler(module_name="guarded")
        code = """
@export
def repeat(n: int):
    return "a" * n
"""

        compiled_source = compiler.parse_to_code(code)

        self.assertIn("__xian_mul__", compiled_source)

    def test_compiler_rewrites_pow_and_shifts_to_guarded_helpers(self):
        compiler = ContractingCompiler(module_name="guarded")
        code = """
@export
def calculate(n: int):
    return (2 ** n) + (1 << n) + (8 >> n)
"""

        compiled_source = compiler.parse_to_code(code)

        self.assertIn("__xian_pow__", compiled_source)
        self.assertIn("__xian_lshift__", compiled_source)
        self.assertIn("__xian_rshift__", compiled_source)

    def test_compiler_rewrites_int_and_pow_calls_to_guarded_helpers(self):
        compiler = ContractingCompiler(module_name="guarded")
        code = """
@export
def calculate(value: str):
    return int(value) + pow(2, 8)
"""

        compiled_source = compiler.parse_to_code(code)

        self.assertIn("__xian_int__", compiled_source)
        self.assertIn("__xian_pow__", compiled_source)

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

    def test_linter_rejects_augmented_guarded_arithmetic(self):
        for operator in ("**=", "<<=", ">>="):
            errors = Linter().check(
                f"""
@export
def repeat(n: int):
    value = 2
    value {operator} n
    return value
"""
            )

            self.assertIsNotNone(errors)
            self.assertIn(ErrorCode.E001, {error.code for error in errors})
