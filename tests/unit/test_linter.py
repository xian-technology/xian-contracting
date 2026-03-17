"""Tests for the smart contract linter."""

from unittest import TestCase

from contracting.compilation.linter import (
    ErrorCode,
    Linter,
    LintError,
    LintingError,
)

VALID_CONTRACT = """
v = Variable()

@construct
def seed():
    v.set(0)

@export
def get(key: str):
    return v.get()

@export
def set_val(key: str, value: int):
    v.set(value)
"""


class TestLinterClean(TestCase):
    def setUp(self):
        self.linter = Linter()

    def test_valid_contract(self):
        self.assertIsNone(self.linter.check(VALID_CONTRACT))

    def test_simple_export(self):
        code = """
@export
def hello(name: str):
    return "Hello " + name
"""
        self.assertIsNone(self.linter.check(code))

    def test_export_with_return_annotation(self):
        code = """
@export
def hello(name: str) -> str:
    return "Hello " + name
"""
        self.assertIsNone(self.linter.check(code))

    def test_hash_and_variable(self):
        code = """
balances = Hash(default_value=0)
owner = Variable()

@construct
def seed():
    owner.set("alice")

@export
def transfer(amount: float, to: str):
    balances[ctx.caller] -= amount
    balances[to] += amount
"""
        self.assertIsNone(self.linter.check(code))

    def test_import_contract(self):
        code = """
import currency

@export
def spend(amount: float):
    currency.transfer(amount=amount, to="bob")
"""
        self.assertIsNone(self.linter.check(code))


class TestErrorPositions(TestCase):
    def setUp(self):
        self.linter = Linter()

    def test_error_has_line_and_col(self):
        code = """
class Bad:
    pass
"""
        errors = self.linter.check(code)
        self.assertIsNotNone(errors)
        err = next(error for error in errors if error.code == ErrorCode.E006)
        self.assertEqual(err.line, 2)
        self.assertEqual(err.col, 0)

    def test_error_has_end_positions(self):
        code = """
class Bad:
    pass
"""
        errors = self.linter.check(code)
        err = next(error for error in errors if error.code == ErrorCode.E006)
        self.assertGreater(err.end_line, 0)
        self.assertGreaterEqual(err.end_col, 0)

    def test_errors_sorted_by_position(self):
        code = """
class A:
    pass

@export
def ok():
    pass

class B:
    pass
"""
        errors = self.linter.check(code)
        lines = [error.line for error in errors]
        self.assertEqual(lines, sorted(lines))

    def test_syntax_error_position(self):
        errors = self.linter.check("def (")
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].code, ErrorCode.E020)
        self.assertEqual(errors[0].line, 1)


class TestErrorCodes(TestCase):
    def setUp(self):
        self.linter = Linter()

    def _codes(self, code: str):
        errors = self.linter.check(code) or []
        return {error.code for error in errors}

    def test_e001_lambda(self):
        code = """
@export
def f(x: int):
    g = lambda: x
    return g()
"""
        self.assertIn(ErrorCode.E001, self._codes(code))

    def test_e002_dunder_attribute_blocked(self):
        code = """
@export
def f():
    x = ().__class__.__bases__[0].__subclasses__()
"""
        self.assertIn(ErrorCode.E002, self._codes(code))

    def test_e003_nested_import(self):
        code = """
@export
def f():
    import os
"""
        self.assertIn(ErrorCode.E003, self._codes(code))

    def test_e004_import_from(self):
        code = """
from os import path

@export
def f():
    pass
"""
        self.assertIn(ErrorCode.E004, self._codes(code))

    def test_e005_stdlib_import(self):
        code = """
import os

@export
def f():
    pass
"""
        self.assertIn(ErrorCode.E005, self._codes(code))

    def test_e006_class(self):
        code = """
class Foo:
    pass
"""
        self.assertIn(ErrorCode.E006, self._codes(code))

    def test_e007_async(self):
        code = """
@export
async def f():
    pass
"""
        self.assertIn(ErrorCode.E007, self._codes(code))

    def test_e008_invalid_decorator(self):
        code = """
@invalid_decorator
def f():
    pass
"""
        self.assertIn(ErrorCode.E008, self._codes(code))

    def test_e009_multiple_constructors(self):
        code = """
@construct
def seed1():
    pass

@construct
def seed2():
    pass

@export
def f():
    pass
"""
        self.assertIn(ErrorCode.E009, self._codes(code))

    def test_e010_multiple_decorators(self):
        code = """
@construct
@export
def f():
    pass
"""
        self.assertIn(ErrorCode.E010, self._codes(code))

    def test_e011_orm_keyword_override(self):
        code = """
v = Variable(contract="currency")

@export
def f():
    pass
"""
        self.assertIn(ErrorCode.E011, self._codes(code))

    def test_e012_tuple_orm_assignment(self):
        code = """
a, b = Variable()

@export
def f(x: int):
    pass
"""
        self.assertIn(ErrorCode.E012, self._codes(code))

    def test_e013_no_export(self):
        code = """
def f():
    pass
"""
        self.assertIn(ErrorCode.E013, self._codes(code))

    def test_e014_illegal_builtin(self):
        code = """
@export
def f():
    exec("print(1)")
"""
        self.assertIn(ErrorCode.E014, self._codes(code))

    def test_e015_orm_shadow(self):
        code = """
v = Variable()

@export
def f(v: int):
    pass
"""
        self.assertIn(ErrorCode.E015, self._codes(code))

    def test_e016_bad_annotation(self):
        code = """
@export
def f(x: mytype):
    pass
"""
        self.assertIn(ErrorCode.E016, self._codes(code))

    def test_e017_missing_annotation(self):
        code = """
@export
def f(x):
    pass
"""
        self.assertIn(ErrorCode.E017, self._codes(code))

    def test_e018_return_annotation(self):
        code = """
@export
def f(x: int) -> mytype:
    return x
"""
        self.assertIn(ErrorCode.E018, self._codes(code))

    def test_e019_nested_function(self):
        code = """
@export
def f():
    def g():
        pass
    g()
"""
        self.assertIn(ErrorCode.E019, self._codes(code))

    def test_e020_syntax_error(self):
        self.assertIn(ErrorCode.E020, self._codes("def ("))


class TestLintErrorFormat(TestCase):
    def test_str_format(self):
        err = LintError(
            code=ErrorCode.E006,
            message="Class definitions are not allowed",
            line=5,
            col=0,
            end_line=6,
            end_col=8,
        )
        self.assertEqual(
            str(err),
            "5:0: E006 Class definitions are not allowed",
        )

    def test_to_dict(self):
        err = LintError(
            code=ErrorCode.E001,
            message="Illegal syntax: Lambda",
            line=3,
            col=4,
            end_line=3,
            end_col=20,
        )
        data = err.to_dict()
        self.assertEqual(data["code"], "E001")
        self.assertEqual(data["line"], 3)
        self.assertEqual(data["col"], 4)
        self.assertEqual(data["end_line"], 3)
        self.assertEqual(data["end_col"], 20)


class TestCheckRaise(TestCase):
    def setUp(self):
        self.linter = Linter()

    def test_clean_code_no_exception(self):
        self.linter.check_raise(VALID_CONTRACT)

    def test_bad_code_raises(self):
        code = """
class Bad:
    pass
"""
        with self.assertRaises(LintingError):
            self.linter.check_raise(code)

    def test_raise_message_contains_error_code(self):
        try:
            self.linter.check_raise("def (")
            self.fail("Expected exception")
        except LintingError as exc:
            self.assertIn("E020", str(exc))
