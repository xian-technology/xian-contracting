"""Native execution enforces allocation bounds without CPython builtin wrappers."""

import os
import subprocess
import sys
from unittest import TestCase

import pytest

from contracting import constants
from contracting.compilation.linter import ErrorCode, Linter
from contracting.local import ContractingClient


@pytest.fixture
def client():
    with ContractingClient() as client:
        yield client


@pytest.mark.parametrize(
    ("body", "kwargs"),
    [
        ("return list(range(n))", {"n": constants.MAX_SEQUENCE_LENGTH + 1}),
        ("return bytes(n)", {"n": constants.MAX_BINARY_ALLOCATION_BYTES + 1}),
        ("return bytearray(n)", {"n": constants.MAX_BINARY_ALLOCATION_BYTES + 1}),
        ("return 'ab' * n", {"n": constants.MAX_BINARY_ALLOCATION_BYTES}),
        ("return [1] * n", {"n": constants.MAX_SEQUENCE_LENGTH + 1}),
        ("return 2 ** n", {"n": constants.MAX_INTEGER_BITS}),
        ("power = pow\n    return power(2, n)", {"n": constants.MAX_INTEGER_BITS}),
        ("return 1 << n", {"n": constants.MAX_INTEGER_BITS}),
        ("return pow(7, n, 13)", {"n": 1 << constants.MAX_MODULAR_POW_EXPONENT_BITS}),
    ],
)
def test_native_allocation_and_arithmetic_limits(client, body, kwargs):
    client.submit(f"@export\ndef probe(n: int):\n    {body}", name="con_guard")
    result = client.executor.execute(
        sender="alice", contract_name="con_guard", function_name="probe", kwargs=kwargs
    )
    assert result["status_code"] == 1
    assert "exceed" in str(result["result"]).lower()
    assert result["writes"] == {}
    assert result["events"] == []


@pytest.mark.parametrize("body", ["return int(value)", "convert = int\n    return convert(value)"])
def test_native_integer_parser_bounds_direct_and_aliased_calls(client, body):
    client.submit(f"@export\ndef probe(value: str):\n    {body}", name="con_guard")
    result = client.executor.execute(
        sender="alice",
        contract_name="con_guard",
        function_name="probe",
        kwargs={"value": "9" * (constants.MAX_INT_STRING_CHARS + 1)},
    )
    assert result["status_code"] == 1
    assert "int() input exceeds" in str(result["result"])


def test_native_small_arithmetic_and_binary_class_checks(client):
    client.submit(
        "@export\ndef probe():\n    return [6 * 7, pow(10, 3), pow(7, 3, 13), "
        "isinstance(bytes('abc', 'utf-8'), bytes), isinstance(bytearray(b'abc'), bytearray)]",
        name="con_guard",
    )
    assert client.get_contract_proxy("con_guard").probe() == [42, 1000, 5, True, True]


def test_native_range_remains_lazy_until_materialized(client):
    client.submit("@export\ndef probe():\n    return len(range(1000000))", name="con_guard")
    assert client.get_contract_proxy("con_guard").probe() == 1000000


def test_native_large_right_shift_returns_zero_without_allocating(client):
    client.submit("@export\ndef probe(n: int):\n    return 1 >> n", name="con_guard")
    assert client.get_contract_proxy("con_guard").probe(n=constants.MAX_INTEGER_BITS + 1) == 0


class TestHostAdmissionGuards(TestCase):
    def test_contracting_package_refuses_optimized_python(self):
        environment = os.environ | {"PYTHONOPTIMIZE": "1"}
        result = subprocess.run(
            [sys.executable, "-c", "import contracting"],
            capture_output=True,
            text=True,
            env=environment,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("xian-contracting refuses to run with PYTHONOPTIMIZE", result.stderr)

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
