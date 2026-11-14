"""The SDK value types answer as the V2 VM does where the VM defines the answer."""

from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.time import Datetime, Timedelta


def test_decimal_compares_exactly_with_ints_beyond_the_decimal_range():
    # numeric_v2::ordering compares any VM int (up to 512 bits) with a decimal.
    huge = 10**80
    value = ContractingDecimal("2.5")
    assert (value == huge, value != huge) == (False, True)
    assert (value < huge, value <= huge, value > -huge, value >= -huge) == (True,) * 4
    assert (huge > value, -huge < value) == (True, True)


def test_time_values_are_unequal_to_other_types():
    # VM equality: values of different types are never equal; it does not fail.
    when = Datetime(2026, 1, 2)
    span = Timedelta(days=1)
    for other in (1, None, "2026-01-02", ContractingDecimal(1)):
        assert (when == other, when != other) == (False, True)
        assert (span == other, span != other) == (False, True)
    assert (when == span, span == when) == (False, False)


def test_timedelta_truthiness_follows_its_seconds():
    # VmValue::truthy: a timedelta is true when its seconds are nonzero.
    assert not Timedelta()
    assert not Timedelta(days=1, seconds=-86400)
    assert Timedelta(seconds=-1)
    assert Timedelta(weeks=1)
    assert Datetime(1, 1, 1)


def test_zero_with_a_huge_exponent_is_zero_without_huge_work():
    # VmDecimal::from_str_literal: a zero coefficient is zero for any exponent.
    assert ContractingDecimal("0e999999999999") == 0
    assert ContractingDecimal("-0.000e-999999999999") == 0
