import decimal
import unittest
from decimal import Decimal, InvalidOperation
from unittest import TestCase

from xian_runtime_types.decimal import (
    CONTEXT,
    MAX_DECIMAL,
    MIN_DECIMAL,
    ContractingDecimal,
    DecimalOverflowError,
    fix_precision,
)


class TestDecimal(TestCase):
    def test_init(self):
        ContractingDecimal("1.1")

    def test_init_float(self):
        ContractingDecimal(1.2)

    def test_init_int(self):
        ContractingDecimal(1)

    def test_bool_true(self):
        self.assertTrue(ContractingDecimal(1))

    def test_bool_false(self):
        self.assertFalse(ContractingDecimal(0))

    def test_bool_negative_nonzero(self):
        self.assertTrue(ContractingDecimal(-1))

    def test_eq_whole_numbers(self):
        self.assertEqual(ContractingDecimal(1), ContractingDecimal(1))

    def test_eq_floats(self):
        self.assertEqual(ContractingDecimal(1.234), ContractingDecimal(1.234))

    def test_lt(self):
        self.assertLess(ContractingDecimal(1), ContractingDecimal(2))
        self.assertLess(ContractingDecimal(1.1), ContractingDecimal(2.2))

    def test_lte(self):
        self.assertLessEqual(ContractingDecimal(1), ContractingDecimal(2))
        self.assertLessEqual(ContractingDecimal(1.1), ContractingDecimal(2.2))
        self.assertLessEqual(ContractingDecimal(2.2), ContractingDecimal(2.2))

    def test_gt(self):
        self.assertGreater(ContractingDecimal(10), ContractingDecimal(2))
        self.assertGreater(ContractingDecimal(10.1), ContractingDecimal(2.2))

    def test_gte(self):
        self.assertGreaterEqual(ContractingDecimal(10), ContractingDecimal(2))
        self.assertGreaterEqual(
            ContractingDecimal(10.1), ContractingDecimal(2.2)
        )
        self.assertGreaterEqual(
            ContractingDecimal(2.2), ContractingDecimal(2.2)
        )

    def test_str(self):
        f = ContractingDecimal(1.23445)
        self.assertEqual(str(f), "1.23445")

    def test_neg(self):
        self.assertEqual(-ContractingDecimal(1), ContractingDecimal(-1))

    def test_pos(self):
        self.assertEqual(+ContractingDecimal(1), ContractingDecimal(1))

    def test_other_equality(self):
        self.assertEqual(ContractingDecimal(1), 1)
        self.assertEqual(ContractingDecimal(1), 1.0)

    def test_abs(self):
        self.assertEqual(abs(ContractingDecimal(1)), 1)
        self.assertEqual(abs(ContractingDecimal(-1)), 1)

    def test_add(self):
        self.assertEqual(ContractingDecimal(1) + ContractingDecimal(1), 2)
        self.assertEqual(ContractingDecimal(1) + ContractingDecimal(10), 11)

        self.assertEqual(
            ContractingDecimal(1.23456) + ContractingDecimal(6.54321),
            ContractingDecimal(7.77777),
        )

    def test_arbitrarily_large_number(self):
        a = ContractingDecimal(
            "38327950288419716939937510.582097494459230781640628620899"
        )
        b = ContractingDecimal(
            "67523846748184676694051320.005681271452635608277857713427"
        )
        c = ContractingDecimal(
            "105851797036604393633988830.587778765911866389918486334326"
        )

        self.assertEqual(a + b, c)

    def test_zero_equality(self):
        self.assertEqual(ContractingDecimal(0), 0)

    def test_sub(self):
        self.assertEqual(ContractingDecimal(1) - ContractingDecimal(1), 0)
        self.assertEqual(ContractingDecimal(1) - ContractingDecimal(10), -9)

        self.assertEqual(
            ContractingDecimal(1.23456) - ContractingDecimal(6.54321),
            ContractingDecimal(-5.30865),
        )

    def test_add_negs(self):
        self.assertEqual(ContractingDecimal(1) + ContractingDecimal(-1), 0)

    def test_radd(self):
        self.assertEqual(1 + ContractingDecimal(1), 2)
        self.assertEqual(1 + ContractingDecimal(10), 11)

        self.assertEqual(
            1.23456 + ContractingDecimal(6.54321), ContractingDecimal(7.77777)
        )

    def test_rsub(self):
        self.assertEqual(1 - ContractingDecimal(1), 0)
        self.assertEqual(1 - ContractingDecimal(10), -9)

        self.assertEqual(
            1.23456 - ContractingDecimal(6.54321), ContractingDecimal(-5.30865)
        )

    def test_mul(self):
        self.assertEqual(ContractingDecimal(5) * ContractingDecimal(42), 210)
        self.assertEqual(ContractingDecimal(0) * ContractingDecimal(100), 0)
        self.assertEqual(ContractingDecimal(-5) * ContractingDecimal(42), -210)
        self.assertEqual(
            ContractingDecimal(5.1234) * ContractingDecimal(2.3451),
            ContractingDecimal("12.01488534"),
        )

    def test_rmul(self):
        self.assertEqual(5 * ContractingDecimal(42), 210)
        self.assertEqual(0 * ContractingDecimal(100), 0)
        self.assertEqual(-5 * ContractingDecimal(42), -210)
        self.assertEqual(
            5.1234 * ContractingDecimal(2.3451),
            ContractingDecimal("12.01488534"),
        )

    def test_div(self):
        self.assertEqual(
            (ContractingDecimal(1) / ContractingDecimal(3)),
            ContractingDecimal("0.333333333333333333333333333333"),
        )
        self.assertEqual(ContractingDecimal(3) / ContractingDecimal(1), 3)

    def test_div_large_decimals(self):
        a = "0.78164062862089986280348253421170"
        b = "0.53642401735797937714409102114816"

        c = ContractingDecimal(a) / ContractingDecimal(b)

        print(c)

    def test_fix_precision_cuts_too_low(self):
        d = Decimal("1.123456789012345678901234567890123")
        e = Decimal("1.12345678901234567890123456789")

        self.assertEqual(fix_precision(d), e)

    def test_fix_precision_cuts_too_high(self):
        e = Decimal("123456789012345678901234567890")
        self.assertEqual(fix_precision(e), e)

    def test_fix_precision_doesnt_cut_high(self):
        e = Decimal("12345678901234567890123456789")
        self.assertEqual(fix_precision(e), e)

    def test_fix_precision_cuts_all_decimals_if_too_high(self):
        e = Decimal("123456789012345678901234567890.123456")
        self.assertEqual(fix_precision(e), e)

    def test_fix_precision_cuts_decimals_if_high_but_not_too_high(self):
        e = Decimal(
            "12345678901234567890123456789.123456789012345678901234567890"
        )
        f = Decimal(
            "12345678901234567890123456789.12345678901234567890123456789"
        )

        self.assertEqual(fix_precision(e), f)

    def test_fix_precision_rejects_negative_overflow(self):
        e = Decimal(
            "-12345678901234567890123456789012345678901234567890123456789012"
        )
        with self.assertRaises(DecimalOverflowError):
            fix_precision(e)

    def test_fix_precision_rejects_positive_overflow(self):
        e = Decimal(
            "12345678901234567890123456789012345678901234567890123456789012"
        )
        with self.assertRaises(DecimalOverflowError):
            fix_precision(e)

    def test_fix_precision_rounds_negative_toward_zero(self):
        d = Decimal("-1.123456789012345678901234567890123")
        e = Decimal("-1.12345678901234567890123456789")

        self.assertEqual(fix_precision(d), e)

    def test_max_decimal_exceeds_ethereum_18_decimal_range(self):
        ethereum_style_max = Decimal(2**256 - 1) / (Decimal(10) ** 18)
        self.assertGreater(MAX_DECIMAL, ethereum_style_max)

    def test_fix_precision_allows_extra_fractional_digits_if_value_stays_in_range(
        self,
    ):
        e = Decimal("9" * 61 + "." + "9" * 30 + "9")
        self.assertEqual(fix_precision(e), MAX_DECIMAL)

    def test_fix_precision_does_not_depend_on_ambient_decimal_context(self):
        previous = decimal.getcontext().copy()
        try:
            decimal.setcontext(decimal.Context(prec=28))
            self.assertEqual(
                fix_precision(Decimal("9980.099711")),
                Decimal("9980.099711"),
            )
        finally:
            decimal.setcontext(previous)

    def test_contracting_decimal_can_round(self):
        s = "12345678901234567890123456789.123456789012345678901234567890"
        with decimal.localcontext(CONTEXT):
            self.assertEqual(
                round(Decimal(s), 10), round(ContractingDecimal(s), 10)
            )

    def test_contracting_decimal_arithmetic_ignores_ambient_context(self):
        previous = decimal.getcontext().copy()
        try:
            decimal.setcontext(decimal.Context(prec=5))
            self.assertEqual(
                ContractingDecimal("1") / ContractingDecimal("3"),
                ContractingDecimal("0.333333333333333333333333333333"),
            )
            self.assertEqual(
                ContractingDecimal("5.1234") * ContractingDecimal("2.3451"),
                ContractingDecimal("12.01488534"),
            )
        finally:
            decimal.setcontext(previous)

    def test_contracting_decimal_negative_tiny_scientific_notation_truncates_to_zero(
        self,
    ):
        self.assertEqual(ContractingDecimal("-1e-31"), 0)

    def test_contracting_decimal_huge_tiny_exponent_truncates_to_zero(self):
        self.assertEqual(ContractingDecimal("1e-1000000"), 0)

    def test_contracting_decimal_huge_positive_exponent_rejects_overflow(self):
        with self.assertRaises(DecimalOverflowError):
            ContractingDecimal("1e1000000")

    def test_contracting_decimal_arithmetic_rejects_overflow(self):
        with self.assertRaises(DecimalOverflowError):
            ContractingDecimal(MAX_DECIMAL) + ContractingDecimal(MIN_DECIMAL)

    def test_contracting_decimal_modulo_uses_dividend_sign(self):
        self.assertEqual(
            ContractingDecimal("-1") % ContractingDecimal("2"),
            ContractingDecimal("-1"),
        )

    def test_contracting_decimal_rejects_non_vm_decimal_exponent(self):
        with self.assertRaises(InvalidOperation):
            ContractingDecimal("9") ** ContractingDecimal("0.3")

    def test_contracting_decimal_text_is_plain_fixed_point_like_the_v2_vm(self):
        cases = [
            ("1000", "1000"),
            ("10000", "10000"),
            ("50000000", "50000000"),
            ("1234000", "1234000"),
            ("1234500", "1234500"),
            ("0.0001", "0.0001"),
            ("0.0000001", "0.0000001"),
            ("1234.5", "1234.5"),
            ("12345", "12345"),
            ("0.10", "0.1"),
            ("-1000", "-1000"),
            ("1e-30", "0.000000000000000000000000000001"),
            ("0", "0"),
            ("-0", "0"),
        ]
        for literal, expected in cases:
            with self.subTest(literal=literal):
                value = ContractingDecimal(literal)
                self.assertEqual(str(value), expected)
                self.assertEqual(repr(value), expected)
                self.assertEqual(f"{value}", expected)
                self.assertEqual(str([value]), f"[{expected}]")

    def test_contracting_decimal_format_specs_apply_to_the_plain_value(self):
        cases = [
            ("1000", ".4f", "1000.0000"),
            ("1000", ",", "1,000"),
            ("1234.5", ">10", "    1234.5"),
            ("1234.5", ",.2f", "1,234.50"),
            ("0.1", "%", "10%"),
            ("1000", "e", "1.000e+3"),
            ("-0.5", "+.3f", "-0.500"),
        ]
        for literal, spec, expected in cases:
            with self.subTest(literal=literal, spec=spec):
                self.assertEqual(format(ContractingDecimal(literal), spec), expected)

    def test_contracting_decimal_rejects_integer_format_types(self):
        with self.assertRaises(ValueError):
            format(ContractingDecimal("1"), "d")

if "__main__" == __name__:
    unittest.main()
