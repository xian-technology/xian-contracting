"""Fixed binary64 vectors; no host libm computes expected contract results.

Fractional powers have broad mathematical anchors and persist their full hex
outputs for exact cross-platform comparison. Hex strings preserve every finite
binary64 value, including subnormals and signed zero. Payload-bearing NaN source
constructors are presently rejected; those cases explicitly pin rejection.
"""

import textwrap


def _case(name, body, expected, *, record=False):
    return {
        "id": "float_edge_" + name,
        "source": ("observed = Variable()\n" if record else "")
        + "@export\ndef probe():\n"
        + textwrap.indent(body, "    ")
        + "\n",
        "expected_result": expected,
        "records_hex": record,
    }


def _powers():
    # Exact hexadecimal operands; bounds follow magnitude/monotonicity, not a
    # host's pow implementation. Include near-one, exponent and normal boundaries.
    vectors = [
        ("sqrt_two", "0x1p+1", "0x1p-1", "1", "2"),
        ("cube_two", "0x1p+1", "0x1.5555555555555p-2", "1", "2"),
        ("cube_twentyseven", "0x1.bp+4", "0x1.5555555555555p-2", "2", "4"),
        ("near_one_above", "0x1.0000000000001p+0", "0x1p+52", "2", "3"),
        ("near_one_below", "0x1.fffffffffffffp-1", "0x1p+52", "0.5", "1"),
        ("tenth_to_tenth", "0x1.999999999999ap-4", "0x1.999999999999ap-4", "0.5", "1"),
        ("ten_to_pi", "0x1.4p+3", "0x1.921fb54442d18p+1", "1000", "2000"),
        ("inverse_root_three", "0x1.8p+1", "-0x1p-1", "0.5", "1"),
        ("sqrt_min_normal", "0x1p-1022", "0x1p-1", "0", "1"),
        ("cube_min_subnormal", "0x1p-1074", "0x1.5555555555555p-2", "0", "1"),
        ("sqrt_max_normal", "0x1.fffffffffffffp+1023", "0x1p-1", "1e154", "2e154"),
        ("exponent_above_one", "0x1p+1", "0x1.0000000000001p+0", "1", "3"),
        ("base_below_two", "0x1.fffffffffffffp+0", "0x1p-1", "1", "2"),
    ]
    return [
        _case(
            name,
            f"base = float.fromhex({base!r})\nexponent = float.fromhex({exponent!r})\n"
            "values = [base ** exponent, pow(base, exponent)]\n"
            f"assert all([float({lower!r}) < value < float({upper!r}) for value in values])\n"
            "observed.set([value.hex() for value in values])\nreturn True",
            True,
            record=True,
        )
        for name, base, exponent, lower, upper in vectors
    ]


def _exact_cases():
    return [
        _case(
            "mixed_integer_power",
            "value = 2 ** float('3')\nreturn value.hex()",
            "0x1.0000000000000p+3",
        ),
        _case(
            "negative_integer_power",
            "value = pow(float('-2'), 3)\nreturn value.hex()",
            "-0x1.0000000000000p+3",
        ),
        _case(
            "power_subnormal_tie",
            "return [(float('2') ** -1074).hex(), pow(float('2'), -1075).hex()]",
            ["0x0.0000000000001p-1022", "0x0.0p+0"],
        ),
        _case(
            "sqrt_min_subnormal_exact",
            "value = float.fromhex('0x1p-1074') ** float('0.5')\nreturn value.hex()",
            "0x1.0000000000000p-537",
        ),
        _case(
            "division_min_normal",
            "value = float.fromhex('0x1p-1022') / float('2')\nreturn value.hex()",
            "0x0.8000000000000p-1022",
        ),
        _case(
            "division_subnormal_ties",
            "tiny = float.fromhex('0x1p-1074')\n"
            "return [(tiny / 2).hex(), ((-tiny) / 2).hex(), ((tiny * 3) / 2).hex()]",
            ["0x0.0p+0", "-0x0.0p+0", "0x0.0000000000002p-1022"],
        ),
        _case("division_tenth", "return (float('1') / 10).hex()", "0x1.999999999999ap-4"),
        _case(
            "addition_ties_even",
            "value = float.fromhex('0x1p+53')\n"
            "return [(value + 1).hex(), (value + 3).hex(), (value - 1).hex()]",
            ["0x1.0000000000000p+53", "0x1.0000000000002p+53", "0x1.fffffffffffffp+52"],
        ),
        _case(
            "signed_zero",
            "zero = float('-0')\n"
            "return [(zero * 2).hex(), (zero / -2).hex(), (zero + float('0')).hex(), pow(zero, 3).hex()]",
            ["-0x0.0p+0", "0x0.0p+0", "0x0.0p+0", "-0x0.0p+0"],
        ),
        _case(
            "cancellation_no_fusion",
            "a = float.fromhex('0x1.0000000000001p+0')\n"
            "b = float.fromhex('0x1.ffffffffffffep-1')\nreturn ((a * b) - 1).hex()",
            "0x0.0p+0",
        ),
        _case(
            "finite_overflow",
            "value = float.fromhex('0x1.fffffffffffffp+1023')\nreturn [(value * 2).hex(), (-value * 2).hex()]",
            ["inf", "-inf"],
        ),
        _case(
            "round_decimal_boundary",
            "values = [round(float('2.675'), 2), round(float('0.125'), 2), round(float('-0.001'), 2)]\n"
            "observed.set([value.hex() for value in values])\nreturn [str(value) for value in values]",
            ["2.67", "0.12", "-0.0"],
            record=True,
        ),
        _case(
            "nan_classification",
            "a = float('nan')\nb = float.fromhex('-nan')\n"
            "observed.set([a.hex(), b.hex(), (a + 1).hex()])\nreturn [a != a, b != b, a == b]",
            [True, True, False],
            record=True,
        ),
    ]


def _rejections():
    vectors = [
        ("divmod_tenth", "divmod(float('1'), float('0.1'))", "unsupported floordiv operands"),
        (
            "divmod_negative_boundary",
            "divmod(float.fromhex('-0x1.0000000000001p+0'), float('0.1'))",
            "unsupported floordiv operands",
        ),
        ("mod_subnormal", "float.fromhex('0x1p-1074') % float('2')", "unsupported mod operands"),
        ("nan_payload_decimal", "float('nan(123)')", "invalid numeric string"),
        (
            "nan_payload_hex",
            "float.fromhex('nan(123)')",
            "invalid hexadecimal floating-point string",
        ),
    ]
    cases = []
    for name, expression, error in vectors:
        case = _case(
            name, "observed.set('must roll back')\nreturn " + expression, None, record=True
        )
        del case["expected_result"]
        case.update(expected_failure=True, expected_error=error, records_hex=False)
        cases.append(case)
    return cases


def float_cases():
    """Return independent fresh dictionaries for the fixed edge corpus."""
    raw_nan = _case(
        "nan_public_boundary",
        "observed.set('must roll back')\n"
        "a = float('nan')\nb = float.fromhex('-nan')\ninfinity = float('inf')\n"
        "values = [a, b, a + 1, infinity - infinity, infinity * 0, infinity / infinity, "
        "pow(float('-1'), float('0.5'))]\n"
        "assert all([value != value for value in values])\nreturn values",
        None,
        record=True,
    )
    del raw_nan["expected_result"]
    raw_nan.update(
        expected_failure=True,
        expected_error="cannot encode non-finite float",
        records_hex=False,
    )
    return _powers() + _exact_cases() + _rejections() + [raw_nan]
