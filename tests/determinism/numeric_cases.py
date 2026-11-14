"""Independent exact arithmetic vectors shared by conformance and native campaigns."""

# Expected values are independent of the compiler, VM and host decimal context.
VECTORS = [
    ("9007199254740993 / 1", "9007199254740993"),
    ("1 / 3", "0.333333333333333333333333333333"),
    ("-1 / 3", "-0.333333333333333333333333333333"),
    ("1 / 10**31", "0"),
    ("10**65 / 10**65", "1"),
    ("0.123456789012345678901234567891", "0.123456789012345678901234567891"),
    ("0.000000000000000000000000000001 * 0.5", "0"),
    ("(10**65) * 0.0000000001", "1" + "0" * 55),
    ("-7 // 3", -3),
    ("-7 % 3", 2),
    ("mul_div_floor(-5, 1, 2)", -3),
    ("mul_div_ceil(-5, 1, 2)", -2),
    ("mul_div_floor(2**500, 2**500, 2**500)", 2**500),
    ("quantize(1.005, 2, 'half_even')", "1"),
    ("quantize(-1.015, 2, 'half_even')", "-1.02"),
    ("quantize(-1.001, 2, 'floor')", "-1.01"),
    ("quantize(-1.001, 2, 'ceil')", "-1"),
    ("quantize(-1.001, 2, 'toward_zero')", "-1"),
    ("sqrt(2)", "1.414213562373095048801688724209"),
    ("sqrt(10**100)", "1" + "0" * 50),
    # round(): Python's half-to-even on ints and decimals.
    ("round(2.5)", 2),
    ("round(-2.5)", -2),
    ("round(3.5)", 4),
    ("round(1.005, 2)", "1"),
    ("round(-1.015, 2)", "-1.02"),
    ("round(0.000000000000000000000000000015, 29)", "0.00000000000000000000000000002"),
    ("round(1234.5678, -2)", "1200"),
    ("round(1.5, 10**40)", "1.5"),
    ("round(125, -1)", 120),
    ("round(-135, -1)", -140),
    ("round(2**511, -154)", 10**154),
    ("round(5, -(10**40))", 0),
]

FAILURES = [
    "1 / 0",
    "10**61 / 1",
    "2**512",
    "sqrt(-1)",
    "mul_div_floor(1, 2, 0)",
    "quantize(0.1, 31, 'floor')",
    "round(True)",
    "round(1, 0.5)",
    "round(" + "9" * 61 + ".5, 0)",
    "round(2**512 - 1, -1)",
]

# random.random(): an exact decimal on the 30-place grid, drawn like
# randrange(10**30); the stored draw puts its exact digits in the writes.
RANDOM_DECIMAL_SALTS = ["", "salt", 7, None]


def numeric_cases():
    cases = []
    for index, (expression, expected) in enumerate(VECTORS):
        # JSON documents carry exact decimal expectations as strings. The
        # observer compares the actual decimal type and all of its digits.
        oracle = (
            {"expected_decimal": expected}
            if isinstance(expected, str)
            else {"expected_result": expected}
        )
        cases.append(
            {
                "id": f"numeric_v2_value_{index}",
                "vm_profile": "xian_vm_v2",
                "source": (
                    "balance = Variable()\n@export\ndef probe():\n"
                    f"    balance.set({expression})\n    return balance.get()\n"
                ),
                **oracle,
            }
        )
    for index, expression in enumerate(FAILURES):
        cases.append(
            {
                "id": f"numeric_v2_failure_{index}",
                "vm_profile": "xian_vm_v2",
                "source": (
                    "balance = Variable()\n@export\ndef probe():\n"
                    f"    balance.set(1)\n    return {expression}\n"
                ),
                "expected_failure": True,
            }
        )
    return cases


def random_decimal_cases():
    cases = []
    for index, salt in enumerate(RANDOM_DECIMAL_SALTS):
        cases.append(
            {
                "id": f"random_decimal_{index}",
                "vm_profile": "xian_vm_v2",
                "source": (
                    "drawn = Variable()\n@export\ndef probe():\n"
                    f"    random.seed({salt!r})\n    r = random.random()\n    drawn.set(r)\n"
                    f"    random.seed({salt!r})\n    k = random.randrange(10**30)\n"
                    "    return [0 <= r < 1, r == k / 10**30, int(r * 10**30) == k,\n"
                    "            round(r, 2) <= 1, isinstance(r, decimal)]\n"
                ),
                "expected_result": [True, True, True, True, True],
            }
        )
    return cases
