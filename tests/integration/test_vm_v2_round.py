"""``round()`` in V2 follows Python on ints and decimals, checked against CPython.

``round(x)`` is an int, half to even; ``round(decimal, n)`` is a decimal
quantized half to even to ``n`` places (``n`` may be negative; beyond 30 it
changes nothing); ``round(int, n)`` is an int (negative ``n`` rounds to tens,
hundreds, ... half to even). The oracle is CPython's ``round`` on
``decimal.Decimal`` (in a context wide enough to be exact) and on ``int``.
A result outside the VM's ranges (decimals below 10**61, ints of at most
512 bits) fails the call, as any other V2 operation does. Unlike CPython,
the work is bounded for any ``n`` (CPython computes ``10**-n`` for ints).
"""

import random
from decimal import ROUND_HALF_EVEN, Context, Decimal, localcontext

import pytest
from xian_runtime_types.decimal import ContractingDecimal

from tests.integration.test_vm_v2_numeric_boundaries import call

pytestmark = pytest.mark.optional_native

SOURCE = """@export
def probe(pairs: list):
    out = []
    for v, n in pairs:
        x = decimal(v) if isinstance(v, str) else v
        out.append(round(x) if n == 'absent' else round(x, n))
    return out
"""
# Exact for every V2 decimal: 61 integer and 30 fractional digits fit.
WIDE = Context(prec=200, rounding=ROUND_HALF_EVEN, Emin=-999, Emax=999)
DECIMAL_LIMIT = 10**61
ONE_ULP = "0." + "0" * 29 + "1"

DECIMALS = [
    "0",
    "1",
    "-1",
    "0.5",
    "1.5",
    "2.5",
    "-0.5",
    "-1.5",
    "-2.5",
    "0.125",
    "0.375",
    "-0.125",
    "1.005",
    "2.675",
    "99.5",
    "-99.5",
    "250",
    "-250",
    "350",
    "1250",
    "-1350",
    ONE_ULP,
    "-" + ONE_ULP,
    "0." + "0" * 29 + "5",
    "0." + "0" * 28 + "15",
    "-0." + "0" * 28 + "25",
    "3.141592653589793238462643383279",
    "123456789.987654321",
    "-123456789.987654321",
    "5" + "0" * 60,
    "-5" + "0" * 60,
    "4" + "9" * 60,
    "1" + "0" * 59 + ".5",
    "9" * 61 + "." + "9" * 30,
    "-" + "9" * 61 + "." + "9" * 30,
    "9" * 60 + ".5",
    "9" * 61 + ".5",
]
INTS = [
    0,
    5,
    15,
    25,
    35,
    -25,
    -35,
    1234567890,
    10**154,
    5 * 10**153,
    -15 * 10**152,
    2**511,
    -(2**511),
    2**512 - 1,
    -(2**512 - 1),
]
DIGITS = ["absent", None, 0, 1, 2, 5, 29, 30, 31, 100, 10**40, 2**511]
DIGITS += [-1, -2, -5, -29, -30, -31, -59, -60, -61, -62, -91, -92, -100, -10**40, -(2**511)]
INT_DIGITS = ["absent", None, 0, 1, 3, 10**40, 2**511, -1, -2, -3, -10, -100]
INT_DIGITS += [-152, -153, -154, -155, -156, -1000, -10**40, -(2**511)]


def generated_decimals(count=150, seed=20261114):
    """Random V2 decimals, a third of them ties at a random place."""
    rng = random.Random(seed)
    values = []
    for _ in range(count):
        whole = str(rng.randrange(10 ** rng.randrange(1, 62)))
        fraction = "".join(rng.choice("0123456789") for _ in range(rng.randrange(0, 31)))
        if fraction and rng.random() < 0.33:
            fraction = fraction[:-1] + "5"
        sign = rng.choice(["", "-"])
        values.append(f"{sign}{whole}.{fraction}" if fraction else f"{sign}{whole}")
    return values


def generated_ints(count=60, seed=20261115):
    rng = random.Random(seed)
    values = []
    for _ in range(count):
        value = rng.randrange(2 ** rng.randrange(1, 513))
        if rng.random() < 0.33:
            value = value // 10 * 10 + 5  # a tie at the tens
        values.append(rng.choice([1, -1]) * value)
    return [value for value in values if value.bit_length() <= 512]


def python_round(value, digits):
    """CPython's round of the same value (str: a decimal's exact text)."""
    if not isinstance(value, str):
        if digits in ("absent", None):
            return round(value) if digits == "absent" else round(value, None)
        # CPython computes 10**-n; every V2 int is below 10**155, so rounding
        # to 10**160 and beyond gives the same value (0) as any larger -n.
        return round(value, max(digits, -160))
    with localcontext(WIDE):
        number = Decimal(value)
        if digits == "absent":
            return round(number)
        if digits is None:
            return round(number, None)
        # A V2 decimal has at most 30 places and is below 10**61: rounding to
        # 31 or more places, or to 10**200 and beyond, gives the same value as
        # any larger |n| (whose quantum this context cannot represent).
        return round(number, max(min(digits, 31), -200))


def in_range(result):
    if isinstance(result, Decimal):
        return result.copy_abs() < DECIMAL_LIMIT  # abs() would round to 28 digits
    return result.bit_length() <= 512


def matrix():
    pairs = [[value, digits] for value in DECIMALS + generated_decimals() for digits in DIGITS]
    pairs += [[value, digits] for value in INTS + generated_ints() for digits in INT_DIGITS]
    return [(pair, python_round(*pair)) for pair in pairs]


def same(actual, expected):
    if isinstance(expected, Decimal):
        # V2 decimals have no negative zero and no trailing-zero quantum.
        return type(actual) is ContractingDecimal and Decimal(str(actual)) == expected
    return type(actual) is int and actual == expected


def test_round_matches_cpython_on_ints_and_decimals():
    cases = [(pair, expected) for pair, expected in matrix() if in_range(expected)]
    assert len(cases) > 6000
    for start in range(0, len(cases), 1500):
        chunk = cases[start : start + 1500]
        result = call(SOURCE, kwargs={"pairs": [pair for pair, _ in chunk]})
        assert result.status_code == 0, result.result
        for (pair, expected), actual in zip(chunk, result.result, strict=True):
            assert same(actual, expected), (pair, expected, actual)


@pytest.mark.parametrize(
    ("value", "digits"),
    [(pair[0], pair[1]) for pair, expected in matrix() if not in_range(expected)],
)
def test_results_outside_the_vm_ranges_fail(value, digits):
    result = call(SOURCE, kwargs={"pairs": [[value, digits]]})
    assert result.status_code == 1
    assert ("decimal" in str(result.result)) or ("512-bit" in str(result.result)), result.result


def test_round_of_large_values_overflows_like_python_results_would():
    # Python's results exist but leave the VM's ranges; the call fails.
    out_of_range = [pair for pair, expected in matrix() if not in_range(expected)]
    assert ["9" * 61 + ".5", 0] in out_of_range
    assert ["9" * 60 + ".5", 0] not in out_of_range
    assert [2**512 - 1, -1] in out_of_range
    assert ["9" * 61 + "." + "9" * 30, "absent"] not in out_of_range


@pytest.mark.parametrize(
    ("expression", "message"),
    [
        ("round(True)", "round() requires an int or decimal"),
        ("round(False, 1)", "round() requires an int or decimal"),
        ("round('2')", "round() requires an int or decimal"),
        ("round(None)", "round() requires an int or decimal"),
        ("round([1])", "round() requires an int or decimal"),
        ("round(1, True)", "round() ndigits must be an int or None"),
        ("round(decimal('1.5'), decimal('1'))", "round() ndigits must be an int or None"),
        ("round(1, '2')", "round() ndigits must be an int or None"),
        ("round()", "round() expects one or two positional arguments"),
        ("round(1, 2, 3)", "round() expects one or two positional arguments"),
        ("round(number=1)", "round() expects one or two positional arguments"),
        ("round(1, ndigits=2)", "round() expects one or two positional arguments"),
    ],
)
def test_wrong_arguments_fail_in_the_vm_error_style(expression, message):
    result = call(f"@export\ndef probe():\n    return {expression}")
    assert result.status_code == 1
    assert message in str(result.result), result.result


@pytest.mark.parametrize(
    ("value", "unchanged", "zero"),
    [
        ("1.5", [2, 31], [-1, -1000]),
        ("9" * 61 + "." + "9" * 30, [30, 31], [-62, -1000]),
        (7, [0, 3], [-2, -1000]),
        (2**511, [0, 3], [-156, -1000]),
    ],
)
def test_round_work_does_not_grow_with_ndigits(value, unchanged, zero):
    # A call's cost depends on its result's size, not on how large n is.
    huge = [10**40, 2**511]
    for digits in (unchanged + huge, zero + [-n for n in huge]):
        costs = set()
        for n in digits:
            result = call(SOURCE, kwargs={"pairs": [[value, n]]})
            assert result.status_code == 0, result.result
            costs.add(tuple(result.contract_costs.items()))
        assert len(costs) == 1, (digits, costs)
