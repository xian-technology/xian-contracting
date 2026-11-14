"""The SDK's ContractingDecimal, Datetime and Timedelta compute what the V2 VM computes.

The VM is the reference: each probe evaluates the same operations in a
contract and in Python on the SDK types and requires identical results
(values, types and text).
"""

import random

import pytest
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.time import Datetime, Timedelta

from tests.integration.test_vm_v2_numeric_boundaries import call

pytestmark = pytest.mark.optional_native

DECIMAL_SOURCE = """@export
def probe(rows: list):
    out = []
    for a, b, m, n in rows:
        x = decimal(a)
        y = decimal(b)
        quotient = None
        if y != 0:
            quotient = x / y
        out.append([str(x), x + y, x - y, x * y, quotient, x + m, x * m, m - x,
                    x == y, x != y, x < y, x <= y, x > y, x >= y,
                    x == n, x != n, x < n, x > n, round(x), round(x, 3), round(x, -2), -x, abs(x)])
    return out
"""

TIME_SOURCE = """@export
def probe(rows: list):
    out = []
    for parts, seconds, factor in rows:
        moment = datetime.datetime(*parts)
        span = datetime.timedelta(seconds=seconds)
        later = moment + span
        out.append([str(moment), str(span), later, span + moment, later - moment, moment - later,
                    span.seconds, span.minutes, span.hours, span.days, span.weeks,
                    span * factor, span * span, span + span, span - span * 2, bool(span),
                    moment == later, moment < later, span < span * 2, moment == 1, span == 1,
                    moment.year, moment.month, moment.day, moment.hour, moment.minute,
                    moment.second, moment.microsecond])
    return out
"""


def _grid_text(rng, integer_digits):
    scaled = rng.randint(0, 10 ** (integer_digits + 30))
    text = str(scaled).rjust(31, "0")
    text = f"{text[:-30]}.{text[-30:]}".rstrip("0").rstrip(".")
    return ("-" if rng.random() < 0.5 else "") + text


def _decimal_cases():
    """Rows ``[a, b, m, n]``: decimals a and b, a small int m, any VM int n."""
    rng = random.Random(20261115)
    edges = ["0", "1", "-1", "0.5", "2.5", "-2.5", "0." + "0" * 29 + "1", "1234.5678", "-0.0005"]
    rows = [[a, b, m, m] for a in edges for b in edges for m in (0, 3, -7)]
    for _ in range(300):
        # Products stay inside the range: at most 30 integer digits per side.
        a, b = _grid_text(rng, rng.randint(0, 30)), _grid_text(rng, rng.randint(0, 30))
        rows.append([a, b, rng.randint(-(10**20), 10**20), rng.randint(-(2**511), 2**511)])
    # Ints beyond the decimal range compare exactly (numeric_v2::ordering).
    rows += [["1.5", "2", 2, 2**300], ["-1.5", "2", 2, -(2**300)], ["9" * 30, "1", 1, 10**61]]
    return rows


def _sdk_decimal_row(a, b, m, n):
    x, y = ContractingDecimal(a), ContractingDecimal(b)
    quotient = x / y if y != 0 else None
    return [str(x), x + y, x - y, x * y, quotient, x + m, x * m, m - x,
            x == y, x != y, x < y, x <= y, x > y, x >= y,
            x == n, x != n, x < n, x > n, round(x), round(x, 3), round(x, -2), -x, abs(x)]  # fmt: skip


def _same(left, right):
    return type(left) is type(right) and str(left) == str(right) and left == right


def test_decimal_arithmetic_comparison_rounding_and_text_match_the_vm():
    rows = _decimal_cases()
    for start in range(0, len(rows), 200):
        chunk = rows[start : start + 200]
        result = call(DECIMAL_SOURCE, kwargs={"rows": chunk})
        assert result.status_code == 0, result.result
        for row, chain in zip(chunk, result.result, strict=True):
            sdk = _sdk_decimal_row(*row)
            for index, (mine, theirs) in enumerate(zip(sdk, chain, strict=True)):
                assert _same(mine, theirs), (row, index, mine, theirs)


def _time_cases():
    rng = random.Random(20261116)
    rows = [
        [[2020, 1, 1], 0, 2],
        [[2020, 1, 2, 3, 4, 5, 6], -90061, -3],
        [[1, 1, 1, 0, 0, 0, 1], 59, 0],
    ]
    for _ in range(200):
        parts = [
            rng.randint(100, 9000),
            rng.randint(1, 12),
            rng.randint(1, 28),
            rng.randint(0, 23),
            rng.randint(0, 59),
            rng.randint(0, 59),
            rng.choice([0, rng.randint(1, 999999)]),
        ]
        rows.append(
            [parts[: rng.randint(3, 7)], rng.randint(-(10**9), 10**9), rng.randint(-50, 50)]
        )
    return rows


def _sdk_time_row(parts, seconds, factor):
    moment = Datetime(*parts)
    span = Timedelta(seconds=seconds)
    later = moment + span
    return [str(moment), str(span), later, span + moment, later - moment, moment - later,
            span.seconds, span.minutes, span.hours, span.days, span.weeks,
            span * factor, span * span, span + span, span - span * 2, bool(span),
            moment == later, moment < later, span < span * 2, moment == 1, span == 1,
            moment.year, moment.month, moment.day, moment.hour, moment.minute,
            moment.second, moment.microsecond]  # fmt: skip


def test_datetime_and_timedelta_match_the_vm():
    rows = _time_cases()
    result = call(TIME_SOURCE, kwargs={"rows": rows})
    assert result.status_code == 0, result.result
    for row, chain in zip(rows, result.result, strict=True):
        sdk = _sdk_time_row(*row)
        for index, (mine, theirs) in enumerate(zip(sdk, chain, strict=True)):
            assert _same(mine, theirs), (row, index, mine, theirs)
