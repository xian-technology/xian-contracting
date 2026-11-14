"""Observable behaviour of the SDK decimal and time types, pinned case by case.

Each table is behaviour that callers (encoders, the SDK, archival tooling)
rely on, including the legacy operations the V2 VM does not offer.
"""

import decimal
import pickle
import re
from datetime import datetime, timezone
from decimal import Decimal, DivisionByZero, InvalidOperation

import pytest
from xian_runtime_types.decimal import (
    ContractingDecimal,
    DecimalOverflowError,
    canonical_fixed,
    fix_precision,
    make_max_decimal_str,
    make_min_decimal_str,
)
from xian_runtime_types.time import (
    Datetime,
    Timedelta,
    datetime_module,
    get_raw_seconds,
    to_contract_time,
)

cd = ContractingDecimal
ONE_ULP = "0." + "0" * 29 + "1"
LARGEST = "9" * 61 + "." + "9" * 30


@pytest.mark.parametrize(
    ("value", "text", "normalized"),
    [
        (1, "1", "1"),
        (1.2, "1.2", "1.2"),
        (1e-7, "0.0000001", "1E-7"),
        ("1_000", "1000", "1E+3"),
        (" 1.10 ", "1.1", "1.1"),
        ("-0", "0", "0"),
        ("1e-31", "0", "0"),
        (
            "-1.0000000000000000000000000000019",
            "-1.000000000000000000000000000001",
            "-1.000000000000000000000000000001",
        ),
        (Decimal("1E+2"), "100", "1E+2"),
        ((0, (1, 5), -1), "1.5", "1.5"),
        (cd("2.5"), "2.5", "2.5"),
        (ONE_ULP, ONE_ULP, "1E-30"),
        (LARGEST, LARGEST, LARGEST),
    ],
)
def test_construction_truncates_onto_the_grid(value, text, normalized):
    value = cd(value)
    assert (str(value), repr(value), str(value._d)) == (text, text, normalized)


@pytest.mark.parametrize(
    ("value", "error", "message"),
    [
        (True, InvalidOperation, "ConversionSyntax"),
        ("abc", InvalidOperation, "ConversionSyntax"),
        ([1], ValueError, "sequence of length 3"),
        (None, TypeError, "NoneType"),
        (
            10**61,
            DecimalOverflowError,
            "Value 1" + "0" * 61 + " exceeds the supported decimal range.",
        ),
        ("1e61", DecimalOverflowError, "Value 1E+61 exceeds"),
        (float("nan"), DecimalOverflowError, "Value NaN exceeds"),
        ("-Infinity", DecimalOverflowError, "Value -Infinity exceeds"),
    ],
)
def test_construction_rejects_what_is_not_a_grid_number(value, error, message):
    with pytest.raises(error, match=message.replace("+", r"\+")):
        cd(value)


@pytest.mark.parametrize(
    ("left", "op", "right", "expected"),
    [
        ("7", "//", "2", "3"),
        ("-7", "//", "2", "-3"),
        ("-7.5", "//", "2", "-3"),
        ("7", "%", "-2", "1"),
        ("-7", "%", "2", "-1"),
        ("-7.5", "%", "2", "-1.5"),
        ("1", "%", "0.000000000000000000000000000003", ONE_ULP),
        ("1", "/", "3", "0.333333333333333333333333333333"),
        ("-1", "/", "3", "-0.333333333333333333333333333333"),
        ("-5.1234", "*", "2.3451", "-12.01488534"),
        (ONE_ULP, "*", "0.5", "0"),
        ("-" + ONE_ULP, "*", "0.5", "0"),
    ],
)
def test_arithmetic_truncates_toward_zero(left, op, right, expected):
    operations = {
        "/": lambda a, b: a / b,
        "//": lambda a, b: a // b,
        "%": lambda a, b: a % b,
        "*": lambda a, b: a * b,
    }
    assert operations[op](cd(left), cd(right)) == cd(expected)


@pytest.mark.parametrize("op", [lambda a, b: a / b, lambda a, b: a // b, lambda a, b: a % b])
def test_division_by_zero(op):
    with pytest.raises(DivisionByZero):
        op(cd("1"), 0)


def test_results_outside_the_range_name_the_scaled_result():
    with pytest.raises(
        DecimalOverflowError, match="Value scaled integer 1" + "0" * 91 + " exceeds"
    ):
        cd("9" * 61) + 1
    with pytest.raises(
        DecimalOverflowError, match="scaled integer -1" + "9" * 60 + "8" + "0" * 30 + " "
    ):
        cd("9" * 61) * -2


@pytest.mark.parametrize(
    ("base", "exponent", "expected"),
    [
        ("2", 10, "1024"),
        ("-2", 3, "-8"),
        ("-1.5", 2, "2.25"),
        ("2", -1, "0.5"),
        ("3", -1, "0.333333333333333333333333333333"),
        ("-0.5", -3, "-8"),
        ("0", 0, "1"),
        ("0", 5, "0"),
        ("10", -30, ONE_ULP),
        ("10", -31, "0"),
        # Each product is truncated, so long chains lose the last digits.
        ("1.1", 50, "117.390852879695316506666495990357"),
        ("7", -7, "0.000001214265678902012402509644"),
        ("1.000000000000000000000000000001", 10**6, "1.000000000000000000000001"),
        ("2", cd("2.0"), "4"),
        ("2", "-2", "0.25"),
        ("2", "0.5", "1.414213562373095048801688724209"),
        ("0.25", cd("0.5"), "0.5"),
        ("0", 0.5, "0"),
    ],
)
def test_power_with_integral_exponents_or_one_half(base, exponent, expected):
    assert cd(base) ** exponent == cd(expected)


def test_power_reflected_operands():
    assert (2 ** cd(3), "2" ** cd(2), Decimal(2) ** cd(-1)) == (cd(8), cd(4), cd("0.5"))


@pytest.mark.parametrize(
    ("base", "exponent", "error", "message"),
    [
        ("2", "1.5", InvalidOperation, "^$"),
        ("2", "-0.5", InvalidOperation, "^$"),
        ("-4", "0.5", InvalidOperation, "^$"),
        ("2", True, InvalidOperation, "ConversionSyntax"),
        ("0", -1, DecimalOverflowError, "Value Infinity exceeds"),
        ("0.0000000000000001", -3, DivisionByZero, "^$"),
        ("10", 61, DecimalOverflowError, "scaled integer 1" + "0" * 91 + " "),
        ("10", -61, DecimalOverflowError, "scaled integer 1" + "0" * 91 + " "),
        # 10**64: the square that is never needed already leaves the range.
        ("10", 64, DecimalOverflowError, "scaled integer 1" + "0" * 94 + " "),
        ("1.5", 10**9, DecimalOverflowError, "scaled integer 1441201271173910994302038255"),
    ],
)
def test_power_failures(base, exponent, error, message):
    with pytest.raises(error, match=message):
        cd(base) ** exponent


@pytest.mark.parametrize(
    ("other", "expected"),
    [
        (cd("2.5"), (True, False, False, True)),
        (2, (False, False, True, True)),
        (2.5, (True, False, False, True)),
        (True, (False, False, True, True)),
        (Decimal("2.5000000000000000000000000000001"), (False, True, False, False)),
    ],
)
def test_comparisons(other, expected):
    value = cd("2.5")
    assert (value == other, value < other, value > other, value >= other) == expected


def test_comparisons_with_non_numbers():
    value = cd("2.5")
    assert (value == "2.5", value != None) == (False, True)  # noqa: E711
    with pytest.raises(
        TypeError, match="'<' not supported between instances of 'decimal.Decimal' and 'str'"
    ):
        value < "3"  # noqa: B015
    with pytest.raises(InvalidOperation):
        value < Decimal("NaN")  # noqa: B015
    with pytest.raises(DecimalOverflowError):
        value < float("nan")  # noqa: B015


def test_conversions_and_protocols():
    value = cd("-2.75")
    assert (int(value), float(value), bool(value), bool(cd(0))) == (-2, -2.75, True, False)
    assert (-value, +value, abs(value)) == (cd("2.75"), value, cd("2.75"))
    assert pickle.loads(pickle.dumps(value)) == value
    assert (format(value, ".1f"), format(value, ">8"), f"{cd(ONE_ULP)}") == (
        "-2.8",
        "   -2.75",
        ONE_ULP,
    )
    with pytest.raises(TypeError, match="unhashable"):
        hash(value)
    with pytest.raises(TypeError, match=r"ContractingDecimal.__pow__\(\) takes 2 positional"):
        pow(value, 2, 3)


def test_round_returns_an_int_or_a_decimal_on_the_grid():
    assert (round(cd("2.5")), round(cd("-0.5")), round(cd("2.675"), 2)) == (2, 0, cd("2.68"))
    assert round(cd("1.5"), 30) == cd("1.5")
    with pytest.raises(TypeError, match="ndigits must be an int or None"):
        round(cd("1.5"), 1.0)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (Decimal("1.50"), "1.5"),
        (Decimal("1E+2"), "100"),
        (Decimal("-0"), "0"),
        ("+0012300e-2", "123"),
        ("-.5", "-0.5"),
        ("5.", "5"),
        ("100000e-35", ONE_ULP),
        ("-0e999999999999999999999", "0"),
        ("1e-0000000000000000000000000000000000000000000000001", "0.1"),
        (-5, "-5"),
        (cd("-0.000001"), "-0.000001"),
        (LARGEST, LARGEST),
    ],
)
def test_canonical_fixed_spelling(value, expected):
    assert canonical_fixed(value) == expected


@pytest.mark.parametrize(
    ("value", "error", "message"),
    [
        (" 1", ValueError, "invalid decimal spelling"),
        ("1_0", ValueError, "invalid decimal spelling"),
        ("١", ValueError, "invalid decimal spelling"),
        ("nan", ValueError, "invalid decimal spelling"),
        (Decimal("NaN"), ValueError, "decimal must be finite"),
        ("1e-31", ValueError, "not exactly representable at scale 30"),
        ("1e61", DecimalOverflowError, "decimal exceeds the supported range"),
        ("1e999999999999999999999999", DecimalOverflowError, "decimal exceeds the supported range"),
        ("1e-999999999999999999999999", ValueError, "not exactly representable at scale 30"),
        (10**61, DecimalOverflowError, "decimal exceeds the supported range"),
        (2**512, OverflowError, "integer exceeds 512 bits"),
        (True, TypeError, "requires decimal text"),
        (1.5, TypeError, "requires decimal text"),
    ],
)
def test_canonical_fixed_rejects(value, error, message):
    with pytest.raises(error, match=message):
        canonical_fixed(value)


def test_fix_precision_is_the_normalized_v1_spelling():
    assert [str(fix_precision(v)) for v in (Decimal("100"), "1.50", 1.5, Decimal("5.0E-30"))] == [
        "1E+2",
        "1.5",
        "1.5",
        "5E-30",
    ]
    for value in ("abc", True, [1, 2, 3]):
        with pytest.raises(DecimalOverflowError, match=re.escape(f"Value {value} exceeds")):
            fix_precision(value)
    with pytest.raises(TypeError):
        fix_precision(None)


def test_decimal_text_helpers():
    assert (make_min_decimal_str(3), make_min_decimal_str(0)) == ("0.001", "0.1")
    assert (make_max_decimal_str(3, 2), make_max_decimal_str(0, 2), make_max_decimal_str(2)) == (
        "999.99",
        ".99",
        "99",
    )


def test_datetime_fields_text_and_arithmetic():
    moment = Datetime(2020, 1, 2, 3, 4, 5, 6)
    assert (
        moment.year,
        moment.month,
        moment.day,
        moment.hour,
        moment.minute,
        moment.second,
        moment.microsecond,
    ) == (2020, 1, 2, 3, 4, 5, 6)
    assert (str(moment), repr(Datetime(2020, 1, 1))) == (
        "2020-01-02 03:04:05.000006",
        "2020-01-01 00:00:00",
    )
    start = Datetime(2020, 1, 1)
    assert ((moment - start).seconds, (start - moment).seconds) == (97445, -97446)
    assert moment + Timedelta(days=1) == Datetime(2020, 1, 3, 3, 4, 5, 6)
    assert Timedelta(days=1) + moment == Datetime(2020, 1, 3, 3, 4, 5, 6)
    assert Timedelta(seconds=-1) - start == Datetime(2020, 1, 1, 0, 0, 1)
    with pytest.raises(TypeError):
        moment - Timedelta(days=1)
    with pytest.raises(OverflowError, match="date value out of range"):
        Datetime(9999, 12, 31) + Timedelta(days=1)
    with pytest.raises(TypeError, match="<class 'int'> is not a Datetime!"):
        moment < 1  # noqa: B015
    assert start < moment <= moment and moment > start >= start


def test_datetime_constructors():
    assert Datetime._from_datetime(datetime(2020, 1, 2, tzinfo=timezone.utc)) == Datetime(
        2020, 1, 2
    )
    assert Datetime.strptime("2020-01-02 03:04:05.5", "%Y-%m-%d %H:%M:%S.%f") == Datetime(
        2020, 1, 2, 3, 4, 5, 500000
    )
    with pytest.raises(ValueError, match="day 30 must be in range 1..29"):
        Datetime(2020, 2, 30)
    with pytest.raises(TypeError):
        Datetime(2020.0, 1, 1)


def test_timedelta_components_text_and_parts():
    span = Timedelta(weeks=2, days=1, hours=4, minutes=12, seconds=10)
    assert (span.seconds, span.minutes, span.hours, span.days, span.weeks) == (
        1311130,
        21852,
        364,
        15,
        2,
    )
    negative = Timedelta(seconds=-1)
    assert (negative.seconds, negative.minutes, negative.hours, negative.days, negative.weeks) == (
        -1,
        -1,
        -1,
        -1,
        -1,
    )
    assert [
        str(Timedelta(**kw))
        for kw in ({}, {"days": 1}, {"days": 2, "seconds": 5}, {"seconds": -90061})
    ] == [
        "0:00:00",
        "1 day, 0:00:00",
        "2 days, 0:00:05",
        "-2 days, 22:58:59",
    ]
    assert Timedelta(seconds="5", days=1.5, hours=-1.5) == Timedelta(days=1, seconds=5 - 3600)
    with pytest.raises(OverflowError, match="days=1000000000; must have magnitude <= 999999999"):
        Timedelta(seconds=86400000000000)
    assert Timedelta(seconds=-86399999913600).days == -999999999


def test_timedelta_arithmetic():
    span = Timedelta(days=1, seconds=5)
    assert span + span == Timedelta(days=2, seconds=10)
    assert span - Timedelta(days=2) == Timedelta(days=-1, seconds=5)
    assert span * Timedelta(days=-2, seconds=82739) == Timedelta(days=2, seconds=68095)
    assert (span * 3, span * True, span * -1) == (
        Timedelta(days=3, seconds=15),
        span,
        Timedelta(seconds=-86405),
    )
    for other in (1.5, cd(2), "x", None):
        with pytest.raises(TypeError):
            span * other
    for other in (1, None):
        with pytest.raises(TypeError):
            span + other
        with pytest.raises(TypeError):
            span - other
    with pytest.raises(TypeError, match="is not a Timedelta!"):
        span < 1  # noqa: B015
    assert Timedelta(days=1) < span <= span and span > Timedelta() >= Timedelta()


def test_time_helpers():
    assert get_raw_seconds(1, 1, 1, 1, 1) == 694861
    assert to_contract_time(Datetime(2020, 1, 2, 3, 4, 5, 6)) == {"__time__": [2020, 1, 2, 3, 4, 5]}
    assert to_contract_time(datetime(2020, 1, 2, 3, 4, 5)) == {"__time__": [2020, 1, 2, 3, 4, 5]}
    with pytest.raises(TypeError, match="Expected datetime.datetime or Datetime"):
        to_contract_time("2020-01-02")
    assert (datetime_module.__name__, datetime_module.datetime, datetime_module.timedelta) == (
        "datetime",
        Datetime,
        Timedelta,
    )
    assert datetime_module.WEEKS == Timedelta(days=7)


def test_results_do_not_depend_on_the_ambient_decimal_context():
    with decimal.localcontext(decimal.Context(prec=3, rounding=decimal.ROUND_UP)):
        assert cd("2") ** cd("0.5") == cd("1.414213562373095048801688724209")
        assert cd("1") / cd("3") == cd("0.333333333333333333333333333333")
        assert canonical_fixed("123456.789") == "123456.789"
