"""Authored format() and f-string behavior, independent of native expectations."""

import pytest

from tests.compatibility.runner import encode, run_case

pytestmark = pytest.mark.optional_native

SUCCESS = [
    ("format('é猫', '*^7')", "**é猫***"),
    ("format('abcdef', '>8.3s')", "     abc"),
    ("format('xy', '05')", "xy000"),
    ("format(-42, '+08d')", "-0000042"),
    ("format(42, '*^9d')", "***42****"),
    ("format(255, '#010x')", "0x000000ff"),
    ("format(-255, '#010X')", "-0X00000FF"),
    ("format(1234567, ',d')", "1,234,567"),
    ("format(65535, '#_x')", "0xffff"),
    ("format(65536, '#_x')", "0x1_0000"),
    ("format(1234, '010,d')", "00,001,234"),
    ("format(9731, 'c')", "☃"),
    ("format(True, '04d')", "0001"),
    ("format(False, '')", "False"),
    ("format(12, '.2f')", "12.00"),
    ("format(float('2.675'), '.2f')", "2.67"),
    ("format(float('2.5'), '.0f')", "2"),
    ("format(float('3.5'), '.0f')", "4"),
    ("format(float('-0'), '+z.2f')", "+0.00"),
    ("format(float('-0.004'), 'z.2f')", "0.00"),
    ("format(float('12.5'), '.2e')", "1.25e+01"),
    ("format(float('0.0000123'), '.2g')", "1.2e-05"),
    ("format(float('999.5'), '.3g')", "1e+03"),
    ("format(float('12'), '#.4g')", "12.00"),
    ("format(float('12'), '.4')", "12.0"),
    ("format(float('0.125'), '.1%')", "12.5%"),
    ("format(float('inf'), '+08F')", "+0000INF"),
    ("format(float('nan'), 'F')", "NAN"),
    ("format(float('1e16'), '')", "1e+16"),
    ("format(float('1e-7'), '')", "1e-07"),
    ("format(float('12345.25'), '_.2f')", "12_345.25"),
    ("format(float('12345.25'), 'n')", "12345.2"),
    ("format(None, '')", "None"),
    ("format([1, 2], '')", "[1, 2]"),
    ("format(Exception('x'), '')", "x"),
    ("format(round(decimal('2.125'), 3), '.2f')", "2.12"),
    ("f'{42:#06x}'", "0x002a"),
    ("f'{float(\"2.675\"):.2f}'", "2.67"),
    ("f'{\"é\"!r}'", "'é'"),
    ("f'{\"é\"!a}'", "'\\xe9'"),
    ("f'{Exception(\"x\")!s}'", "x"),
    ("f'{42:0{6}d}'", "000042"),
]

INVALID = [
    "format('x', '+s')",
    "format('x', '=5')",
    "format('x', ',s')",
    "format(1, '.2d')",
    "format(1, 'z')",
    "format(1, ',x')",
    "format(1, '+c')",
    "format(1114112, 'c')",
    "format(float('1'), 'd')",
    "format(float('1'), ',n')",
    "format(decimal('1'), '.2f')",
    "format(None, 's')",
    "format(1, '99999999999999999999d')",
    "format('x', '99999999999999999999s')",
]


@pytest.mark.parametrize("expression,expected", SUCCESS)
def test_value_formatting(tmp_path, expression, expected):
    actual = run_case(
        {"id": "value_format", "source": f"@export\ndef probe():\n    return {expression}\n"},
        tmp_path,
    )
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode(expected), actual


@pytest.mark.parametrize("expression", INVALID)
def test_invalid_value_formatting(tmp_path, expression):
    actual = run_case(
        {
            "id": "invalid_value_format",
            "source": f"@export\ndef probe():\n    return {expression}\n",
        },
        tmp_path,
    )
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 1, actual
    assert actual["writes"] == encode({})


def test_format_preserves_recursive_root_identity(tmp_path):
    source = (
        "@export\ndef probe():\n    value=[]\n    value.append(value)\n    return format(value)\n"
    )
    actual = run_case({"id": "format_cycle", "source": source}, tmp_path)
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode("[[...]]")


def test_fstring_evaluates_spec_before_conversion(tmp_path):
    source = """values = [1]
def specification():
    values.append(2)
    return ''
@export
def probe():
    return f'{values!s:{specification()}}'
"""
    actual = run_case({"id": "format_evaluation_order", "source": source}, tmp_path)
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 0, actual
    # Both engines follow the historical VM policy: evaluate the specification
    # before conversion, including its mutation of the value being converted.
    assert actual["result"] == encode("[1, 2]")


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("str(float('1e-7'))", "1e-07"),
        ("ascii(float('1e16'))", "1e+16"),
        ("str([float('1e-7'), float('1e16')])", "[1e-07, 1e+16]"),
        ("str([float('-0'), float('inf'), float('-nan')])", "[-0.0, inf, nan]"),
        ("ascii(['é', '猫'])", "['\\xe9', '\\u732b']"),
        ('ascii("don\\\'t")', '"don\'t"'),
    ],
)
def test_scalar_and_nested_representations(tmp_path, expression, expected):
    actual = run_case(
        {
            "id": "value_representations",
            "source": f"@export\ndef probe():\n    return {expression}\n",
        },
        tmp_path,
    )
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode(expected), actual
