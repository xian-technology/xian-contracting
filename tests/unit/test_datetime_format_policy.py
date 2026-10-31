"""The contract harness uses the same deterministic format policy as the VM."""

import pytest
from xian_runtime_types.time import Datetime


@pytest.mark.parametrize(
    "text,format",
    [
        ("Feb 03 2026", "%b %d %Y"),
        ("PM", "%p"),
        ("2026-02-03 UTC", "%Y-%m-%d %Z"),
        ("2026-02-03 +0000", "%Y-%m-%d %z"),
        ("2026 2026", "%Y %Y"),
        ("2026-02-03", "%F"),
        ("2026", "%G"),
        ("2026 03", "%Y %V"),
        ("2026-W01-1 01", "%G-W%V-%u %m"),
        ("2026 26", "%Y %y"),
        ("12 12", "%H %I"),
        ("1 1", "%w %u"),
        ("01 01", "%U %W"),
    ],
)
def test_unsupported_format_policy(text, format):
    with pytest.raises(ValueError, match="unsupported datetime format"):
        Datetime.strptime(text, format)


@pytest.mark.parametrize(
    "text,format",
    [("２０２６", "%Y"), ("2026-０2-03", "%Y-%m-%d"), ("2026-02-03.１２", "%Y-%m-%d.%f")],
)
def test_numeric_fields_require_ascii_digits(text, format):
    with pytest.raises(ValueError):
        Datetime.strptime(text, format)


def test_unicode_literals_percent_and_numeric_widths():
    assert str(Datetime.strptime("2026年02月03日 %", "%Y年%m月%d日 %%")) == "2026-02-03 00:00:00"
    assert str(Datetime.strptime("246", "%H%M")) == "1900-01-01 02:46:00"
    assert str(Datetime.strptime("2024-W01-1", "%G-W%V-%u")) == "2024-01-01 00:00:00"


def test_large_ambiguous_numeric_formats_fail_before_parsing():
    literal = "x" * 5000
    with pytest.raises(ValueError, match="datetime parse work limit exceeded"):
        Datetime.strptime("111111111111111111" + literal, "%Y%m%d%H%M%S%f%j%U%w" + literal)
