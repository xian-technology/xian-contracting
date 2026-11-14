# Original Xian implementation, written from the Xian VM's decimal rules.
# Copyright (c) 2026 Xian Technology. Licensed under the MIT License.
"""Exact fixed-point decimals with the Xian VM's number model.

A ``ContractingDecimal`` is one integer, ``scaled = value * 10**30``, exactly
as the VM's ``VmDecimal`` is: 30 fractional digits, magnitude below 10**61,
results truncated toward zero, no ambient ``decimal`` context involved.
"""

from __future__ import annotations

import math
import re
from decimal import ROUND_DOWN, Context, Decimal, DivisionByZero, InvalidOperation

MAX_UPPER_PRECISION = 61
MAX_LOWER_PRECISION = 30
MAX_SCALED_DIGITS = MAX_UPPER_PRECISION + MAX_LOWER_PRECISION
SCALE = 10**MAX_LOWER_PRECISION
MAX_SCALED = 10**MAX_SCALED_DIGITS - 1
CONTEXT = Context(prec=MAX_SCALED_DIGITS, rounding=ROUND_DOWN, Emin=-100, Emax=100)

# round(x, n) never needs a unit above 10**156: the VM shares this bound with
# 512-bit ints, and every decimal rounds to zero well before it.
_ROUNDING_DIGITS_CAP = 156
_HALF = SCALE // 2
# canonical_fixed shares the VM's integer bound for integer input.
_INTEGER_BITS = 512
_EXPONENT_DIGITS_CAP = 30
_SPELLING = re.compile(r"([+-]?)(?:([0-9]+)(?:\.([0-9]*))?|\.([0-9]+))([eE][+-]?[0-9]+)?")


def make_min_decimal_str(prec):
    """The smallest positive decimal with ``prec`` fractional digits, as text."""
    return "0." + "1".rjust(max(prec, 1), "0")


def make_max_decimal_str(upper_prec, lower_prec=0):
    """The largest decimal with the given digit counts, as text."""
    fraction = "." + "9" * lower_prec if lower_prec > 0 else ""
    return "9" * upper_prec + fraction


MAX_DECIMAL = Decimal(make_max_decimal_str(MAX_UPPER_PRECISION, MAX_LOWER_PRECISION))
MIN_DECIMAL = Decimal(make_min_decimal_str(MAX_LOWER_PRECISION))


class DecimalOverflowError(OverflowError):
    """A decimal outside the supported range (|value| >= 10**61)."""


def _overflow(source) -> DecimalOverflowError:
    return DecimalOverflowError(f"Value {source} exceeds the supported decimal range.")


def _checked(scaled: int) -> int:
    """A computed scaled result, if it is inside the range."""
    if abs(scaled) > MAX_SCALED:
        raise _overflow(f"scaled integer {scaled}")
    return scaled


def _truncating_div(numerator: int, denominator: int) -> int:
    quotient = abs(numerator) // abs(denominator)
    return quotient if (numerator < 0) == (denominator < 0) else -quotient


def _decimal_to_scaled(value: Decimal) -> int:
    """Truncate an exact ``Decimal`` to the 30-digit grid (``VmDecimal::from_str_literal``)."""
    if not value.is_finite():
        raise _overflow(value)
    sign, digits, exponent = value.as_tuple()
    coefficient = int("".join(map(str, digits)))
    if not coefficient:
        return 0
    if len(digits) + exponent > MAX_UPPER_PRECISION:
        raise _overflow(value)
    shift = exponent + MAX_LOWER_PRECISION
    if shift >= 0:
        magnitude = coefficient * 10**shift
    elif -shift > len(digits):
        magnitude = 0
    else:
        magnitude = coefficient // 10**-shift
    return -magnitude if sign else magnitude


def _int_to_scaled(number: int) -> int:
    if abs(number) > MAX_SCALED // SCALE:
        raise _overflow(Decimal(number))
    return number * SCALE


def _to_scaled(value) -> int:
    """The scaled value of an operand: exact for ints, text for floats and bools."""
    if isinstance(value, ContractingDecimal):
        return value._scaled
    if isinstance(value, (bool, float)):
        value = str(value)
    elif isinstance(value, int):
        return _int_to_scaled(value)
    if not isinstance(value, Decimal):
        value = Decimal(value)
    return _decimal_to_scaled(value)


def _scaled_text(scaled: int) -> str:
    """The VM's text for a decimal: plain digits, no exponent, no trailing zeros."""
    digits = str(abs(scaled)).rjust(MAX_LOWER_PRECISION + 1, "0")
    whole, fraction = digits[:-MAX_LOWER_PRECISION], digits[-MAX_LOWER_PRECISION:].rstrip("0")
    text = f"{whole}.{fraction}" if fraction else whole
    return "-" + text if scaled < 0 else text


def _scaled_decimal(scaled: int) -> Decimal:
    """The value as a normalized ``Decimal`` (``1000`` is ``Decimal('1E+3')``)."""
    if not scaled:
        return Decimal(0)
    digits = str(abs(scaled))
    significant = digits.rstrip("0")
    exponent = len(digits) - len(significant) - MAX_LOWER_PRECISION
    return Decimal((int(scaled < 0), tuple(map(int, significant)), exponent))


def _round_half_even(scaled: int, unit: int) -> int:
    """``scaled / unit`` rounded to the nearest integer, ties to even."""
    quotient, remainder = divmod(abs(scaled), unit)
    if 2 * remainder > unit or (2 * remainder == unit and quotient % 2):
        quotient += 1
    return -quotient if scaled < 0 else quotient


def _nonzero(divisor: int) -> int:
    if not divisor:
        raise DivisionByZero()
    return divisor


def _add(left: int, right: int) -> int:
    return left + right


def _sub(left: int, right: int) -> int:
    return left - right


def _mul(left: int, right: int) -> int:
    return _truncating_div(left * right, SCALE)


def _truediv(left: int, right: int) -> int:
    return _truncating_div(left * SCALE, _nonzero(right))


def _floordiv(left: int, right: int) -> int:
    return _truncating_div(left, _nonzero(right)) * SCALE


def _mod(left: int, right: int) -> int:
    return left - right * _truncating_div(left, _nonzero(right))


def _power(base: int, exponent: int) -> int:
    """``base ** exponent`` for ``exponent >= 0``, squaring with truncating products."""
    result = SCALE
    while exponent:
        if exponent & 1:
            result = _checked(_mul(result, base))
        exponent >>= 1
        if exponent:
            base = _checked(_mul(base, base))
    return result


def _sqrt(base: int) -> int:
    """The square root rounded down, as the VM's ``sqrt`` helper computes it."""
    if base < 0:
        raise InvalidOperation()
    return math.isqrt(base * SCALE)


def _pow(base: int, exponent: int) -> int:
    """Legacy ``**``: integral exponents or one half; a negative one inverts the power."""
    if exponent == _HALF:
        return _sqrt(base)
    if exponent % SCALE:
        raise InvalidOperation()
    exponent //= SCALE
    if exponent >= 0:
        return _power(base, exponent)
    if not base:
        raise _overflow("Infinity")
    return _truncating_div(SCALE * SCALE, _nonzero(_power(base, -exponent)))


def _comparable(other):
    """``other`` on the scaled grid when it is a number compared exactly, else None."""
    if isinstance(other, ContractingDecimal):
        return other._scaled
    if isinstance(other, float):
        return _to_scaled(other)
    if isinstance(other, int) and not isinstance(other, bool):
        return other * SCALE
    return None


def _comparison(compare):
    def method(self, other):
        right = _comparable(other)
        if right is None:
            return compare(self._d, other)
        return compare(self._scaled, right)

    return method


def _arithmetic(name, operation):
    def forward(self, other):
        return type(self)._from_scaled(operation(self._scaled, _to_scaled(other)))

    def reflected(self, other):
        return type(self)._from_scaled(operation(_to_scaled(other), self._scaled))

    for method, dunder in ((forward, f"__{name}__"), (reflected, f"__r{name}__")):
        method.__name__ = dunder
        method.__qualname__ = f"ContractingDecimal.{dunder}"
    return forward, reflected


class ContractingDecimal:
    """A decimal on the VM's 30-digit grid, held as one scaled integer."""

    __slots__ = ("_scaled",)
    __hash__ = None

    def __init__(self, a):
        self._scaled = _to_scaled(a)

    @classmethod
    def _from_scaled(cls, scaled: int):
        value = cls.__new__(cls)
        value._scaled = _checked(scaled)
        return value

    @property
    def _d(self) -> Decimal:
        return _scaled_decimal(self._scaled)

    def __str__(self):
        return _scaled_text(self._scaled)

    __repr__ = __str__

    def __format__(self, spec):
        text = str(self)
        return format(Decimal(text), spec) if spec else text

    def __bool__(self):
        return self._scaled != 0

    def __int__(self):
        return _truncating_div(self._scaled, SCALE)

    def __float__(self):
        return float(str(self))

    def __neg__(self):
        return type(self)._from_scaled(-self._scaled)

    def __pos__(self):
        return type(self)._from_scaled(self._scaled)

    def __abs__(self):
        return type(self)._from_scaled(abs(self._scaled))

    def __round__(self, n=None):
        """``round()`` as a V2 contract rounds: ties to even, exact, context free.

        ``round(x)`` is an int; ``round(x, n)`` a ContractingDecimal (``n`` may
        be negative; past 30 places nothing changes). ``n`` is an int or None
        (a bool is not an int). A result outside the range raises
        ``DecimalOverflowError``.
        """
        if n is None:
            return _round_half_even(self._scaled, SCALE)
        if isinstance(n, bool) or not isinstance(n, int):
            raise TypeError("round() ndigits must be an int or None")
        dropped = MAX_LOWER_PRECISION - n
        if dropped <= 0:
            return type(self)._from_scaled(self._scaled)
        unit = 10 ** min(dropped, _ROUNDING_DIGITS_CAP)
        return type(self)._from_scaled(_round_half_even(self._scaled, unit) * unit)

    __eq__ = _comparison(lambda left, right: left == right)
    __ne__ = _comparison(lambda left, right: left != right)
    __lt__ = _comparison(lambda left, right: left < right)
    __le__ = _comparison(lambda left, right: left <= right)
    __gt__ = _comparison(lambda left, right: left > right)
    __ge__ = _comparison(lambda left, right: left >= right)

    __add__, __radd__ = _arithmetic("add", _add)
    __sub__, __rsub__ = _arithmetic("sub", _sub)
    __mul__, __rmul__ = _arithmetic("mul", _mul)
    __truediv__, __rtruediv__ = _arithmetic("truediv", _truediv)
    __floordiv__, __rfloordiv__ = _arithmetic("floordiv", _floordiv)
    __mod__, __rmod__ = _arithmetic("mod", _mod)
    __pow__, __rpow__ = _arithmetic("pow", _pow)


def fix_precision(x) -> Decimal:
    """``x`` truncated to 30 fractional digits, range checked, as a normalized Decimal.

    Input that is not a number (``"abc"``, a bool, a list) counts as out of range.
    """
    try:
        scaled = _to_scaled(x)
    except (InvalidOperation, ValueError):
        raise _overflow(x) from None
    return _scaled_decimal(scaled)


def canonical_fixed(value: Decimal | str | int | ContractingDecimal) -> str:
    """Canonical, lossless plain-decimal text for a V2 typed value."""
    if isinstance(value, ContractingDecimal):
        return str(value)
    return _scaled_text(_exact_scaled(*_exact_parts(value)))


def _exact_parts(value) -> tuple[bool, str, int]:
    """``(negative, digits, exponent)`` of exact numeric input, without rounding."""
    if isinstance(value, str):
        return _spelled_parts(value)
    if isinstance(value, int) and not isinstance(value, bool):
        if value.bit_length() > _INTEGER_BITS:
            raise OverflowError("integer exceeds 512 bits")
        return value < 0, str(abs(value)), 0
    if not isinstance(value, Decimal):
        raise TypeError("decimal input requires decimal text, an exact decimal or an integer")
    if not value.is_finite():
        raise ValueError("decimal must be finite")
    sign, digits, exponent = value.as_tuple()
    return bool(sign), "".join(map(str, digits)), exponent


def _spelled_parts(text: str) -> tuple[bool, str, int]:
    """Parse the strict wire grammar (``xian_numeric::canonical_decimal``)."""
    match = _SPELLING.fullmatch(text)
    if match is None:
        raise ValueError("invalid decimal spelling")
    sign, whole, fraction, bare_fraction, exponent_text = match.groups()
    fraction = fraction or bare_fraction or ""
    exponent = _clamped_exponent(exponent_text) - len(fraction)
    return sign == "-", (whole or "") + fraction, exponent


def _clamped_exponent(text: str | None) -> int:
    """The exponent of ``e<digits>``; beyond 30 digits only its sign can matter."""
    if not text:
        return 0
    digits = text[1:].lstrip("+-").lstrip("0")
    magnitude = (
        10**_EXPONENT_DIGITS_CAP if len(digits) > _EXPONENT_DIGITS_CAP else int(digits or "0")
    )
    return -magnitude if "-" in text else magnitude


def _exact_scaled(negative: bool, digits: str, exponent: int) -> int:
    """The scaled value of an exact number that must fit the grid without rounding."""
    stripped = digits.rstrip("0")
    exponent += len(digits) - len(stripped)
    significant = stripped.lstrip("0")
    if not significant:
        return 0
    if len(significant) + exponent > MAX_UPPER_PRECISION:
        raise DecimalOverflowError("decimal exceeds the supported range")
    if -exponent > MAX_LOWER_PRECISION:
        raise ValueError("decimal is not exactly representable at scale 30")
    magnitude = int(significant) * 10 ** (exponent + MAX_LOWER_PRECISION)
    return -magnitude if negative else magnitude


exports = {
    "decimal": ContractingDecimal,
}
