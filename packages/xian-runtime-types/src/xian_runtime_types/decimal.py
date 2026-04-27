import math
from decimal import (
    ROUND_DOWN,
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
)

MAX_UPPER_PRECISION = 61
MAX_LOWER_PRECISION = 30
MAX_SCALED_DIGITS = MAX_UPPER_PRECISION + MAX_LOWER_PRECISION
SCALE = 10**MAX_LOWER_PRECISION
MAX_SCALED = 10**MAX_SCALED_DIGITS - 1

CONTEXT = Context(
    prec=MAX_SCALED_DIGITS,
    rounding=ROUND_DOWN,
    Emin=-100,
    Emax=100,
)


def make_min_decimal_str(prec):
    return "0." + "0" * (prec - 1) + "1"


def make_max_decimal_str(upper_prec, lower_prec=0):
    whole = "9" * upper_prec
    if lower_prec <= 0:
        return whole
    return f"{whole}.{'9' * lower_prec}"


MAX_DECIMAL = Decimal(
    make_max_decimal_str(MAX_UPPER_PRECISION, MAX_LOWER_PRECISION)
)
MIN_DECIMAL = Decimal(make_min_decimal_str(MAX_LOWER_PRECISION))


class DecimalOverflowError(OverflowError):
    pass


def _coerce_decimal(value) -> Decimal:
    if isinstance(value, Decimal):
        return value
    if isinstance(value, ContractingDecimal):
        return value._d
    if isinstance(value, bool):
        return Decimal(str(value))
    if isinstance(value, (float, int)):
        return Decimal(str(value))
    return Decimal(value)


def _div_trunc(numerator: int, denominator: int) -> int:
    if denominator == 0:
        raise DivisionByZero
    quotient = abs(numerator) // abs(denominator)
    if (numerator < 0) ^ (denominator < 0):
        return -quotient
    return quotient


def _decimal_to_scaled(value: Decimal) -> int:
    if not value.is_finite():
        raise DecimalOverflowError(
            f"Value {value} exceeds the supported decimal range."
        )

    sign, digits, exponent = value.as_tuple()
    if not any(digits):
        return 0
    if value.adjusted() >= MAX_UPPER_PRECISION:
        raise DecimalOverflowError(
            f"Value {value} exceeds the supported decimal range."
        )

    coefficient = "".join(str(digit) for digit in digits)
    shift = exponent + MAX_LOWER_PRECISION
    if shift >= 0:
        scaled = int(coefficient) * (10**shift)
    else:
        keep_digits = len(coefficient) + shift
        if keep_digits <= 0:
            return 0
        scaled = int(coefficient[:keep_digits])
    if sign:
        scaled = -scaled
    return _check_scaled(scaled, value)


def _scaled_to_decimal(scaled: int) -> Decimal:
    if scaled == 0:
        return Decimal("0")

    sign = 1 if scaled < 0 else 0
    digits = tuple(int(digit) for digit in str(abs(scaled)))
    value = Decimal((sign, digits, -MAX_LOWER_PRECISION))
    return value.normalize(context=CONTEXT)


def _check_scaled(scaled: int, source=None) -> int:
    if abs(scaled) > MAX_SCALED:
        value = source if source is not None else f"scaled integer {scaled}"
        raise DecimalOverflowError(
            f"Value {value} exceeds the supported decimal range."
        )
    return 0 if scaled == 0 else scaled


def _coerce_scaled(value) -> int:
    if isinstance(value, ContractingDecimal):
        return value._scaled
    return _decimal_to_scaled(_coerce_decimal(value))


def fix_precision(x: Decimal):
    try:
        scaled = _decimal_to_scaled(_coerce_decimal(x))
        return _scaled_to_decimal(scaled)
    except (InvalidOperation, ValueError) as exc:
        raise DecimalOverflowError(
            f"Value {x} exceeds the supported decimal range."
        ) from exc


class ContractingDecimal:
    __slots__ = ("_scaled", "_d")

    @classmethod
    def _from_scaled(cls, scaled: int):
        scaled = _check_scaled(scaled)
        value = cls.__new__(cls)
        value._scaled = scaled
        value._d = _scaled_to_decimal(scaled)
        return value

    def _get_other(self, other):
        if isinstance(other, ContractingDecimal):
            return other._d
        elif isinstance(other, (float, int)) and not isinstance(other, bool):
            return fix_precision(Decimal(str(other)))
        return other

    def __init__(self, a):
        self._scaled = _coerce_scaled(a)
        self._d = _scaled_to_decimal(self._scaled)

    def __bool__(self):
        return self._scaled != 0

    def __eq__(self, other):
        return self._d == self._get_other(other)

    def __lt__(self, other):
        return self._d < self._get_other(other)

    def __le__(self, other):
        return self._d <= self._get_other(other)

    def __gt__(self, other):
        return self._d > self._get_other(other)

    def __ge__(self, other):
        return self._d >= self._get_other(other)

    def __str__(self):
        return self._d.to_eng_string()

    def __repr__(self):
        return self._d.to_eng_string()

    def __neg__(self):
        return self._from_scaled(-self._scaled)

    def __pos__(self):
        return self

    def __abs__(self):
        return self._from_scaled(abs(self._scaled))

    def __add__(self, other):
        return self._from_scaled(self._scaled + _coerce_scaled(other))

    def __radd__(self, other):
        return self._from_scaled(_coerce_scaled(other) + self._scaled)

    def __sub__(self, other):
        return self._from_scaled(self._scaled - _coerce_scaled(other))

    def __rsub__(self, other):
        return self._from_scaled(_coerce_scaled(other) - self._scaled)

    def __mul__(self, other):
        return self._from_scaled(
            _div_trunc(self._scaled * _coerce_scaled(other), SCALE)
        )

    def __rmul__(self, other):
        return self._from_scaled(
            _div_trunc(_coerce_scaled(other) * self._scaled, SCALE)
        )

    def __truediv__(self, other):
        other_scaled = _coerce_scaled(other)
        return self._from_scaled(_div_trunc(self._scaled * SCALE, other_scaled))

    def __rtruediv__(self, other):
        return self._from_scaled(
            _div_trunc(_coerce_scaled(other) * SCALE, self._scaled)
        )

    def __mod__(self, other):
        other_scaled = _coerce_scaled(other)
        if other_scaled == 0:
            raise DivisionByZero
        quotient = _div_trunc(self._scaled, other_scaled)
        return self._from_scaled(self._scaled - quotient * other_scaled)

    def __rmod__(self, other):
        other_scaled = _coerce_scaled(other)
        if self._scaled == 0:
            raise DivisionByZero
        quotient = _div_trunc(other_scaled, self._scaled)
        return self._from_scaled(other_scaled - quotient * self._scaled)

    def __floordiv__(self, other):
        quotient = _div_trunc(self._scaled, _coerce_scaled(other))
        return self._from_scaled(quotient * SCALE)

    def __rfloordiv__(self, other):
        quotient = _div_trunc(_coerce_scaled(other), self._scaled)
        return self._from_scaled(quotient * SCALE)

    def __pow__(self, other):
        return self._from_scaled(
            _pow_scaled(self._scaled, _coerce_scaled(other))
        )

    def __rpow__(self, other):
        return self._from_scaled(
            _pow_scaled(_coerce_scaled(other), self._scaled)
        )

    def __int__(self):
        return _div_trunc(self._scaled, SCALE)

    def __float__(self):
        return float(str(self))

    def __round__(self, n=None):
        return round(self._d, n)


def _pow_scaled(base_scaled: int, exponent_scaled: int) -> int:
    if exponent_scaled == 0:
        return SCALE
    if exponent_scaled == SCALE // 2:
        if base_scaled < 0:
            raise InvalidOperation
        return math.isqrt(base_scaled * SCALE)
    if exponent_scaled % SCALE != 0:
        raise InvalidOperation

    exponent = exponent_scaled // SCALE
    if exponent < 0:
        if base_scaled == 0:
            raise DecimalOverflowError(
                "Value Infinity exceeds the supported decimal range."
            )
        return _div_trunc(
            SCALE * SCALE, _pow_scaled(base_scaled, -exponent * SCALE)
        )

    result = SCALE
    base = base_scaled
    while exponent:
        if exponent & 1:
            result = _div_trunc(result * base, SCALE)
            _check_scaled(result)
        exponent >>= 1
        if exponent:
            base = _div_trunc(base * base, SCALE)
            _check_scaled(base)
    return _check_scaled(result)


exports = {"decimal": ContractingDecimal}
