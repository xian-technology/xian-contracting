import decimal
from decimal import ROUND_DOWN, Context, Decimal, InvalidOperation

MAX_UPPER_PRECISION = 61
MAX_LOWER_PRECISION = 30

CONTEXT = Context(
    prec=MAX_UPPER_PRECISION + MAX_LOWER_PRECISION,
    rounding=ROUND_DOWN,
    Emin=-100,
    Emax=100,
)
decimal.setcontext(CONTEXT)


def make_min_decimal_str(prec):
    return "0." + "0" * (prec - 1) + "1"


def make_max_decimal_str(upper_prec, lower_prec=0):
    whole = "9" * upper_prec
    if lower_prec <= 0:
        return whole
    return f"{whole}.{'9' * lower_prec}"


def neg_sci_not(s: str):
    try:
        base, exp = s.split("e-")
        if float(base) > 9:
            return s

        base = base.replace(".", "")
        numbers = ("0" * (int(exp) - 1)) + base

        if int(exp) > 0:
            numbers = "0." + numbers

        return numbers
    except ValueError:
        return s


MAX_DECIMAL = Decimal(
    make_max_decimal_str(MAX_UPPER_PRECISION, MAX_LOWER_PRECISION)
)
MIN_DECIMAL = Decimal(make_min_decimal_str(MAX_LOWER_PRECISION))


class DecimalOverflowError(OverflowError):
    pass


def fix_precision(x: Decimal):
    try:
        quantized = x.quantize(MIN_DECIMAL, rounding=ROUND_DOWN).normalize()
    except InvalidOperation as exc:
        raise DecimalOverflowError(
            f"Value {x} exceeds the supported decimal range."
        ) from exc
    if quantized == 0:
        return Decimal("0")
    if quantized > MAX_DECIMAL or quantized < -MAX_DECIMAL:
        raise DecimalOverflowError(
            f"Value {x} exceeds the supported decimal range."
        )
    return quantized


class ContractingDecimal:
    def _get_other(self, other):
        if isinstance(other, ContractingDecimal):
            return other._d
        elif isinstance(other, (float, int)):
            return fix_precision(Decimal(neg_sci_not(str(other))))
        return other

    def __init__(self, a):
        if isinstance(a, (float, int)):
            self._d = Decimal(neg_sci_not(str(a)))
        elif isinstance(a, str):
            self._d = Decimal(neg_sci_not(a))
        elif isinstance(a, Decimal):
            self._d = a
        else:
            self._d = Decimal(a)

        self._d = fix_precision(self._d)

    def __bool__(self):
        return self._d != 0

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
        return ContractingDecimal(-self._d)

    def __pos__(self):
        return self

    def __abs__(self):
        return ContractingDecimal(abs(self._d))

    def __add__(self, other):
        return ContractingDecimal(
            fix_precision(self._d + self._get_other(other))
        )

    def __radd__(self, other):
        return ContractingDecimal(
            fix_precision(self._get_other(other) + self._d)
        )

    def __sub__(self, other):
        return ContractingDecimal(
            fix_precision(self._d - self._get_other(other))
        )

    def __rsub__(self, other):
        return ContractingDecimal(
            fix_precision(self._get_other(other) - self._d)
        )

    def __mul__(self, other):
        return ContractingDecimal(
            fix_precision(self._d * self._get_other(other))
        )

    def __rmul__(self, other):
        return ContractingDecimal(
            fix_precision(self._get_other(other) * self._d)
        )

    def __truediv__(self, other):
        return ContractingDecimal(
            fix_precision(self._d / self._get_other(other))
        )

    def __rtruediv__(self, other):
        return ContractingDecimal(
            fix_precision(self._get_other(other) / self._d)
        )

    def __mod__(self, other):
        return ContractingDecimal(
            fix_precision(self._d % self._get_other(other))
        )

    def __rmod__(self, other):
        return ContractingDecimal(
            fix_precision(self._get_other(other) % self._d)
        )

    def __floordiv__(self, other):
        return ContractingDecimal(
            fix_precision(self._d // self._get_other(other))
        )

    def __rfloordiv__(self, other):
        return ContractingDecimal(
            fix_precision(self._get_other(other) // self._d)
        )

    def __pow__(self, other):
        return ContractingDecimal(
            fix_precision(self._d ** self._get_other(other))
        )

    def __rpow__(self, other):
        return ContractingDecimal(
            fix_precision(self._get_other(other) ** self._d)
        )

    def __int__(self):
        return int(self._d)

    def __float__(self):
        return float(self._d)

    def __round__(self, n=None):
        return round(self._d, n)


exports = {"decimal": ContractingDecimal}
