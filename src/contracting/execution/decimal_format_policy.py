"""Bounded raw Decimal formatting with the native contract grammar.

Use Python's trusted formatter for the numeric body, with an explicit context.
Neither libmpdec's lazy fallback cache nor the host locale defines admission.
"""

import _pydecimal
from dataclasses import dataclass, replace
from decimal import getcontext

LIMIT = 128 * 1024


def invalid_specification():
    return ValueError("invalid or unsupported format specification")


def allocation_limit():
    return ValueError("formatted output exceeds allocation limit")


@dataclass(frozen=True)
class DecimalSpec:
    fill: str = " "
    align: str = ">"
    sign: str = "-"
    positive_zero: bool = False
    zero: bool = False
    width: int = 0
    grouping: bool = False
    precision: int | None = None
    kind: str = "G"


def _number(text, position):
    start = position
    value = 0
    while position < len(text) and "0" <= text[position] <= "9":
        value = value * 10 + ord(text[position]) - ord("0")
        if value > LIMIT:
            raise allocation_limit()
        position += 1
    return (value if position != start else None), position


def _alignment(text):
    values = {}
    position = 0
    if len(text) > 1 and text[1] in "<>=^":
        values.update(fill=text[0], align=text[1])
        position = 2
    elif text[:1] and text[0] in "<>=^":
        values["align"] = text[0]
        position = 1
    return values, position


def _prefix(text):
    values, position = _alignment(text)
    for name, allowed in [("sign", "+- "), ("positive_zero", "z"), ("zero", "0")]:
        if position < len(text) and text[position] in allowed:
            values[name] = text[position] if name == "sign" else True
            position += 1
    if values.get("zero"):
        values.update(fill="0", align="=")
    return values, position


def _suffix(text, position, values):
    if text[position : position + 1] == ",":
        values["grouping"] = True
        position += 1
    if text[position : position + 1] == ".":
        precision, position = _number(text, position + 1)
        if precision is None:
            raise invalid_specification()
        values["precision"] = precision
    _kind(text[position:], values)


def _kind(tail, values):
    if tail and (len(tail) != 1 or tail not in "eEfFgGn%"):
        raise invalid_specification()
    values["kind"] = tail or "G"
    if values["kind"] == "n" and values.get("grouping"):
        raise invalid_specification()


def parse_decimal_specification(text):
    if not isinstance(text, str):
        raise TypeError("format specification must be a string")
    if len(text) > LIMIT or len(text.encode("utf-8")) > LIMIT:
        raise allocation_limit()
    values, position = _prefix(text)
    width, position = _number(text, position)
    values["width"] = width or 0
    _suffix(text, position, values)
    return DecimalSpec(**values)


def _body(value, spec):
    if value.is_finite():
        _bound_body(value, spec)
    # The C and pure-Python Decimal modules have separate ambient contexts.
    # Execution sets the C context explicitly; transfer its formatting options.
    context = getcontext()
    pure_context = _pydecimal.Context(rounding=context.rounding, capitals=context.capitals)
    number = _pydecimal.Decimal(value.as_tuple())
    precision = "" if spec.precision is None else "." + str(spec.precision)
    kind = "g" if spec.kind == "n" else spec.kind
    text = number.__format__(
        spec.sign + ("z" if spec.positive_zero else "") + precision + kind, context=pure_context
    )
    if len(text) > LIMIT:
        raise allocation_limit()
    sign = text[:1] if text[:1] in ("-", "+", " ") else ""
    return sign, text[len(sign) :]


def _bound_body(value, spec):
    exponent = value.as_tuple().exponent
    places = spec.precision if spec.precision is not None else abs(exponent)
    whole = max(value.adjusted(), 0) + 3
    if spec.kind in "fF%" and whole + places > LIMIT:
        raise allocation_limit()
    if spec.precision is not None and spec.precision >= LIMIT - 16:
        raise allocation_limit()
    # General formatting preserves the coefficient; reject oversized input
    # before creating its pure-Python copy or output body.
    if len(value.as_tuple().digits) > LIMIT:
        raise allocation_limit()


def _whole_length(body):
    return next((index for index, ch in enumerate(body) if ch in ".eE%"), len(body))


def _grouped_body(body, sign, spec):
    whole = _whole_length(body)
    zeros = 0
    if spec.align == "=" and spec.fill == "0":
        low, high = 0, spec.width
        while low < high:
            middle = (low + high) // 2
            width = len(sign) + len(body) + middle + (whole + middle - 1) // 3
            if width < spec.width:
                low = middle + 1
            else:
                high = middle
        zeros = low
    grouped_size = len(body) + zeros + (whole + zeros - 1) // 3
    if grouped_size + len(sign) > LIMIT:
        raise allocation_limit()
    integer = "0" * zeros + body[:whole]
    first = len(integer) % 3 or 3
    groups = [integer[:first]]
    groups.extend(integer[index : index + 3] for index in range(first, len(integer), 3))
    return ",".join(groups) + body[whole:]


def _pad(body, sign, spec):
    padding = max(spec.width - len(body) - len(sign), 0)
    if padding * len(spec.fill.encode("utf-8")) + len(body) + len(sign) > LIMIT:
        raise allocation_limit()
    left = spec.fill * (padding // 2 if spec.align == "^" else padding)
    if spec.align == "<":
        return sign + body + left
    if spec.align == "=":
        return sign + left + body
    if spec.align == "^":
        return left + sign + body + spec.fill * (padding - padding // 2)
    return left + sign + body


def format_decimal(value, specification):
    spec = parse_decimal_specification(specification)
    if not value.is_finite() and spec.zero:
        spec = replace(spec, fill=" ", align=">")
    sign, body = _body(value, spec)
    if spec.grouping and value.is_finite():
        body = _grouped_body(body, sign, spec)
    return _pad(body, sign, spec)
