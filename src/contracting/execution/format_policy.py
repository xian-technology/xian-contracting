"""Trusted, bounded formatting adapters for Python contract execution."""

import _string
import builtins
import re
from decimal import Decimal

from contracting.execution.decimal_format_policy import (
    LIMIT,
    allocation_limit,
    format_decimal,
    invalid_specification,
)

_SCALAR_SPEC = re.compile(
    r"(?:(?P<fill>.)?[<>=^])?[+ -]?z?#?0?(?P<width>[0-9]*)[,_]?"
    r"(?:\.(?P<precision>[0-9]+))?[a-zA-Z%]?\Z",
    re.DOTALL,
)


def _bounded(text):
    if len(text) > LIMIT or len(text.encode("utf-8")) > LIMIT:
        raise allocation_limit()
    return text


def _check_scalar_specification(specification):
    _bounded(specification)
    match = _SCALAR_SPEC.fullmatch(specification)
    if match is None:
        raise invalid_specification()
    for field in ("width", "precision"):
        digits = (match[field] or "").lstrip("0")
        if len(digits) > 6 or int(digits or "0") > LIMIT:
            raise allocation_limit()


def contract_format(value, format_spec="", /):
    if not isinstance(format_spec, str):
        raise TypeError("format specification must be a string")
    if isinstance(value, Decimal):
        return format_decimal(value, format_spec)
    _check_scalar_specification(format_spec)
    return _bounded(builtins.format(value, format_spec))


def _converted(value, conversion):
    if conversion in (None, -1):
        return value
    conversions = {"s": str, "r": repr, "a": ascii, 115: str, 114: repr, 97: ascii}
    try:
        convert = conversions[conversion]
    except KeyError:
        raise ValueError("invalid format conversion") from None
    return convert(value)


def format_fstring(value, format_spec, conversion=-1):
    return contract_format(_converted(value, conversion), format_spec)


class _StringFormatter:
    def __init__(self, arguments, keywords, *, map_only=False):
        self.arguments = arguments
        self.keywords = keywords
        self.map_only = map_only
        self.automatic = None
        self.next_index = 0

    def _root(self, field):
        first, rest = _string.formatter_field_name_split(field)
        if first == "":
            first = self.next_index
            automatic = True
        else:
            automatic = False
        if isinstance(first, int):
            if self.map_only:
                raise ValueError("format_map does not accept positional fields")
            if self.automatic is not None and self.automatic != automatic:
                raise ValueError("cannot mix automatic and manual field numbering")
            self.automatic = automatic
            self.next_index += int(automatic)
            value = self.arguments[first]
        else:
            value = self.keywords[first]
        return value, rest

    def _field(self, field):
        value, selectors = self._root(field)
        for attribute, key in selectors:
            if attribute:
                if key.startswith("_"):
                    raise AttributeError("private attributes are not available to contracts")
                value = getattr(value, key)
            else:
                value = value[key]
        return value

    def render(self, template, depth=0):
        if depth > 2:
            raise ValueError("format specification nesting limit exceeded")
        _bounded(template)
        pieces = []
        length = 0
        for literal, field, specification, conversion in _string.formatter_parser(template):
            length = _append(pieces, literal, length)
            if field is not None:
                value = _converted(self._field(field), conversion)
                specification = self.render(specification, depth + 1)
                length = _append(pieces, contract_format(value, specification), length)
        return "".join(pieces)


def _append(pieces, text, length):
    length += len(text.encode("utf-8"))
    if length > LIMIT:
        raise allocation_limit()
    pieces.append(text)
    return length


class _FormatCallable:
    """Retain original callable identity/equality while guarding invocation."""

    __slots__ = ("_original", "_receiver", "_method", "_unbound")

    def __init__(self, original, receiver, method, *, unbound=False):
        self._original = original
        self._receiver = receiver
        self._method = method
        self._unbound = unbound

    def __eq__(self, other):
        if not isinstance(other, _FormatCallable):
            return NotImplemented
        return self._original == other._original

    def __hash__(self):
        return hash(self._original)

    def __call__(self, /, *arguments, **keywords):
        template = self._receiver
        if self._unbound:
            if not arguments or not isinstance(arguments[0], str):
                raise TypeError("string format method requires a string receiver")
            template, *arguments = arguments
        if self._method == "format_map":
            if len(arguments) != 1 or keywords:
                raise TypeError("format_map expects one positional argument")
            formatter = _StringFormatter((), arguments[0], map_only=True)
        else:
            formatter = _StringFormatter(arguments, keywords)
        return formatter.render(template)


_UNBOUND_FORMATTERS = {
    method: _FormatCallable(getattr(str, method), str, method, unbound=True)
    for method in ("format", "format_map")
}


def format_attribute(receiver, name):
    original = getattr(receiver, name)
    if name not in _UNBOUND_FORMATTERS:
        return original
    if receiver is str:
        return _UNBOUND_FORMATTERS[name]
    if isinstance(receiver, str):
        return _FormatCallable(original, receiver, name)
    return original
