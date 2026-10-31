"""Locale-independent numeric strptime policy shared with the native VM.

Literal text is preserved. Numeric fields use ASCII digits; repeated directives,
locale-dependent directives, format extensions and incomplete ISO dates fail.
"""

import re
from datetime import datetime

NUMERIC_DIRECTIVES = "YymdHIMSfjUWwuGV"
_WIDTHS = {"Y": "{4}", "G": "{4}", "y": "{2}", "f": "{1,6}", "j": "{1,3}", "w": "{1}", "u": "{1}"}
_ERROR = "unsupported datetime format"
_MAX_PARSE_WORK = 1_000_000
_CHOICES = {"Y": 1, "G": 1, "y": 1, "w": 1, "u": 1, "f": 6, "j": 3}
_WHITESPACE = "\u0009\u000a\u000b\u000c\u000d\u001c\u001d\u001e\u001f\u0020\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
_SPACE_PATTERN = "[" + re.escape(_WHITESPACE) + "]+"


def parse_datetime(text: str, format: str) -> datetime:
    directives = validate_datetime_format(text, format)
    if not directives.intersection({"Y", "y", "G"}):
        # Pin 1900 explicitly rather than inherit Python's changing yearless-date policy.
        text += " 1900"
        format += " %Y"
    return datetime.strptime(text, format)


def validate_datetime_format(text: str, format: str) -> set[str]:
    if not isinstance(text, str) or not isinstance(format, str):
        raise TypeError("datetime.strptime() requires strings")
    directives, pattern = _pattern(format)
    _validate_combinations(directives)
    _validate_work(text, format, directives)
    if re.fullmatch(pattern, text) is None:
        raise ValueError("datetime.strptime() failed")
    return directives


def _validate_work(text: str, format: str, directives: set[str]) -> None:
    branches = 1
    for directive in directives:
        branches *= _CHOICES.get(directive, 2)
    work = (
        len(text.encode("utf-8")) + len(format.encode("utf-8")) + 32 * len(directives) + 1
    ) * branches
    if work > _MAX_PARSE_WORK:
        raise ValueError("datetime parse work limit exceeded")


def _pattern(format: str) -> tuple[set[str], str]:
    directives = set()
    pattern = []
    characters = iter(format)
    for character in characters:
        if character == "%":
            directive = next(characters, "")
            pattern.append(_directive(directive, directives))
        elif character in _WHITESPACE:
            if not pattern or pattern[-1] != _SPACE_PATTERN:
                pattern.append(_SPACE_PATTERN)
        else:
            pattern.append(re.escape(character))
    return directives, "".join(pattern)


def _directive(directive: str, seen: set[str]) -> str:
    if directive == "%":
        return "%"
    if not directive or directive not in NUMERIC_DIRECTIVES or directive in seen:
        raise ValueError(_ERROR)
    seen.add(directive)
    if directive == "d":
        return r"(?:[0-9]{1,2}| [0-9])"
    return "[0-9]" + _WIDTHS.get(directive, "{1,2}")


def _validate_combinations(directives: set[str]) -> None:
    for left, right in [("Y", "y"), ("H", "I"), ("U", "W"), ("w", "u")]:
        if left in directives and right in directives:
            raise ValueError(_ERROR)
    if directives.intersection({"G", "V"}):
        _validate_iso(directives)


def _validate_iso(directives: set[str]) -> None:
    complete = {"G", "V"}.issubset(directives) and directives.intersection({"u", "w"})
    if not complete or directives.intersection("YymdjUW"):
        raise ValueError(_ERROR)
