"""Versioned, bounded member grammar for persistent deterministic wrapper sets."""

import json
import math
import re
import struct
from decimal import Decimal

from .collections import ContractingFrozenSet, ContractingSet
from .decimal import ContractingDecimal
from .time import Datetime, Timedelta

SET_CODEC = "xian-set-1"
MAX_SET_DEPTH = 64
MAX_SET_NODES = 131072
MAX_SET_BYTES = 8 * 1024 * 1024
MAX_NORMALIZATION_WORK = 8388608
MAX_INTEGER_BITS = 1048576
MAX_RAW_DIGITS = 131072
MAX_RAW_EXPONENT = 131072
RESERVED_TAGS = frozenset(
    {
        "__fixed__",
        "__delta__",
        "__frozenset__",
        "__bytes__",
        "__bytearray__",
        "__set__",
        "__time__",
        "__big_int__",
    }
)
_INTEGER = re.compile(r"(?:0|-[1-9][0-9]*|[1-9][0-9]*)\Z", re.ASCII)
_HEX = re.compile(r"(?:[0-9a-f]{2})*\Z", re.ASCII)


def is_wrapper_set(value):
    return isinstance(value, (ContractingSet, ContractingFrozenSet))


def _json_string_size(value):
    size = 2
    for character in value:
        code = ord(character)
        if 0xD800 <= code <= 0xDFFF:
            raise ValueError("set codec rejects non-scalar Unicode")
        if character in '\\"\b\f\n\r\t':
            size += 2
        elif code < 32:
            size += 6
        else:
            size += 1 if code < 128 else 6 if code < 65536 else 12
        if size > MAX_SET_BYTES:
            raise ValueError("set codec encoded byte limit exceeded")
    return size


class _NormalizationBudget:
    def __init__(self):
        self.work = 0

    def add(self, work):
        self.work += work
        if self.work > MAX_NORMALIZATION_WORK:
            raise ValueError("set codec aggregate normalization work limit exceeded")


class _Budget:
    def __init__(self, normalization=None):
        self.nodes = 0
        self.bytes = 0
        self.normalization_work = 0
        self.normalization = normalization

    def add(self, size):
        self.bytes += size
        if self.bytes > MAX_SET_BYTES:
            raise ValueError("set codec encoded byte limit exceeded")

    def visit(self, depth):
        self.nodes += 1
        if depth > MAX_SET_DEPTH or self.nodes > MAX_SET_NODES:
            raise ValueError("set codec depth or node limit exceeded")

    def normalize(self, length):
        if self.normalization is not None:
            self.normalization.add(length * length)
        self.normalization_work += length * length
        if self.normalization_work > MAX_NORMALIZATION_WORK:
            raise ValueError("set codec normalization work limit exceeded")

    def scalar(self, node):
        # Strings are measured before JSON allocation; scalars are otherwise small.
        size = 2 + max(0, len(node) - 1)
        for value in node:
            size += (
                _json_string_size(value)
                if isinstance(value, str)
                else len(json.dumps(value, separators=(",", ":")))
            )
        self.add(size)
        return node

    def container(self, tag, length):
        if length > MAX_SET_NODES:
            raise ValueError("set codec node limit exceeded")
        self.add(5 + _json_string_size(tag) + max(0, length - 1))


def _integer_text(value):
    if value.bit_length() > MAX_INTEGER_BITS:
        raise ValueError("set codec integer bit limit exceeded")
    # Decimal's exact integer conversion avoids Python's process-global str(int) cap.
    return str(Decimal(value))


def _parse_integer(text):
    if not isinstance(text, str) or len(text) > 315654 or not _INTEGER.fullmatch(text):
        raise ValueError("invalid canonical set integer")
    value = int(Decimal(text))
    if value.bit_length() > MAX_INTEGER_BITS:
        raise ValueError("set codec integer bit limit exceeded")
    return value


def _raw_parts(value):
    if not value.is_finite():
        raise ValueError("set codec requires finite numeric members")
    if len(str(value)) > MAX_RAW_DIGITS:
        raise ValueError("set codec raw decimal text limit exceeded")
    parts = value.as_tuple()
    if len(parts.digits) > MAX_RAW_DIGITS or abs(parts.exponent) > MAX_RAW_EXPONENT:
        raise ValueError("set codec raw decimal limit exceeded")
    return parts.sign, "".join(map(str, parts.digits)), parts.exponent


def _encode_member(value, budget, depth, exact_numbers):
    budget.visit(depth)
    if value is None:
        return budget.scalar(["none"])
    if type(value) is bool:
        return budget.scalar(["bool", value])
    if type(value) is int:
        if exact_numbers:
            from .numeric_wire import _check_int

            _check_int(value)
        return budget.scalar(["int", _integer_text(value)])
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("set codec requires finite numeric members")
        if exact_numbers:
            raise ValueError("V2 set members cannot contain binary float")
        return budget.scalar(["float", struct.pack(">d", value).hex()])
    if isinstance(value, ContractingDecimal):
        return budget.scalar(["fixed", _integer_text(value._scaled)])
    if isinstance(value, Decimal):
        if exact_numbers:
            raise ValueError("V2 set members cannot contain raw Decimal")
        return budget.scalar(["raw_decimal", *_raw_parts(value)])
    if isinstance(value, str):
        return budget.scalar(["str", value])
    if isinstance(value, bytes):
        if len(value) * 2 > MAX_SET_BYTES:
            raise ValueError("set codec encoded byte limit exceeded")
        return budget.scalar(["bytes", value.hex()])
    if isinstance(value, Datetime):
        parts = [
            value.year,
            value.month,
            value.day,
            value.hour,
            value.minute,
            value.second,
            value.microsecond,
        ]
        return budget.scalar(["datetime", parts])
    if isinstance(value, Timedelta):
        return budget.scalar(["timedelta", _integer_text(value.seconds)])
    if isinstance(value, (tuple, ContractingFrozenSet)):
        tag = "tuple" if isinstance(value, tuple) else "frozenset"
        budget.container(tag, len(value))
        if tag == "frozenset":
            budget.normalize(len(value))
        return [tag, [_encode_member(item, budget, depth + 1, exact_numbers) for item in value]]
    raise TypeError("unsupported set member: " + type(value).__name__)


def encode_set_value(value, *, _normalization=None, exact_numbers=True):
    if not is_wrapper_set(value):
        raise TypeError("expected deterministic wrapper set")
    tag = "__set__" if isinstance(value, ContractingSet) else "__frozenset__"
    budget = _Budget(_normalization)
    budget.add(len(json.dumps({tag: {"codec": SET_CODEC, "items": []}}, separators=(",", ":"))))
    if len(value) > MAX_SET_NODES:
        raise ValueError("set codec node limit exceeded")
    budget.normalize(len(value))
    budget.add(max(0, len(value) - 1))
    items = [_encode_member(item, budget, 1, exact_numbers) for item in value]
    return {tag: {"codec": SET_CODEC, "items": items}}


def _node(node, lengths):
    if not isinstance(node, list) or len(node) not in lengths or not isinstance(node[0], str):
        raise ValueError("malformed typed set member")
    return node[0]


def _decode_scalar(node):
    tag = node[0]
    value = node[1] if len(node) > 1 else None
    if tag == "none" and len(node) == 1:
        return None
    if tag == "bool" and type(value) is bool:
        return value
    if tag in ("int", "fixed", "timedelta"):
        number = _parse_integer(value)
        if tag == "fixed":
            return ContractingDecimal._from_scaled(number)
        if tag == "timedelta":
            return Timedelta(seconds=number)
        return number
    if tag == "str" and isinstance(value, str):
        return value
    if tag in ("float", "bytes") and isinstance(value, str) and _HEX.fullmatch(value):
        if tag == "bytes":
            return bytes.fromhex(value)
        if len(value) == 16:
            number = struct.unpack(">d", bytes.fromhex(value))[0]
            if math.isfinite(number):
                return number
            raise ValueError("set codec requires finite numeric members")
    if (
        tag == "datetime"
        and isinstance(value, list)
        and len(value) == 7
        and all(type(item) is int for item in value)
    ):
        return Datetime(*value)
    raise ValueError("invalid typed set member payload")


def _decode_raw(node):
    _, sign, digits, exponent = node
    if type(sign) is not int or sign not in (0, 1) or type(exponent) is not int:
        raise ValueError("invalid raw decimal tuple")
    if not isinstance(digits, str) or not digits or len(digits) > MAX_RAW_DIGITS:
        raise ValueError("set codec raw decimal limit exceeded")
    if (
        not digits.isascii()
        or not digits.isdigit()
        or (len(digits) > 1 and digits[0] == "0")
        or abs(exponent) > MAX_RAW_EXPONENT
    ):
        raise ValueError("invalid canonical raw decimal tuple")
    return Decimal((sign, tuple(map(int, digits)), exponent))


def _decode_member(node, budget, depth, exact_numbers):
    budget.visit(depth)
    tag = _node(node, (1, 2, 4))
    if exact_numbers and tag in ("raw_decimal", "float"):
        raise ValueError("V2 set members cannot contain binary float or raw Decimal")
    if (
        exact_numbers
        and tag == "int"
        and len(node) == 2
        and isinstance(node[1], str)
        and len(node[1]) > 156
    ):
        raise ValueError("integer exceeds 512 bits")
    if tag in ("tuple", "frozenset") and len(node) == 2 and isinstance(node[1], list):
        budget.container(tag, len(node[1]))
        if tag == "frozenset":
            budget.normalize(len(node[1]))
        children = [_decode_member(item, budget, depth + 1, exact_numbers) for item in node[1]]
        if tag == "tuple":
            return tuple(children)
        return (
            ContractingFrozenSet._from_v2_members(children)
            if exact_numbers
            else ContractingFrozenSet(children)
        )
    if tag == "raw_decimal" and len(node) == 4:
        result = _decode_raw(node)
        budget.scalar(node)
        return result
    if (tag == "none" and len(node) != 1) or (tag != "none" and len(node) != 2):
        raise ValueError("invalid typed set member arity")
    if tag == "none":
        budget.scalar(node)
        return None
    payload = node[1]
    if tag == "bool":
        valid = type(payload) is bool
    elif tag == "datetime":
        valid = (
            isinstance(payload, list)
            and len(payload) == 7
            and all(type(item) is int and abs(item) <= 999999 for item in payload)
        )
    else:
        valid = tag in {"int", "fixed", "timedelta", "str", "bytes", "float"} and isinstance(
            payload, str
        )
    if not valid:
        raise ValueError("invalid typed set member payload")
    budget.scalar(node)
    return _decode_scalar(node)


def _legacy_member(value, budget, depth):
    budget.visit(depth)
    if isinstance(value, list):
        return tuple(_legacy_member(item, budget, depth + 1) for item in value)
    return value


def decode_set_value(tag, payload, *, _normalization=None, exact_numbers=True):
    if tag not in ("__set__", "__frozenset__"):
        raise ValueError("invalid wrapper set tag")
    wrapper = ContractingSet if tag == "__set__" else ContractingFrozenSet
    budget = _Budget(_normalization)
    if isinstance(payload, list):
        if exact_numbers:
            raise ValueError("V2 set requires a typed member envelope")
        budget.normalize(len(payload))
        value = wrapper(_legacy_member(item, budget, 1) for item in payload)
        encode_set_value(
            value, exact_numbers=False
        )  # Apply the same finite/member/resource boundary.
        return value
    if (
        not isinstance(payload, dict)
        or set(payload) != {"codec", "items"}
        or payload["codec"] != SET_CODEC
    ):
        raise ValueError("unsupported or malformed set codec envelope")
    items = payload["items"]
    if not isinstance(items, list) or len(items) > MAX_SET_NODES:
        raise ValueError("invalid set codec items")
    budget.add(
        len(json.dumps({tag: {"codec": SET_CODEC, "items": []}}, separators=(",", ":")))
        + max(0, len(items) - 1)
    )
    budget.normalize(len(items))
    construct = wrapper._from_v2_members if exact_numbers else wrapper
    value = construct(_decode_member(item, budget, 1, exact_numbers) for item in items)
    # Reject noncanonical order/duplicates and numeric representatives.
    if encode_set_value(value, exact_numbers=exact_numbers)[tag] != payload:
        raise ValueError("noncanonical set codec members")
    return value


def _validate_serializable_value(value, *, allow_codec_tags, exact_numbers=True):
    active = set()
    count = 0
    normalization = _NormalizationBudget()

    def visit(item, depth):
        nonlocal count
        count += 1
        if depth > 128 or count > 1024 * 1024:
            raise ValueError("persistent value traversal limit exceeded")
        if is_wrapper_set(item):
            encode_set_value(item, _normalization=normalization, exact_numbers=exact_numbers)
            return
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("persistent values require finite numbers")
        if isinstance(item, Decimal) and not item.is_finite():
            raise ValueError("persistent values require finite numbers")
        if exact_numbers and allow_codec_tags and isinstance(item, dict) and len(item) == 1:
            # The typed set decoder bounds member depth, bytes and aggregate work.
            # Its envelope uses several JSON layers per logical tuple.
            if next(iter(item)) in ("__set__", "__frozenset__"):
                return
        if isinstance(item, (dict, list, tuple)):
            identity = id(item)
            if identity in active:
                raise ValueError("cyclic persistent value")
            active.add(identity)
            if isinstance(item, dict):
                for key, child in item.items():
                    if (exact_numbers or allow_codec_tags) and not isinstance(key, str):
                        raise TypeError("wire JSON object keys must be strings")
                    if not allow_codec_tags and isinstance(key, str) and key in RESERVED_TAGS:
                        raise ValueError("reserved runtime codec dictionary key: " + key)
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
            active.remove(identity)
        elif item is not None and not isinstance(
            item,
            (
                bool,
                int,
                float,
                str,
                bytes,
                bytearray,
                Decimal,
                ContractingDecimal,
                Datetime,
                Timedelta,
            ),
        ):
            raise TypeError("unsupported persistent value: " + type(item).__name__)

    visit(value, 0)


def validate_persistent_value(value, *, vm_profile="xian_vm_v2"):
    """Reject invalid numbers, reserved wire tags and unsupported storage values."""
    from .encoding import _exact_profile
    from .numeric_wire import _persistent_numbers

    if _exact_profile(vm_profile):
        _persistent_numbers(value)
    else:
        _validate_serializable_value(value, allow_codec_tags=False, exact_numbers=False)
