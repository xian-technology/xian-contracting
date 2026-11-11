"""Exact numeric interchange for the fresh-genesis VM profile."""

from decimal import Decimal

from .decimal import ContractingDecimal, canonical_fixed
from .set_codec import (
    RESERVED_TAGS,
    _NormalizationBudget,
    _validate_serializable_value,
    decode_set_value,
    encode_set_value,
    is_wrapper_set,
)
from .time import Datetime, Timedelta

SAFE_INTEGER = 2**53 - 1
MAX_INTEGER_BITS = 512


def _check_int(number):
    if number.bit_length() > MAX_INTEGER_BITS:
        raise ValueError("integer exceeds 512 bits")
    return number


def _tagged_integer(text):
    if not isinstance(text, str) or not 1 <= len(text) <= 156:
        raise ValueError("invalid __big_int__ decimal string")
    try:
        number = _check_int(int(text))
    except ValueError as exc:
        raise ValueError("invalid __big_int__ decimal string") from exc
    if str(number) != text or abs(number) <= SAFE_INTEGER:
        raise ValueError("noncanonical __big_int__")
    return number


def _check_set_node(node):
    # The set codec first checks the closed grammar and enforces depth/work limits.
    tag = node[0]
    if tag in ("tuple", "frozenset"):
        for child in node[1]:
            _check_set_node(child)
    elif tag in ("raw_decimal", "float"):
        raise ValueError("V2 set members cannot contain binary float or raw Decimal")
    elif tag == "int":
        if len(node[1]) > 156:
            raise ValueError("integer exceeds 512 bits")
        _check_int(int(node[1]))


def _fixed_payload(payload):
    if not isinstance(payload, str) or len(payload) > 93 or canonical_fixed(payload) != payload:
        raise ValueError("noncanonical __fixed__ decimal string")
    return ContractingDecimal(payload)


def _decode_tag(tag, payload, budget):
    from .encoding import as_object

    if tag == "__fixed__":
        return _fixed_payload(payload)
    if tag == "__big_int__":
        return _tagged_integer(payload)
    if tag in ("__set__", "__frozenset__"):
        if not isinstance(payload, dict):
            raise ValueError("V2 set requires a typed member envelope")
        decoded = decode_set_value(tag, payload, _normalization=budget, exact_numbers=True)
        for node in payload["items"]:
            _check_set_node(node)
        return decoded
    if isinstance(payload, list) and not all(
        type(x) is int and abs(x) <= SAFE_INTEGER for x in payload
    ):
        raise ValueError("invalid numeric value in runtime wrapper")
    return as_object({tag: payload})


def _integer(number, decoding):
    _check_int(number)
    if abs(number) <= SAFE_INTEGER:
        return number
    if decoding:
        raise ValueError("large JSON integer requires __big_int__")
    return {"__big_int__": str(number)}


def _numbers(value, decoding, budget):
    if isinstance(value, dict):
        tags = value.keys() & RESERVED_TAGS
        if tags:
            if len(value) != 1:
                raise ValueError("runtime wrapper must contain a single key")
            tag = next(iter(tags))
            decoded = _decode_tag(tag, value[tag], budget)
            return decoded if decoding else value
        return {key: _numbers(item, decoding, budget) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_numbers(item, decoding, budget) for item in value]
    if type(value) is int:
        return _integer(value, decoding)
    if isinstance(value, float):
        raise TypeError("binary float is not a contract number")
    if isinstance(value, (ContractingDecimal, Decimal)):
        if decoding:
            raise TypeError("expected JSON decimal wrapper")
        return {"__fixed__": canonical_fixed(value)}
    if is_wrapper_set(value):
        return _numbers(encode_set_value(value), decoding, budget)
    if isinstance(value, (bytes, bytearray, Datetime, Timedelta)):
        from .encoding import Encoder

        return _numbers(Encoder().default(value), decoding, budget)
    return value


def _process(value, *, decoding):
    _validate_serializable_value(value, allow_codec_tags=True)
    return _numbers(value, decoding, _NormalizationBudget())


def normalize_wire_numbers(value):
    """Encode exact typed numbers and validate already-tagged JSON recursively."""
    return _process(value, decoding=False)


def decode_wire_numbers(value):
    """Decode a JSON tree only if its numeric wrappers are canonical."""
    return _process(value, decoding=True)
