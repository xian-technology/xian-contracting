import decimal
import json

from xian_runtime_types.decimal import ContractingDecimal, fix_precision
from xian_runtime_types.set_codec import (
    RESERVED_TAGS,
    _NormalizationBudget,
    decode_set_value,
    encode_set_value,
    is_wrapper_set,
    validate_persistent_value,
)
from xian_runtime_types.time import Datetime, Timedelta

MIN_INT = -(2**63)
MAX_INT = 2**63 - 1
TYPES = set(RESERVED_TAGS)


def safe_repr(obj, max_len=1024):
    try:
        raw = obj.__repr__()
        parts = raw.split(" at 0x")
        if len(parts) > 1:
            return parts[0] + ">"
        return parts[0][:max_len]
    except Exception:
        return None


class Encoder(json.JSONEncoder):
    def iterencode(self, value, _one_shot=False):
        validate_persistent_value(value)
        return super().iterencode(value, _one_shot)

    def default(self, value, *args):
        if isinstance(value, Datetime) or value.__class__.__name__ == Datetime.__name__:
            return {
                "__time__": [
                    value.year,
                    value.month,
                    value.day,
                    value.hour,
                    value.minute,
                    value.second,
                    value.microsecond,
                ]
            }
        if isinstance(value, Timedelta) or value.__class__.__name__ == Timedelta.__name__:
            return {
                "__delta__": [
                    value._timedelta.days,
                    value._timedelta.seconds,
                ]
            }
        if is_wrapper_set(value):
            return encode_set_value(value)
        if isinstance(value, bytes):
            return {"__bytes__": value.hex()}
        if isinstance(value, bytearray):
            return {"__bytearray__": value.hex()}
        if (
            isinstance(value, decimal.Decimal)
            or value.__class__.__name__ == decimal.Decimal.__name__
        ):
            return {"__fixed__": str(fix_precision(value))}
        if (
            isinstance(value, ContractingDecimal)
            or value.__class__.__name__ == ContractingDecimal.__name__
        ):
            return {"__fixed__": str(fix_precision(value._d))}
        return super().default(value)


def encode_int(value: int):
    if MIN_INT < value < MAX_INT:
        return value
    return {"__big_int__": str(value)}


def encode_ints_in_dict(data: dict):
    return {key: _encode_ints(value) for key, value in data.items()}


def _encode_ints(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return encode_int(value)
    if isinstance(value, dict):
        return encode_ints_in_dict(value)
    if isinstance(value, list):
        return [_encode_ints(item) for item in value]
    return value


def encode(data):
    validate_persistent_value(data)
    encoder = Encoder(separators=(",", ":"))
    # Generated bigint tags are trusted codec output, not caller dictionaries.
    return "".join(json.JSONEncoder.iterencode(encoder, _encode_ints(data), _one_shot=True))


def as_object(value, *, _normalization=None):
    if "__time__" in value:
        return Datetime(*value["__time__"])
    if "__delta__" in value:
        return Timedelta(days=value["__delta__"][0], seconds=value["__delta__"][1])
    if "__set__" in value:
        return decode_set_value("__set__", value["__set__"], _normalization=_normalization)
    if "__frozenset__" in value:
        return decode_set_value(
            "__frozenset__", value["__frozenset__"], _normalization=_normalization
        )
    if "__bytes__" in value:
        return bytes.fromhex(value["__bytes__"])
    if "__bytearray__" in value:
        return bytearray.fromhex(value["__bytearray__"])
    if "__fixed__" in value:
        return ContractingDecimal(value["__fixed__"])
    if "__big_int__" in value:
        return int(value["__big_int__"])
    return dict(value)


def decode(data):
    if data is None:
        return None
    if isinstance(data, bytes):
        data = data.decode()
    try:
        normalization = _NormalizationBudget()
        return json.loads(
            data, object_hook=lambda value: as_object(value, _normalization=normalization)
        )
    except json.decoder.JSONDecodeError:
        return None


def encode_kv(key, value):
    return key.encode(), encode(value).encode()


def decode_kv(key, value):
    return key.decode(), decode(value)


def convert(key, value, *, _normalization=None):
    if _normalization is None:
        _normalization = _NormalizationBudget()
    if key == "__fixed__":
        return ContractingDecimal(value)
    if key == "__delta__":
        return Timedelta(days=value[0], seconds=value[1])
    if key == "__set__":
        return decode_set_value(
            key,
            [convert_dict(item, _normalization=_normalization) for item in value]
            if isinstance(value, list)
            else value,
            _normalization=_normalization,
        )
    if key == "__frozenset__":
        return decode_set_value(
            key,
            [convert_dict(item, _normalization=_normalization) for item in value]
            if isinstance(value, list)
            else value,
            _normalization=_normalization,
        )
    if key == "__bytes__":
        return bytes.fromhex(value)
    if key == "__bytearray__":
        return bytearray.fromhex(value)
    if key == "__time__":
        return Datetime(*value)
    if key == "__big_int__":
        return int(value)
    return value


def convert_dict(data, *, _normalization=None):
    if _normalization is None:
        _normalization = _NormalizationBudget()
    if isinstance(data, list):
        return [convert_dict(item, _normalization=_normalization) for item in data]
    if not isinstance(data, dict):
        return data

    converted = {}
    for key, value in data.items():
        if key in TYPES:
            return convert(key, value, _normalization=_normalization)
        converted[key] = convert_dict(value, _normalization=_normalization)
    return converted
