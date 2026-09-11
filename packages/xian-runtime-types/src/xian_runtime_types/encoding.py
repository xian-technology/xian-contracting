import decimal
import json

from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet
from xian_runtime_types.decimal import ContractingDecimal, fix_precision
from xian_runtime_types.time import Datetime, Timedelta

MIN_INT = -(2**63)
MAX_INT = 2**63 - 1
TYPES = {
    "__fixed__",
    "__delta__",
    "__frozenset__",
    "__bytes__",
    "__bytearray__",
    "__set__",
    "__time__",
    "__big_int__",
}


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
        if isinstance(value, ContractingSet):
            return {"__set__": list(value)}
        if isinstance(value, ContractingFrozenSet):
            return {"__frozenset__": list(value)}
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
    return json.dumps(_encode_ints(data), cls=Encoder, separators=(",", ":"))


def as_object(value):
    if "__time__" in value:
        return Datetime(*value["__time__"])
    if "__delta__" in value:
        return Timedelta(days=value["__delta__"][0], seconds=value["__delta__"][1])
    if "__set__" in value:
        return ContractingSet(value["__set__"])
    if "__frozenset__" in value:
        return ContractingFrozenSet(value["__frozenset__"])
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
        return json.loads(data, object_hook=as_object)
    except json.decoder.JSONDecodeError:
        return None


def encode_kv(key, value):
    return key.encode(), encode(value).encode()


def decode_kv(key, value):
    return key.decode(), decode(value)


def convert(key, value):
    if key == "__fixed__":
        return ContractingDecimal(value)
    if key == "__delta__":
        return Timedelta(days=value[0], seconds=value[1])
    if key == "__set__":
        return ContractingSet(convert_dict(item) for item in value)
    if key == "__frozenset__":
        return ContractingFrozenSet(convert_dict(item) for item in value)
    if key == "__bytes__":
        return bytes.fromhex(value)
    if key == "__bytearray__":
        return bytearray.fromhex(value)
    if key == "__time__":
        return Datetime(*value)
    if key == "__big_int__":
        return int(value)
    return value


def convert_dict(data):
    if isinstance(data, list):
        return [convert_dict(item) for item in data]
    if not isinstance(data, dict):
        return data

    converted = {}
    for key, value in data.items():
        if key in TYPES:
            return convert(key, value)
        converted[key] = convert_dict(value)
    return converted
