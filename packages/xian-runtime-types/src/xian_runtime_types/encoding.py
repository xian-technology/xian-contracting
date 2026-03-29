import decimal
import json

from xian_runtime_types.decimal import ContractingDecimal, fix_precision
from xian_runtime_types.time import Datetime, Timedelta

MIN_INT = -(2**63)
MAX_INT = 2**63 - 1
TYPES = {"__fixed__", "__delta__", "__bytes__", "__time__", "__big_int__"}


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
        if (
            isinstance(value, Datetime)
            or value.__class__.__name__ == Datetime.__name__
        ):
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
        if (
            isinstance(value, Timedelta)
            or value.__class__.__name__ == Timedelta.__name__
        ):
            return {
                "__delta__": [
                    value._timedelta.days,
                    value._timedelta.seconds,
                ]
            }
        if isinstance(value, bytes):
            return {"__bytes__": value.hex()}
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
    encoded = {}
    for key, value in data.items():
        if isinstance(value, int):
            encoded[key] = encode_int(value)
        elif isinstance(value, dict):
            encoded[key] = encode_ints_in_dict(value)
        elif isinstance(value, list):
            encoded[key] = []
            for item in value:
                if isinstance(item, dict):
                    encoded[key].append(encode_ints_in_dict(item))
                elif isinstance(item, int):
                    encoded[key].append(encode_int(item))
                else:
                    encoded[key].append(item)
        else:
            encoded[key] = value
    return encoded


def encode(data):
    if isinstance(data, int):
        data = encode_int(data)
    elif isinstance(data, dict):
        data = encode_ints_in_dict(data)
    return json.dumps(data, cls=Encoder, separators=(",", ":"))


def as_object(value):
    if "__time__" in value:
        return Datetime(*value["__time__"])
    if "__delta__" in value:
        return Timedelta(
            days=value["__delta__"][0], seconds=value["__delta__"][1]
        )
    if "__bytes__" in value:
        return bytes.fromhex(value["__bytes__"])
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
    if key == "__bytes__":
        return bytes.fromhex(value)
    if key == "__time__":
        return Datetime(*value)
    if key == "__big_int__":
        return int(value)
    return value


def convert_dict(data):
    if not isinstance(data, dict):
        return data

    converted = {}
    for key, value in data.items():
        if key in TYPES:
            return convert(key, value)
        if isinstance(value, dict):
            converted[key] = convert_dict(value)
        elif isinstance(value, list):
            converted[key] = [convert_dict(item) for item in value]
        else:
            converted[key] = value
    return converted
