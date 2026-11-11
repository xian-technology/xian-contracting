import decimal
import json

from xian_runtime_types.decimal import ContractingDecimal, canonical_fixed, fix_precision
from xian_runtime_types.numeric_wire import (
    SAFE_INTEGER,
    _persistent_numbers,
    decode_wire_numbers,
    normalize_wire_numbers,
)
from xian_runtime_types.set_codec import (
    RESERVED_TAGS,
    _NormalizationBudget,
    _validate_serializable_value,
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
    def __init__(self, *args, vm_profile="xian_vm_v2", **kwargs):
        super().__init__(*args, **kwargs)
        self._exact_numbers = _exact_profile(vm_profile)

    def iterencode(self, value, _one_shot=False):
        if self._exact_numbers:
            value = _persistent_numbers(value)
        else:
            validate_persistent_value(value, vm_profile="xian_vm_v1")
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
            return encode_set_value(value, exact_numbers=self._exact_numbers)
        if isinstance(value, bytes):
            return {"__bytes__": value.hex()}
        if isinstance(value, bytearray):
            return {"__bytearray__": value.hex()}
        if (
            isinstance(value, decimal.Decimal)
            or value.__class__.__name__ == decimal.Decimal.__name__
        ):
            return {
                "__fixed__": canonical_fixed(value)
                if self._exact_numbers
                else str(fix_precision(value))
            }
        if (
            isinstance(value, ContractingDecimal)
            or value.__class__.__name__ == ContractingDecimal.__name__
        ):
            return {
                "__fixed__": canonical_fixed(value._d)
                if self._exact_numbers
                else str(fix_precision(value._d))
            }
        return super().default(value)


def encode_int(value: int, *, vm_profile="xian_vm_v2"):
    if _exact_profile(vm_profile):
        return normalize_wire_numbers(value)
    return _legacy_int(value)


def _legacy_int(value):
    if MIN_INT < value < MAX_INT:
        return value
    return {"__big_int__": str(value)}


def encode_ints_in_dict(data: dict, *, vm_profile="xian_vm_v2"):
    if _exact_profile(vm_profile):
        return normalize_wire_numbers(data)
    return _legacy_ints(data)


def _legacy_ints(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return _legacy_int(value)
    if isinstance(value, dict):
        return {key: _legacy_ints(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_legacy_ints(item) for item in value]
    return value


def _exact_profile(vm_profile):
    if vm_profile not in ("xian_vm_v1", "xian_vm_v2"):
        raise ValueError(f"unknown VM profile {vm_profile!r}")
    return vm_profile == "xian_vm_v2"


def encode(data, *, vm_profile="xian_vm_v2"):
    if _exact_profile(vm_profile):
        return json.dumps(_persistent_numbers(data), separators=(",", ":"))
    validate_persistent_value(data, vm_profile=vm_profile)
    return _encode_document(data)


def encode_wire(data, *, vm_profile="xian_vm_v2"):
    """Serialize a transaction wire document using the selected numeric rules."""
    if _exact_profile(vm_profile):
        return json.dumps(normalize_wire_numbers(data), separators=(",", ":"))
    _validate_serializable_value(data, allow_codec_tags=True, exact_numbers=False)
    return _encode_document(data)


def _encode_document(data):
    encoder = Encoder(separators=(",", ":"), vm_profile="xian_vm_v1")
    # Generated bigint tags are trusted codec output, not caller dictionaries.
    return "".join(json.JSONEncoder.iterencode(encoder, _legacy_ints(data), _one_shot=True))


def as_object(value, *, vm_profile="xian_vm_v2", _normalization=None):
    """Convert one JSON object hook value. Use decode() to validate a whole document."""
    if _exact_profile(vm_profile):
        return decode_wire_numbers(value) if value.keys() & RESERVED_TAGS else value
    return _legacy_object(value, _normalization=_normalization)


def _legacy_object(value, *, _normalization=None):
    if "__time__" in value:
        return Datetime(*value["__time__"])
    if "__delta__" in value:
        return Timedelta(days=value["__delta__"][0], seconds=value["__delta__"][1])
    if "__set__" in value:
        return decode_set_value(
            "__set__", value["__set__"], _normalization=_normalization, exact_numbers=False
        )
    if "__frozenset__" in value:
        return decode_set_value(
            "__frozenset__",
            value["__frozenset__"],
            _normalization=_normalization,
            exact_numbers=False,
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


def _wire_integer(token):
    if token == "-0" or len(token.lstrip("-")) > 16 or abs(value := int(token)) > SAFE_INTEGER:
        raise ValueError("V2 JSON requires canonical safe integers or __big_int__")
    return value


def _reject_json_fraction(token):
    raise ValueError("V2 fractional JSON numbers require __fixed__")


def loads_wire_json(data):
    """Read V2 JSON without erasing the lexical distinction between -0 and 0.

    Returns the original tagged tree for signature validation and hashing.
    Use decode_wire_numbers on value fields to obtain typed contract arguments.
    """
    return json.loads(
        data,
        parse_int=_wire_integer,
        parse_float=_reject_json_fraction,
        parse_constant=_reject_json_fraction,
    )


def decode(data, *, vm_profile="xian_vm_v2"):
    if data is None:
        return None
    if isinstance(data, bytes):
        data = data.decode()
    if _exact_profile(vm_profile):
        return decode_wire_numbers(loads_wire_json(data))
    try:
        normalization = _NormalizationBudget()
        return json.loads(
            data, object_hook=lambda value: _legacy_object(value, _normalization=normalization)
        )
    except json.decoder.JSONDecodeError:
        return None


def encode_kv(key, value, *, vm_profile="xian_vm_v2"):
    return key.encode(), encode(value, vm_profile=vm_profile).encode()


def decode_kv(key, value, *, vm_profile="xian_vm_v2"):
    return key.decode(), decode(value, vm_profile=vm_profile)


def convert(key, value, *, vm_profile="xian_vm_v2", _normalization=None):
    if _exact_profile(vm_profile):
        return decode_wire_numbers({key: value}) if key in RESERVED_TAGS else value
    return _legacy_convert(key, value, _normalization=_normalization)


def _legacy_convert(key, value, *, _normalization=None):
    if _normalization is None:
        _normalization = _NormalizationBudget()
    if key == "__fixed__":
        return ContractingDecimal(value)
    if key == "__delta__":
        return Timedelta(days=value[0], seconds=value[1])
    if key == "__set__":
        return decode_set_value(
            key,
            [_legacy_tree(item, _normalization=_normalization) for item in value]
            if isinstance(value, list)
            else value,
            _normalization=_normalization,
            exact_numbers=False,
        )
    if key == "__frozenset__":
        return decode_set_value(
            key,
            [_legacy_tree(item, _normalization=_normalization) for item in value]
            if isinstance(value, list)
            else value,
            _normalization=_normalization,
            exact_numbers=False,
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


def convert_dict(data, *, vm_profile="xian_vm_v2", _normalization=None):
    if _exact_profile(vm_profile):
        return decode_wire_numbers(data)
    return _legacy_tree(data, _normalization=_normalization)


def _legacy_tree(data, *, _normalization=None):
    if _normalization is None:
        _normalization = _NormalizationBudget()
    if isinstance(data, list):
        return [_legacy_tree(item, _normalization=_normalization) for item in data]
    if not isinstance(data, dict):
        return data

    converted = {}
    for key, value in data.items():
        if key in TYPES:
            return _legacy_convert(key, value, _normalization=_normalization)
        converted[key] = _legacy_tree(value, _normalization=_normalization)
    return converted
