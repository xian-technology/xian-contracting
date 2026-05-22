import builtins

from contracting import constants


def _allocation_limit_error(kind: str, limit: int) -> AssertionError:
    return AssertionError(
        f"{kind} exceeds the maximum allowed allocation size of {limit}"
    )


def _ensure_sequence_length(length: int, *, kind: str) -> None:
    if length > constants.MAX_SEQUENCE_LENGTH:
        raise _allocation_limit_error(kind, constants.MAX_SEQUENCE_LENGTH)


def _ensure_binary_size(size: int, *, kind: str) -> None:
    if size > constants.MAX_BINARY_ALLOCATION_BYTES:
        raise _allocation_limit_error(
            kind,
            constants.MAX_BINARY_ALLOCATION_BYTES,
        )


def _integer_limit_error(kind: str) -> AssertionError:
    return AssertionError(
        f"{kind} exceeds the maximum allowed integer size of "
        f"{constants.MAX_INTEGER_BITS} bits"
    )


def _ensure_integer_size(value: int, *, kind: str) -> None:
    if abs(value).bit_length() > constants.MAX_INTEGER_BITS:
        raise _integer_limit_error(kind)


def _ensure_int_string_size(value, *, kind: str) -> None:
    if isinstance(value, str):
        size = len(value)
    elif isinstance(value, (bytes, bytearray)):
        size = len(value)
    else:
        return
    if size > constants.MAX_INT_STRING_CHARS:
        raise AssertionError(
            f"{kind} input exceeds the maximum allowed integer input length of "
            f"{constants.MAX_INT_STRING_CHARS} characters"
        )


def _estimated_mul_bits(left: int, right: int) -> int:
    if left == 0 or right == 0:
        return 0
    return abs(left).bit_length() + abs(right).bit_length()


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _estimated_pow_bits(base: int, exponent: int) -> int:
    if exponent < 0 or base in {-1, 0, 1}:
        return 1
    absolute = abs(base)
    if _is_power_of_two(absolute):
        return ((absolute.bit_length() - 1) * exponent) + 1
    return absolute.bit_length() * exponent


def safe_range(*args):
    values = builtins.range(*args)
    _ensure_sequence_length(len(values), kind="range()")
    return values


class _SafeBytesMeta(type):
    def __call__(cls, *args):
        if len(args) == 1 and isinstance(args[0], int) and args[0] >= 0:
            _ensure_binary_size(args[0], kind="bytes()")
        return builtins.bytes(*args)

    def __instancecheck__(cls, instance):
        return isinstance(instance, builtins.bytes)


class safe_bytes(metaclass=_SafeBytesMeta):
    pass


class _SafeBytearrayMeta(type):
    def __call__(cls, *args):
        if len(args) == 1 and isinstance(args[0], int) and args[0] >= 0:
            _ensure_binary_size(args[0], kind="bytearray()")
        return builtins.bytearray(*args)

    def __instancecheck__(cls, instance):
        return isinstance(instance, builtins.bytearray)


class safe_bytearray(metaclass=_SafeBytearrayMeta):
    pass


class _SafeIntMeta(type):
    def __call__(cls, *args):
        if len(args) > 2:
            return builtins.int(*args)
        if args:
            _ensure_int_string_size(args[0], kind="int()")
        value = builtins.int(*args)
        _ensure_integer_size(value, kind="int()")
        return value

    def __getattr__(cls, name):
        return getattr(builtins.int, name)

    def __instancecheck__(cls, instance):
        return isinstance(instance, builtins.int)

    def __subclasscheck__(cls, subclass):
        return issubclass(subclass, builtins.int)


class safe_int(builtins.int, metaclass=_SafeIntMeta):
    pass


def safe_mul(left, right):
    sequence = None
    count = None
    if isinstance(right, int) and isinstance(
        left,
        (list, tuple, str, bytes, bytearray),
    ):
        sequence = left
        count = right
    elif isinstance(left, int) and isinstance(
        right,
        (list, tuple, str, bytes, bytearray),
    ):
        sequence = right
        count = left

    if sequence is not None and count is not None and count > 0:
        if isinstance(sequence, (list, tuple)):
            _ensure_sequence_length(
                len(sequence) * count,
                kind="sequence repetition",
            )
        elif isinstance(sequence, str):
            _ensure_binary_size(
                len(sequence.encode("utf-8")) * count,
                kind="string repetition",
            )
        else:
            _ensure_binary_size(
                len(sequence) * count,
                kind="binary repetition",
            )
    if isinstance(left, int) and isinstance(right, int):
        if _estimated_mul_bits(left, right) > constants.MAX_INTEGER_BITS + 1:
            raise _integer_limit_error("integer multiplication")
        result = left * right
        _ensure_integer_size(result, kind="integer multiplication")
        return result
    return left * right


def safe_pow(*args):
    if len(args) not in {2, 3}:
        return builtins.pow(*args)

    base = args[0]
    exponent = args[1]
    modulus = args[2] if len(args) == 3 else None

    if isinstance(base, int) and isinstance(exponent, int):
        if modulus is None:
            if _estimated_pow_bits(base, exponent) > constants.MAX_INTEGER_BITS:
                raise _integer_limit_error("integer exponentiation")
        elif isinstance(modulus, int):
            _ensure_integer_size(modulus, kind="modular exponentiation modulus")
            if exponent < 0:
                raise ValueError(
                    "pow() 3rd argument not allowed unless exponent is non-negative"
                )
            if (
                exponent.bit_length()
                > constants.MAX_MODULAR_POW_EXPONENT_BITS
            ):
                raise _integer_limit_error("modular exponentiation exponent")

    result = builtins.pow(*args)
    if isinstance(result, int):
        _ensure_integer_size(result, kind="integer exponentiation")
    return result


def safe_lshift(left, right):
    if isinstance(left, int) and isinstance(right, int):
        if right < 0:
            raise ValueError("negative shift count")
        if left != 0 and abs(left).bit_length() + right > constants.MAX_INTEGER_BITS:
            raise _integer_limit_error("left shift")
    result = left << right
    if isinstance(result, int):
        _ensure_integer_size(result, kind="left shift")
    return result


def safe_rshift(left, right):
    if isinstance(right, int):
        if right < 0:
            raise ValueError("negative shift count")
        if right > constants.MAX_INTEGER_BITS:
            raise _integer_limit_error("right shift count")
    return left >> right


def eager_map(function, *iterables):
    if function is None or not callable(function):
        raise TypeError("map() must have a callable first argument")
    if len(iterables) == 0:
        raise TypeError("map() must have at least two arguments")
    return [function(*items) for items in zip(*iterables)]


def eager_filter(function, iterable):
    if function is None:
        return [item for item in iterable if item]
    if not callable(function):
        raise TypeError("filter() must have a callable first argument or None")
    return [item for item in iterable if function(item)]


exports = {
    "map": eager_map,
    "filter": eager_filter,
    "range": safe_range,
    "bytes": safe_bytes,
    "bytearray": safe_bytearray,
    "__xian_int__": safe_int,
    "__xian_mul__": safe_mul,
    "__xian_pow__": safe_pow,
    "__xian_lshift__": safe_lshift,
    "__xian_rshift__": safe_rshift,
}
