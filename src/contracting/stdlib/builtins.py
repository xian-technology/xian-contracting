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
    return left * right


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
    "__xian_mul__": safe_mul,
}
