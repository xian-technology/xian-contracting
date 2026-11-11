from __future__ import annotations

from decimal import Decimal
from typing import Iterable

from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.time import Datetime, Timedelta


def _values_equal(left, right) -> bool:
    # Python containers match an identical object even when NaN != NaN.
    if left is right:
        return True
    try:
        return left == right
    except TypeError:
        return False


def _exact_values_equal(left, right):
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, tuple) and isinstance(right, tuple):
        return len(left) == len(right) and all(
            _exact_values_equal(a, b) for a, b in zip(left, right)
        )
    return _values_equal(left, right)


def _canonical_key(value):
    if value is None:
        return (0, "")
    if type(value) is bool:
        return (1, 1 if value else 0)
    if type(value) is int:
        return (2, value)
    if isinstance(value, ContractingDecimal):
        return (3, value._d)
    if type(value) is float:
        # NaNs have one final sort key. Stable sorting preserves their input
        # order; _values_equal separately handles identity and deduplication.
        return (4, 1) if value != value else (4, 0, value)
    if isinstance(value, Datetime):
        return (
            5,
            (
                value.year,
                value.month,
                value.day,
                value.hour,
                value.minute,
                value.second,
                value.microsecond,
            ),
        )
    if isinstance(value, Timedelta):
        return (6, value.seconds)
    if isinstance(value, str):
        return (7, value)
    if isinstance(value, bytes):
        return (8, value)
    if isinstance(value, tuple):
        return (9, tuple(_canonical_key(item) for item in value))
    if isinstance(value, ContractingFrozenSet):
        return (10, tuple(_canonical_key(item) for item in value))
    if isinstance(value, Decimal):
        if value.is_snan():
            raise TypeError("Cannot hash a signaling NaN value")
        if value.is_nan():
            parts = value.as_tuple()
            return (11, 3, parts.sign, len(parts.digits), parts.digits)
        if value.is_infinite():
            return (11, 0 if value.is_signed() else 2)
        return (11, 1, value)
    raise TypeError(f"unhashable type: '{type(value).__name__}'")


def _ensure_hashable(value):
    _canonical_key(value)


def _normalize_set_items(iterable: Iterable, equals=_values_equal):
    normalized: list[tuple[object, tuple]] = []
    for value in iterable:
        _ensure_hashable(value)
        key = _canonical_key(value)
        for index, (existing, existing_key) in enumerate(normalized):
            if equals(existing, value):
                if key < existing_key:
                    normalized[index] = (value, key)
                break
        else:
            normalized.append((value, key))
    normalized.sort(key=lambda item: item[1])
    return tuple(value for value, _ in normalized)


def _iterable_values(iterable=None):
    if iterable is None:
        return ()
    try:
        return tuple(iterable)
    except TypeError as exc:
        raise TypeError(f"'{type(iterable).__name__}' object is not iterable") from exc


class _ContractingSetBase:
    __slots__ = ("_exact_numbers", "_values")

    @classmethod
    def _from_v2_members(cls, iterable):
        result = cls.__new__(cls)
        result._init_members(iterable, exact_numbers=True)
        return result

    def _init_members(self, iterable, *, exact_numbers=False):
        object.__setattr__(self, "_exact_numbers", exact_numbers)
        values = _normalize_set_items(_iterable_values(iterable), self._equals)
        object.__setattr__(self, "_values", values)

    @property
    def _equals(self):
        return _exact_values_equal if self._exact_numbers else _values_equal

    def _new(self, values):
        return self._from_v2_members(values) if self._exact_numbers else type(self)(values)

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def __bool__(self):
        return bool(self._values)

    def __contains__(self, item):
        return any(self._equals(existing, item) for existing in self._values)

    def __eq__(self, other):
        if isinstance(other, _ContractingSetBase):
            return len(self) == len(other) and all(item in other for item in self)
        return False

    def __le__(self, other):
        other = self._coerce_operator_other(other)
        if other is NotImplemented:
            return NotImplemented
        return all(item in other for item in self)

    def __lt__(self, other):
        other = self._coerce_operator_other(other)
        if other is NotImplemented:
            return NotImplemented
        return len(self) < len(other) and self <= other

    def __ge__(self, other):
        other = self._coerce_operator_other(other)
        if other is NotImplemented:
            return NotImplemented
        return all(item in self for item in other)

    def __gt__(self, other):
        other = self._coerce_operator_other(other)
        if other is NotImplemented:
            return NotImplemented
        return len(self) > len(other) and self >= other

    def __and__(self, other):
        other = self._coerce_operator_other(other)
        if other is NotImplemented:
            return NotImplemented
        return self.intersection(other)

    def __or__(self, other):
        other = self._coerce_operator_other(other)
        if other is NotImplemented:
            return NotImplemented
        return self.union(other)

    def __sub__(self, other):
        other = self._coerce_operator_other(other)
        if other is NotImplemented:
            return NotImplemented
        return self.difference(other)

    def __xor__(self, other):
        other = self._coerce_operator_other(other)
        if other is NotImplemented:
            return NotImplemented
        return self.symmetric_difference(other)

    def issubset(self, other):
        other = self._new(self._iterable_other(other))
        return self <= other

    def issuperset(self, other):
        other = self._new(self._iterable_other(other))
        return self >= other

    def isdisjoint(self, other):
        other = self._new(self._iterable_other(other))
        return all(item not in other for item in self)

    def union(self, *others):
        values = list(self._values)
        for other in others:
            values.extend(self._iterable_other(other))
        return self._new(values)

    def intersection(self, *others):
        result = list(self._values)
        for other in others:
            other = self._new(self._iterable_other(other))
            result = [item for item in result if item in other]
        return self._new(result)

    def difference(self, *others):
        result = list(self._values)
        for other in others:
            other = self._new(self._iterable_other(other))
            result = [item for item in result if item not in other]
        return self._new(result)

    def symmetric_difference(self, other):
        other = self._new(self._iterable_other(other))
        left_only = [item for item in self if item not in other]
        right_only = [item for item in other if item not in self]
        return self._new([*left_only, *right_only])

    def copy(self):
        return self._new(self._values)

    @classmethod
    def __class_getitem__(cls, item):
        return cls

    @staticmethod
    def _coerce_operator_other(other):
        if isinstance(other, _ContractingSetBase):
            return other
        return NotImplemented

    @staticmethod
    def _iterable_other(other):
        return _iterable_values(other)


def _require_mutable_set(value):
    if not isinstance(value, ContractingSet):
        raise TypeError("mutable set receiver required")


class ContractingSet(_ContractingSetBase):
    __slots__ = ()

    def __init__(self, iterable=None):
        self._init_members(iterable)

    def __repr__(self):
        if not self._values:
            return "set()"
        return "{" + ", ".join(repr(item) for item in self._values) + "}"

    def add(self, value):
        _require_mutable_set(self)
        self._values = _normalize_set_items([*self._values, value], self._equals)

    def remove(self, value):
        _require_mutable_set(self)
        if value not in self:
            raise KeyError(value)
        self._values = tuple(item for item in self._values if not self._equals(item, value))

    def discard(self, value):
        _require_mutable_set(self)
        if value in self:
            self.remove(value)

    def pop(self):
        _require_mutable_set(self)
        if not self._values:
            raise KeyError("pop from an empty set")
        value = self._values[0]
        self._values = self._values[1:]
        return value

    def clear(self):
        _require_mutable_set(self)
        self._values = ()


class ContractingFrozenSet(_ContractingSetBase):
    __slots__ = ("_hash",)

    def __init__(self, iterable=None):
        self._init_members(iterable)

    def _init_members(self, iterable, *, exact_numbers=False):
        super()._init_members(iterable, exact_numbers=exact_numbers)
        # Equal frozen sets share cardinality under either numeric profile.
        object.__setattr__(self, "_hash", hash(len(self)))

    def __setattr__(self, name, value):
        raise AttributeError("ContractingFrozenSet is immutable")

    def __delattr__(self, name):
        raise AttributeError("ContractingFrozenSet is immutable")

    def __reduce__(self):
        # Reconstruct through the initializer so values and cached hash agree.
        # Copy/deepcopy/pickle must not assign immutable slots.
        constructor = self._from_v2_members if self._exact_numbers else type(self)
        return constructor, (self._values,)

    def __repr__(self):
        if not self._values:
            return "frozenset()"
        return "frozenset({" + ", ".join(repr(item) for item in self._values) + "})"

    def __hash__(self):
        return self._hash

    def copy(self):
        return self


exports = {
    "set": ContractingSet,
    "frozenset": ContractingFrozenSet,
}
