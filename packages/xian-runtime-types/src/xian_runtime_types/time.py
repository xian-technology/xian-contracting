# Original Xian implementation, written from the Xian VM's datetime rules.
# Copyright (c) 2026 Xian Technology. Licensed under the MIT License.
"""Contract datetimes and timedeltas with the Xian VM's semantics.

A ``Datetime`` is a calendar moment from year 1 to 9999 with microseconds
(``VmDateTime``). A ``Timedelta`` is a whole number of seconds
(``VmTimeDelta``) within Python's ``timedelta`` range.
"""

from datetime import datetime, timedelta
from types import ModuleType

from .time_format import parse_datetime

SECONDS_IN_MINUTE = 60
SECONDS_IN_HOUR = 60 * SECONDS_IN_MINUTE
SECONDS_IN_DAY = 24 * SECONDS_IN_HOUR
SECONDS_IN_WEEK = 7 * SECONDS_IN_DAY


def get_raw_seconds(weeks, days, hours, minutes, seconds):
    """The total seconds of the given components."""
    return (
        seconds
        + minutes * SECONDS_IN_MINUTE
        + hours * SECONDS_IN_HOUR
        + days * SECONDS_IN_DAY
        + weeks * SECONDS_IN_WEEK
    )


def to_contract_time(py_dt):
    """The ``__time__`` wire form of a datetime, to the second."""
    if not isinstance(py_dt, (datetime, Datetime)):
        raise TypeError("Expected datetime.datetime or Datetime")
    return {
        "__time__": [py_dt.year, py_dt.month, py_dt.day, py_dt.hour, py_dt.minute, py_dt.second]
    }


class _Ordered:
    """Equality and ordering by the subclass's ``_key()`` among values of one kind.

    A value of another kind is unequal (VM equality); ordering against it fails.
    """

    __hash__ = None

    def _other_key(self, other):
        if not isinstance(other, type(self)):
            raise TypeError(f"{type(other)} is not a {type(self).__name__}!")
        return other._key()

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        return self._key() == other._key()

    def __lt__(self, other):
        return self._key() < self._other_key(other)

    def __le__(self, other):
        return self._key() <= self._other_key(other)

    def __gt__(self, other):
        return self._key() > self._other_key(other)

    def __ge__(self, other):
        return self._key() >= self._other_key(other)


class Datetime(_Ordered):
    """A calendar moment; Python's ``datetime`` validates its fields."""

    def __init__(self, year, month, day, hour=0, minute=0, second=0, microsecond=0):
        moment = datetime(year, month, day, hour, minute, second, microsecond)
        self._datetime = moment
        self.year = moment.year
        self.month = moment.month
        self.day = moment.day
        self.hour = moment.hour
        self.minute = moment.minute
        self.second = moment.second
        self.microsecond = moment.microsecond

    @classmethod
    def _from_datetime(cls, value: datetime):
        return cls(
            value.year,
            value.month,
            value.day,
            value.hour,
            value.minute,
            value.second,
            value.microsecond,
        )

    @classmethod
    def strptime(cls, date_string, format):
        return cls._from_datetime(parse_datetime(date_string, format))

    def _key(self):
        return self._datetime

    def __add__(self, other):
        if not isinstance(other, Timedelta):
            return NotImplemented
        return Datetime._from_datetime(self._datetime + other._timedelta)

    def __sub__(self, other):
        """The whole seconds between two moments, rounded down (``VmDateTime::sub_datetime``)."""
        if not isinstance(other, Datetime):
            return NotImplemented
        gap = self._datetime - other._datetime
        return Timedelta(days=gap.days, seconds=gap.seconds)

    def __str__(self):
        return str(self._datetime)

    __repr__ = __str__


class Timedelta(_Ordered):
    """A signed whole number of seconds."""

    def __init__(self, weeks=0, days=0, hours=0, minutes=0, seconds=0):
        raw_seconds = get_raw_seconds(int(weeks), int(days), int(hours), int(minutes), int(seconds))
        # Python's timedelta bounds the value (and words the overflow) as the VM does.
        self._timedelta = timedelta(seconds=raw_seconds)
        self._raw_seconds = raw_seconds

    def _key(self):
        return self._raw_seconds

    def __bool__(self):
        return self._raw_seconds != 0

    def __add__(self, other):
        if isinstance(other, Timedelta):
            return Timedelta(seconds=self._raw_seconds + other._raw_seconds)
        if isinstance(other, Datetime):
            return other + self
        return NotImplemented

    def __sub__(self, other):
        if isinstance(other, Timedelta):
            return Timedelta(seconds=self._raw_seconds - other._raw_seconds)
        if isinstance(other, Datetime):
            return Datetime._from_datetime(other._datetime - self._timedelta)
        return NotImplemented

    def __mul__(self, other):
        """By an int, or by a Timedelta per normalized part (``VmTimeDelta::mul_timedelta``)."""
        if isinstance(other, Timedelta):
            days = self.days * other.days
            seconds = (self._raw_seconds % SECONDS_IN_DAY) * (other._raw_seconds % SECONDS_IN_DAY)
            return Timedelta(days=days, seconds=seconds)
        if isinstance(other, int):
            return Timedelta(seconds=self._raw_seconds * other)
        return NotImplemented

    def __str__(self):
        return str(self._timedelta)

    __repr__ = __str__

    @property
    def seconds(self):
        return self._raw_seconds

    @property
    def minutes(self):
        return self._raw_seconds // SECONDS_IN_MINUTE

    @property
    def hours(self):
        return self._raw_seconds // SECONDS_IN_HOUR

    @property
    def days(self):
        return self._raw_seconds // SECONDS_IN_DAY

    @property
    def weeks(self):
        return self._raw_seconds // SECONDS_IN_WEEK


WEEKS = Timedelta(weeks=1)
DAYS = Timedelta(days=1)
HOURS = Timedelta(hours=1)
MINUTES = Timedelta(minutes=1)
SECONDS = Timedelta(seconds=1)

datetime_module = ModuleType("datetime")
datetime_module.datetime = Datetime
datetime_module.timedelta = Timedelta
datetime_module.WEEKS = WEEKS
datetime_module.DAYS = DAYS
datetime_module.HOURS = HOURS
datetime_module.MINUTES = MINUTES
datetime_module.SECONDS = SECONDS

exports = {"datetime": datetime_module}
