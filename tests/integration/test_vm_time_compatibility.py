"""Time parsing defaults and negative duration boundaries match Python wrappers."""

import pytest

from tests.integration.pre_retirement_oracle import recorded_python_observation
from tests.integration.test_vm_language_conformance import _run_native_case
from tests.integration.test_vm_raw_decimal import compare

pytestmark = pytest.mark.optional_native


@pytest.mark.parametrize(
    "text,format",
    [
        ("2026-02-03", "%Y-%m-%d"),
        ("23:45", "%H:%M"),
        ("2026", "%Y"),
        ("03-02", "%d-%m"),
        ("2024 060", "%Y %j"),
        ("2026-02-03 12:34:56.1234", "%Y-%m-%d %H:%M:%S.%f"),
    ],
)
def test_strptime_defaults_and_fraction(tmp_path, text, format):
    compare(
        tmp_path,
        f"x=datetime.datetime.strptime({text!r},{format!r})\nreturn [str(x),x.year,x.month,x.day,x.hour,x.minute,x.second,x.microsecond]",
    )


@pytest.mark.parametrize("seconds", [-604801, -86401, -3601, -61, -1, 0, 1, 61, 86401])
def test_timedelta_floor_attributes_and_rendering(tmp_path, seconds):
    compare(
        tmp_path,
        f"x=datetime.timedelta(seconds={seconds})\nreturn [str(x),x.seconds,x.minutes,x.hours,x.days,x.weeks]",
    )


def test_negative_subsecond_difference_floors(tmp_path):
    compare(
        tmp_path,
        "a=datetime.datetime(2026,2,3,0,0,0,1)\nb=datetime.datetime(2026,2,3,0,0,0,2)\nreturn [(a-b).seconds,(b-a).seconds]",
    )


@pytest.mark.parametrize(
    "expression",
    [
        "datetime.datetime(4294969322,2,3)",
        "datetime.datetime(2026,4294967298,3)",
        "datetime.datetime(0,1,1)",
        "datetime.datetime(10000,1,1)",
        "datetime.datetime(9999,12,31)+datetime.DAYS",
        "datetime.timedelta(seconds=9223372036854775807)",
        "datetime.timedelta(days=1000000000)",
        "datetime.datetime.strptime('0000-01-01','%Y-%m-%d')",
    ],
)
def test_time_out_of_range_inputs_fail(tmp_path, expression):
    case = {
        "id": "time_bounds",
        "source": "@export\ndef probe():\n    return " + expression + "\n",
        "function_name": "probe",
        "kwargs": {},
    }
    assert recorded_python_observation(case)["status_code"] == 1
    assert _run_native_case(case, tmp_path / "native")["status_code"] == 1


def test_time_factory_methods_and_integer_coercion(tmp_path):
    compare(
        tmp_path,
        "x=datetime.datetime(2026,2,3)\ny=x.strptime('2027','%Y')\nz=datetime.timedelta(seconds='12',minutes=float('1.9'),hours=round(decimal('1.9'),1))\nreturn [str(y),z.seconds]",
        vm_profile="xian_vm_v1",
    )


@pytest.mark.parametrize(
    "expression",
    [
        "datetime.datetime(2026,2,3,year=2027)",
        "datetime.datetime(2026,2,3,unknown=1)",
        "datetime.datetime(2026,2,3,0,0,0,0,0)",
        'datetime.datetime(decimal("2026"),2,3)',
        "datetime.timedelta(1,weeks=2)",
        "datetime.timedelta(unknown=1)",
        "datetime.timedelta(1,2,3,4,5,6)",
    ],
)
def test_time_constructor_invalid_arguments(tmp_path, expression):
    case = {
        "id": "time_arguments",
        "source": "@export\ndef probe():\n    return " + expression + "\n",
        "function_name": "probe",
        "kwargs": {},
    }
    assert recorded_python_observation(case)["status_code"] == 1
    assert _run_native_case(case, tmp_path / "native")["status_code"] == 1


def test_strptime_alias_remains_callable(tmp_path):
    compare(
        tmp_path, "parse=datetime.datetime.strptime\nreturn str(parse('2026-02-03','%Y-%m-%d'))"
    )


def test_strptime_method_is_not_classinfo(tmp_path):
    case = {
        "id": "time_method_classinfo",
        "source": "@export\ndef probe():\n    return isinstance(datetime.datetime(2026,2,3),datetime.datetime.strptime)\n",
        "function_name": "probe",
        "kwargs": {},
    }
    assert recorded_python_observation(case)["status_code"] == 1
    assert _run_native_case(case, tmp_path / "native")["status_code"] == 1
