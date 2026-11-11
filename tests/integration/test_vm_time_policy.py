"""Approved deterministic parsing policy and historical duration multiplication."""

import pytest

from tests.integration.pre_retirement_oracle import recorded_python_observation
from tests.integration.test_vm_language_conformance import _run_native_case
from tests.integration.test_vm_raw_decimal import compare

pytestmark = pytest.mark.optional_native


@pytest.mark.parametrize(
    "left,right",
    [(172800, 259200), (86402, 172803), (-1, -1), (-86401, 86403), (-172800, 259200), (0, 86399)],
)
def test_historical_duration_multiplication(tmp_path, left, right):
    compare(
        tmp_path,
        f"a=datetime.timedelta(seconds={left})\nb=datetime.timedelta(seconds={right})\nc=a*b\nreturn [c.seconds,str(c)]",
    )


@pytest.mark.parametrize(
    "text,format",
    [
        ("2026-02-03", "%F"),
        ("Feb 03 2026", "%b %d %Y"),
        ("2026-02-03 UTC", "%Y-%m-%d %Z"),
        ("2026-02-03 +0000", "%Y-%m-%d %z"),
        ("PM", "%p"),
        ("2026 2026", "%Y %Y"),
        ("2026", "%G"),
        ("2026 03", "%Y %V"),
        ("2026 060 03 1", "%G %j %V %u"),
        ("２０２６", "%Y"),
    ],
)
def test_nonportable_or_ambiguous_formats_are_rejected(tmp_path, text, format):
    case = {
        "id": "time_policy",
        "source": f"@export\ndef probe():\n    return datetime.datetime.strptime({text!r},{format!r})\n",
        "function_name": "probe",
        "kwargs": {},
    }
    assert recorded_python_observation(case)["status_code"] == 1
    assert _run_native_case(case, tmp_path / "native")["status_code"] == 1


@pytest.mark.parametrize(
    "left,right",
    [
        (86399999999999, 86399999999999),
        (-86399999913600, 172800),
        (-86399999913600, -86399999913600),
    ],
)
def test_duration_multiplication_overflow(tmp_path, left, right):
    case = {
        "id": "time_multiply_overflow",
        "source": f"@export\ndef probe():\n    return datetime.timedelta(seconds={left})*datetime.timedelta(seconds={right})\n",
        "function_name": "probe",
        "kwargs": {},
    }
    assert recorded_python_observation(case)["status_code"] == 1
    assert _run_native_case(case, tmp_path / "native")["status_code"] == 1


@pytest.mark.parametrize(
    "text,format",
    [
        ("2024-W01-1", "%G-W%V-%u"),
        ("2026 00 0", "%Y %U %w"),
        ("2026 53 0", "%Y %U %w"),
        ("246", "%H%M"),
        ("02\x1c03", "%m %d"),
        ("202601", "%Y%f"),
        ("01 % 日", "%m %% 日"),
        ("69 366", "%y %j"),
        ("12", "%I"),
    ],
)
def test_numeric_formats_preserve_python_parsing(tmp_path, text, format):
    compare(
        tmp_path,
        f"x=datetime.datetime.strptime({text!r},{format!r})\nreturn [str(x),x.microsecond]",
    )


@pytest.mark.parametrize(
    "text,format",
    [
        ("2026 26", "%Y %y"),
        ("12 12", "%H %I"),
        ("03 03", "%U %W"),
        ("1 1", "%w %u"),
        ("2026-W01-1 2026", "%G-W%V-%u %Y"),
        ("2026-W01-1 01", "%G-W%V-%u %m"),
        ("2026-W01-1 03", "%G-W%V-%u %d"),
        ("2026-W01-1 01", "%G-W%V-%u %U"),
    ],
)
def test_conflicting_calendar_representations_are_rejected(tmp_path, text, format):
    case = {
        "id": "time_conflicts",
        "source": f"@export\ndef probe():\n    return datetime.datetime.strptime({text!r},{format!r})\n",
        "function_name": "probe",
        "kwargs": {},
    }
    assert recorded_python_observation(case)["status_code"] == 1
    assert _run_native_case(case, tmp_path / "native")["status_code"] == 1


@pytest.mark.parametrize(
    "call",
    [
        "datetime.datetime.strptime(text,format)",
        "parse(text,format)",
        "datetime.datetime(2026,1,1).strptime(text,format)",
    ],
)
def test_strptime_precharges_work_before_parsing_and_rolls_back(tmp_path, call):
    from xian_vm_core import execute_contract

    from contracting.storage.driver import Driver

    source = (
        "v=Variable()\n@export\ndef probe(text:str,format:str):\n    parse=datetime.datetime.strptime\n    v.set(1)\n    return "
        + call
        + "\n"
    )
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_time_work", source, owner=None)
        driver.commit()
        output = execute_contract(
            driver=driver,
            contract_name="con_time_work",
            function_name="probe",
            kwargs={"text": "x" * 20000, "format": "%Y" + "x" * 20000},
            context={"caller": "alice", "signer": "alice", "this": "con_time_work"},
            meter=True,
            chi_budget_raw=30000,
        )
    assert output.status_code == 1
    assert "Out of chi" in str(output.result)
    assert output.writes == {} and output.events == []


def test_strptime_unmetered_work_cap(tmp_path):
    case = {
        "id": "time_work_cap",
        "source": "@export\ndef probe():\n    return datetime.datetime.strptime('111111111111111111'+'x'*5000,'%Y%m%d%H%M%S%f%j%U%w'+'x'*5000)\n",
        "function_name": "probe",
        "kwargs": {},
    }
    for output in [recorded_python_observation(case), _run_native_case(case, tmp_path / "native")]:
        assert output["status_code"] == 1
        assert "datetime parse work limit exceeded" in str(output["result"])
