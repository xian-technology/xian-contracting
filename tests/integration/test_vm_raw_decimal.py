"""Raw Decimal quantum, context rounding and resource boundaries."""

import random
from pathlib import Path

import pytest
from tests.integration.test_vm_language_conformance import _run_native_case, _run_python_case

pytestmark = pytest.mark.optional_native


def compare(tmp_path: Path, body: str):
    case = {
        "id": "raw_decimal",
        "source": "@export\ndef probe():\n"
        + "".join("    " + line + "\n" for line in body.splitlines()),
        "function_name": "probe",
        "kwargs": {},
    }
    expected = _run_python_case(case, tmp_path / "python")
    assert expected["status_code"] == 0, expected
    assert _run_native_case(case, tmp_path / "native") == expected


def test_seeded_decimal_arithmetic(tmp_path):
    rng = random.Random(73)
    pairs = [
        [str(rng.randint(-999999, 999999)), str(rng.choice([3, 7, 11, 17, 23])), rng.randint(0, 10)]
        for _ in range(24)
    ]
    compare(
        tmp_path,
        f"pairs={pairs!r}\nout=[]\nfor a,b,n in pairs:\n    x=round(decimal(a),n)/7\n    y=round(decimal(b),n+1)/3\n    out.append([str(x+y),str(x-y),str(x*y),str(x/y),str(x//y),str(x%y),str(x**2),str(x**-2),str(round(x,n))])\nreturn out",
    )


def test_decimal_format_matrix(tmp_path):
    values = ["0", "-0.0001", "1.23456789", "-12.34", "1234567.89", "0.00000001"]
    specs = [
        "",
        "e",
        ".2e",
        "E",
        ".2E",
        "f",
        ".4f",
        "g",
        ".3g",
        "G",
        ".3G",
        "%",
        ".2%",
        ",.2f",
        "+12.2f",
        "08.2f",
        "^15.3g",
        "*>15.2f",
        "n",
    ]
    compare(
        tmp_path,
        f"out=[]\nfor text in {values!r}:\n    x=round(decimal(text),8)\n    for spec in {specs!r}:\n        out.append(format(x,spec))\nreturn out",
    )


def test_raw_decimal_set_order_and_duplicates(tmp_path):
    compare(
        tmp_path,
        "a=round(decimal('2'),2)\nb=round(decimal('1'),3)\ns=set([a,b,a,2,decimal('1')])\nreturn [str(list(s)),list(s),a in s, b in s]",
    )


@pytest.mark.parametrize(
    "operation",
    [
        "x**4096",
        "pow(x,4096)",
        "format(x,'100000.50000f')",
        "x**round(decimal('1.2'),1)",
        "x.ln()",
        "pow(2,10**100,round(decimal('7'),0))",
    ],
)
def test_raw_decimal_work_exhausts_budget_and_rolls_back(tmp_path, operation):
    from contracting.storage.driver import Driver
    from xian_vm_core import execute_contract

    with Driver(storage_home=tmp_path) as driver:
        source = (
            "v=Variable()\n@export\ndef probe():\n    v.set(1)\n    x=round(decimal('1.000000000000000001'),18)\n    return "
            + operation
            + "\n"
        )
        driver.set_contract_from_source("con_quantum_budget", source, owner=None)
        driver.commit()
        output = execute_contract(
            driver=driver,
            contract_name="con_quantum_budget",
            function_name="probe",
            kwargs={},
            context={"caller": "alice", "signer": "alice", "this": "con_quantum_budget"},
            meter=True,
            chi_budget_raw=50_000,
        )
        assert output.status_code == 1 and "Out of chi" in str(output.result)
        assert output.writes == {} and output.events == []


def test_exact_powers_keep_decimal_context_quantum(tmp_path):
    compare(
        tmp_path,
        "x=round(decimal('1'),2)\ny=round(decimal('-1'),2)\nz=round(decimal('-0.001'),2)\nreturn [str(x**(10**50)),str(x**-(10**50)),str(y**(10**50+1)),str(z**round(decimal('0.5'),1))]",
    )


@pytest.mark.parametrize(
    "marker,value,accepted",
    [
        ("int", "'wrong'", False),
        ("decimal", "round(decimal('2'),2)", False),
        ("decimal", "decimal('2')", True),
        ("int", "True", True),
        ("float", "round(decimal('2'),2)", False),
    ],
)
def test_typed_variable_checks_before_storage_conversion(tmp_path, marker, value, accepted):
    case = {
        "id": "typed_decimal_storage",
        "source": f"v=Variable(t={marker})\n@export\ndef probe():\n    v.set({value})\n    return v.get()\n",
        "function_name": "probe",
        "kwargs": {},
    }
    expected = _run_python_case(case, tmp_path / "python")
    actual = _run_native_case(case, tmp_path / "native")
    assert expected["status_code"] == int(not accepted)
    if accepted:
        assert actual == expected
    else:
        assert actual["status_code"] == 1
        assert actual["writes"] == expected["writes"] == {}
        assert actual["events"] == expected["events"] == []
