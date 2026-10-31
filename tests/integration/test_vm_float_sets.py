"""Canonical float-set iteration is numeric, including nested keys and mutations."""

import pytest

from tests.integration.test_vm_language_conformance import _run_native_case, _run_python_case

pytestmark = pytest.mark.optional_native


def assert_float_set_result(tmp_path, body, expected):
    case = {
        "id": "float_set_order",
        "source": "@export\ndef probe():\n"
        + "".join("    " + line + "\n" for line in body.splitlines()),
        "function_name": "probe",
        "kwargs": {},
    }
    for engine, run in [("python", _run_python_case), ("native", _run_native_case)]:
        result = run(case, tmp_path / engine)
        assert result["status_code"] == 0, result
        assert result["result"] == expected, (engine, result)


@pytest.mark.parametrize("constructor", ["set", "frozenset"])
def test_float_set_numeric_order(tmp_path, constructor):
    assert_float_set_result(
        tmp_path,
        f"s={constructor}([float(x) for x in ['2','10','-2','-10','1e-10','0.9',"
        "'inf','-inf','5e-324','-5e-324']])\nreturn [str(x) for x in s]",
        ["-inf", "-10.0", "-2.0", "-5e-324", "5e-324", "1e-10", "0.9", "2.0", "10.0", "inf"],
    )


@pytest.mark.parametrize("first,second", [("0", "-0"), ("-0", "0")])
def test_float_set_retains_first_equal_zero(tmp_path, first, second):
    assert_float_set_result(
        tmp_path,
        f"a=float('{first}')\nb=float('{second}')\ns=set([a,b])\ns.add(b)\n"
        "return [len(s),str(list(s)[0]),list(s)[0] is a]",
        [1, first + ".0", True],
    )


@pytest.mark.parametrize("wrap,unwrap", [("(x,)", "x[0]"), ("frozenset([x])", "list(x)[0]")])
def test_float_set_nested_keys(tmp_path, wrap, unwrap):
    assert_float_set_result(
        tmp_path,
        "values=[float('10'),float('2'),float('-2'),float('-10')]\n"
        f"s=set([{wrap} for x in values])\nreturn [str({unwrap}) for x in s]",
        ["-10.0", "-2.0", "2.0", "10.0"],
    )


def test_float_set_mutations_and_algebra(tmp_path):
    assert_float_set_result(
        tmp_path,
        "a=float('2')\nb=float('10')\nc=float('-2')\ns=set([b])\ns.add(a)\n"
        "s.add(c)\ns.add(b)\npopped=s.pop()\n"
        "return [str(popped),[str(x) for x in s],"
        "[str(x) for x in s.union([c])],"
        "[str(x) for x in s.intersection([a,b])],"
        "[str(x) for x in s.symmetric_difference([b,c])],"
        "[str(x) for x in s.difference([a])]]",
        [
            "-2.0",
            ["2.0", "10.0"],
            ["-2.0", "2.0", "10.0"],
            ["2.0", "10.0"],
            ["-2.0", "2.0"],
            ["10.0"],
        ],
    )


def test_float_set_cross_type_representatives(tmp_path):
    assert_float_set_result(
        tmp_path,
        "s=set([float('10'),10,float('1'),True,float('0'),False,"
        "float('2'),decimal('2'),float('3')])\nreturn [str(x) for x in s]",
        ["False", "True", "10", "2", "3.0"],
    )


@pytest.mark.parametrize("constructor", ["set", "frozenset"])
@pytest.mark.parametrize("values", ["[a,b,c,d,a]", "[c,a,d,b,a]", "[d,c,a,b,a]"])
def test_float_set_nan_order_and_identity(tmp_path, constructor, values):
    assert_float_set_result(
        tmp_path,
        "a=float('nan')\nb=float('-nan')\nc=float('2')\nd=float('inf')\n"
        f"s={constructor}({values})\nt=s.copy()\nitems=list(t)\n"
        "return [len(s),items[0] is c,items[1] is d,items[2] is a,items[3] is b,"
        "a in s,b in s,float('nan') in s,s==s,a==a]",
        [4, True, True, True, True, True, True, False, True, False],
    )


def test_float_set_nan_mutation_and_algebra(tmp_path):
    assert_float_set_result(
        tmp_path,
        "a=float('nan')\nb=float('nan')\ns=set([a])\ns.add(float('2'))\ns.add(b)\n"
        "s.add(a)\ns.add(float('10'))\nx=s.pop()\ny=s.pop()\n"
        "u=s.union([b,float('1')])\ni=s.intersection([a])\nd=s.difference([a])\n"
        "t=s.symmetric_difference([b])\ns.remove(a)\ns.add(a)\n"
        "return [str(x),str(y),len(u),list(u)[1] is a,list(u)[2] is b,"
        "len(i),list(i)[0] is a,len(d),list(d)[0] is b,"
        "len(t),list(t)[0] is a,list(s)[0] is b,list(s)[1] is a]",
        ["2.0", "10.0", 3, True, True, 1, True, 1, True, 1, True, True, True],
    )


def test_float_nan_rendering_in_ordered_sets(tmp_path):
    assert_float_set_result(
        tmp_path,
        "x=float('nan')\nreturn [str(x),str(float('-nan')),str([x]),"
        "str(set([x,float('1')])),str(frozenset([x,float('1')]))]",
        ["nan", "nan", "[nan]", "{1.0, nan}", "frozenset({1.0, nan})"],
    )
