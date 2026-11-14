"""Historical numeric, range and dynamic dictionary protocols."""

import pytest

from tests.integration.pre_retirement_oracle import recorded_python_observation
from tests.integration.test_vm_language_conformance import _run_native_case
from tests.integration.test_vm_language_conformance import compare

pytestmark = pytest.mark.optional_native


def test_wide_integer_range_matches_python(tmp_path):
    compare(
        tmp_path,
        "r=range(10**100,10**100+30,3)\nreturn [r.count(10**100+9),r.index(10**100+9),r.count(10**100+10)]",
    )


def test_dictionary_popitem_and_live_mapping(tmp_path):
    compare(
        tmp_path,
        "d={'a':1,'b':2}\nv=d.keys()\nm=v.mapping\npopped=d.popitem()\n"
        "d['c']=3\nreturn [popped,list(m),m['c'],m.get('a'),dict(m),len(m)]",
    )


def test_dictionary_set_views_are_dynamic(tmp_path):
    compare(
        tmp_path,
        "d={'a':1,'b':2}\nk=d.keys()\ni=d.items()\nd['c']=3\n"
        "return [sorted(k & set(['b','z'])),sorted(k | ['z']),"
        "sorted(k-set(['b'])),sorted(k ^ set(['a','z'])),k.isdisjoint(['z']),"
        "i.isdisjoint([('z',3)]),sorted(i & set([('b',2)])),"
        "sorted(set([('b',2)]) | i)]",
    )


def test_mapping_proxy_reads_are_live_but_copies_are_snapshots(tmp_path):
    compare(
        tmp_path,
        "d={'a':1,'b':2}\nm=d.items().mapping\nc=m.copy()\n"
        "d['a']=9\nd['c']=3\n"
        "return [list(reversed(m)),list(m.keys()),list(m.values()),"
        "list(m.items()),c,m==d,'c' in m,m | {'z':0},{'z':0} | m]",
    )


def test_view_comparisons_and_unhashable_items(tmp_path):
    compare(
        tmp_path,
        "a={'x':[1],'y':[2]}\nb={'x':[1]}\ni=a.items()\nj=b.items()\n"
        "return [j<i,j<=i,i>j,i>=j,i==a.items(),i!=j,"
        "i.isdisjoint([('x',[1])]),i.isdisjoint([('x',[9])]),"
        "('x',[1]) in i,a.keys()==set(['x','y']),a.keys()==['x','y']]",
    )


def test_view_operations_and_popitem_preserve_aliases(tmp_path):
    compare(
        tmp_path,
        "d={'a':1,'b':2}\nk=d.keys()\ns=set(['a','z'])\nalias=s\ns&=k\n"
        "d['a']=3\nfirst=d.popitem()\nd['b']=4\nsecond=d.popitem()\n"
        "return [sorted(s),sorted(alias),s is alias,first,second,list(k)]",
    )


@pytest.mark.parametrize(
    "expression",
    [
        "(256).to_bytes()",
        "(-1).to_bytes()",
        "(128).to_bytes(1,signed=True)",
        "int.from_bytes([256])",
        "(1).to_bytes(1,'big',True)",
        "range(4).index(5)",
        "range(4).count(value=2)",
        "{}.popitem()",
        "{}.keys().isdisjoint([] , [])",
    ],
)
def test_invalid_scalar_and_view_calls_fail(tmp_path, expression):
    case = {
        "id": "scalar_invalid",
        "source": "v=Variable()\n@export\ndef probe():\n    v.set(1)\n    return "
        + expression
        + "\n",
        "function_name": "probe",
        "kwargs": {},
    }
    expected = recorded_python_observation(case)
    actual = _run_native_case(case, tmp_path / "native")
    assert expected["status_code"] == actual["status_code"] == 1
    assert expected["writes"] == actual["writes"] == {}
    assert expected["events"] == actual["events"] == []


def test_items_symmetric_difference_cancels_equal_unhashable_values(tmp_path):
    compare(tmp_path, "a={'x':[1],'a':2}\nb={'x':[1],'b':3}\nreturn sorted(a.items() ^ b.items())")


@pytest.mark.parametrize(
    "operation", ["left==right", "left.isdisjoint(right)", "left | right", "left & right"]
)
def test_view_payload_work_is_charged_before_comparing(tmp_path, operation):
    from tests.vm_calls import execute_contract

    from contracting.storage.driver import Driver

    with Driver(storage_home=tmp_path) as driver:
        source = (
            "v=Variable()\n@export\ndef probe(entries: dict):\n    v.set(1)\n"
            "    left=entries.keys()\n    right=entries.keys()\n    return " + operation + "\n"
        )
        driver.set_contract_from_source("con_view_work", source, owner=None)
        driver.commit()
        result = execute_contract(
            driver=driver,
            contract_name="con_view_work",
            function_name="probe",
            kwargs={"entries": {"a" * 8192 + str(i): i for i in range(10)}},
            context={"caller": "alice", "signer": "alice", "this": "con_view_work"},
            meter=True,
            chi_budget_raw=50_000,
        )
        assert result.status_code == 1 and "Out of chi" in str(result.result)
        assert result.writes == {} and result.events == []
