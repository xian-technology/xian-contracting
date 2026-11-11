"""Historically available string APIs through contract execution."""

import pytest

from tests.integration.pre_retirement_oracle import recorded_python_observation
from tests.integration.test_vm_language_conformance import _run_native_case

pytestmark = pytest.mark.optional_native


EXPRESSIONS = [
    "['ßABC'.capitalize(), 'ǅABC'.capitalize(), 'AΣ'.capitalize()]",
    "['Straße İΣς'.casefold(), 'AΣ'.swapcase(), 'ǅßA'.swapcase()]",
    """["they're BILL'S friends".title(), 'ßa ǅABC'.title()]""",
    "['abc'.center(6, '中'), 'abc'.ljust(5, '_'), 'abc'.rjust(5, '_'), 'abc'.center(-1)]",
    "['-42'.zfill(6), '+42'.zfill(6), ''.zfill(3), '中'.zfill(3)]",
    "['a\\tb\\n\\tc'.expandtabs(4), 'a\\tb'.expandtabs(0), 'a\\tb'.expandtabs(-1)]",
    "['abcabc'.index('b', -4), 'abcabc'.rfind('bc'), 'abcabc'.rindex('bc', 0, 5)]",
    "['abc'.rfind('', 4), 'abc'.rfind('', -100, 100), 'abc'.rfind('a', 2, 1)]",
    "['١'.isdecimal(), '²'.isdecimal(), '²'.isnumeric(), '¼'.isnumeric(), ''.isdecimal()]",
    "['变量'.isidentifier(), '_x1'.isidentifier(), 'class'.isidentifier(), '1x'.isidentifier()]",
    "[''.isprintable(), ' '.isprintable(), '\\xa0'.isprintable(), '\\n'.isprintable(), '\\x1c'.isspace(), ''.isspace()]",
    "['Hello World'.istitle(), 'ǅ Ab'.istitle(), 'HELLO'.istitle(), 'A中'.isupper(), '中'.isupper()]",
    "['  a  '.lstrip(), '  a  '.rstrip(None), 'xyabcxy'.lstrip('xy'), 'xyabcxy'.rstrip('xy')]",
    "['abcabc'.removeprefix('abc'), 'abcabc'.removesuffix('abc'), 'abc'.removesuffix(''), 'abc'.removeprefix('x')]",
    "['a:b:c'.partition(':'), 'a:b:c'.rpartition(':'), 'abc'.partition(':'), 'abc'.rpartition(':')]",
    "[' a b c '.rsplit(None, 1), ' a b c '.rsplit(None, 0), 'a:b:c'.rsplit(':', 1), ''.rsplit(), ''.rsplit(':')]",
    "['a\\r\\nb\\vc\\fd\\x1ce\\x85f\\u2028g\\u2029'.splitlines(), 'a\\r\\nb\\n'.splitlines(True), ''.splitlines()]",
    "'abca'.translate({97: 'XX', 98: None, 99: 100})",
    "'abc'.translate([65] * 100)",
    "'abc'.translate({})",
    "'ab'.translate({97: 'X'}.keys().mapping)",
    "['a\\nb'.splitlines('yes'), 'a\\nb'.splitlines([]), 'a\\nb'.splitlines(10**100)]",
    "['abc'.translate(range(1000)), 'abc'.translate('X' * 100), ''.translate(None)]",
    "sorted(''.maketrans('ab', 'XY', 'c').items())",
    "sorted(''.maketrans({'a': 'XYZ', 98: None, '中': 67}).items())",
    "sorted(str.maketrans('ab', 'XY').items())",
]


@pytest.mark.parametrize("expression", EXPRESSIONS)
def test_string_methods_match_python(tmp_path, expression):
    case = {
        "id": "string_methods",
        "source": f"@export\ndef probe():\n    return {expression}\n",
        "function_name": "probe",
        "kwargs": {},
    }
    expected = recorded_python_observation(case)
    assert expected["status_code"] == 0, expected
    assert _run_native_case(case, tmp_path / "native") == expected


@pytest.mark.parametrize(
    "expression",
    [
        "'x'.center(4, 'ab')",
        "'x'.center(decimal(4))",
        "'abc'.find('a', decimal(0))",
        "'abc'.count('a', decimal(0))",
        "'abc'.startswith('a', decimal(0))",
        "'abc'.split('a', decimal(1))",
        "'abc'.replace('a', 'b', decimal(1))",
        "'aaa'.split('a', 10**100)",
        "'aaa'.replace('a', 'b', -10**100)",
        "'abc'.rfind('a', decimal(0))",
        "'a'.expandtabs(decimal(4))",
        "'a'.expandtabs(2147483648)",
        "''.expandtabs(-2147483649)",
        "'abc'.index('z')",
        "'abc'.rindex('z')",
        "'abc'.partition('')",
        "'abc'.rsplit('')",
        "'abc'.translate({97: []})",
        "'abc'.translate({97: 1114112})",
        "''.maketrans('a', 'bc')",
        "''.maketrans({'ab': 'c'})",
        "''.maketrans({None: 'c'})",
    ],
)
def test_string_method_errors_match_python(tmp_path, expression):
    case = {
        "id": "string_method_error",
        "source": f"@export\ndef probe():\n    return {expression}\n",
        "function_name": "probe",
        "kwargs": {},
    }
    assert recorded_python_observation(case)["status_code"] != 0
    assert _run_native_case(case, tmp_path / "native")["status_code"] != 0


def test_translation_uses_hash_defaults_and_metered_storage_reads(tmp_path):
    case = {
        "id": "string_hash_translate",
        "source": "h=Hash(default_value=None)\n@export\ndef probe():\n    h[97]='X'\n    return 'ab'.translate(h)\n",
        "function_name": "probe",
        "kwargs": {},
    }
    expected = recorded_python_observation(case)
    assert expected["status_code"] == 0, expected
    assert expected["result"] == "X"
    assert _run_native_case(case, tmp_path / "native") == expected


@pytest.mark.parametrize(
    "body",
    [
        "f='a:b:c'.rsplit\nreturn f(sep=':', maxsplit=1)",
        "f='a\\tb'.expandtabs\nreturn f(tabsize=4)",
        "f='a\\nb'.splitlines\nreturn f(keepends=True)",
        "f='abc'.center\nreturn f(7, '_')",
        "f=str.maketrans\nreturn 'ab'.translate(f('ab', 'XY'))",
        "f='Straße'.casefold\nreturn f()",
    ],
)
def test_bound_string_methods_share_direct_semantics(tmp_path, body):
    case = {
        "id": "bound_string_methods",
        "source": "@export\ndef probe():\n"
        + "".join("    " + line + "\n" for line in body.splitlines()),
        "function_name": "probe",
        "kwargs": {},
    }
    expected = recorded_python_observation(case)
    assert expected["status_code"] == 0, expected
    assert _run_native_case(case, tmp_path / "native") == expected


def test_identifier_uses_historical_unicode_15(tmp_path):
    # Unicode 15 identifiers exclude join controls; newer host Python Unicode
    # versions accept them. Contract consensus follows the pinned old runtime.
    case = {
        "id": "historical_identifier",
        "source": "@export\ndef probe():\n    return ['a\\u200c'.isidentifier(), 'a\\u200d'.isidentifier(), '\\U0002ebf0'.isidentifier()]\n",
        "function_name": "probe",
        "kwargs": {},
    }
    observed = _run_native_case(case, tmp_path)
    assert observed == {
        "status_code": 0,
        "result": [False, False, False],
        "writes": {},
        "events": [],
    }


@pytest.mark.parametrize("bound", [False, True])
def test_expansion_work_is_charged_before_allocation_and_rolls_back(tmp_path, bound):
    from xian_vm_core import execute_contract

    from contracting.storage.driver import Driver

    operation = (
        "f = '\\t'.expandtabs\n    return len(f(tabsize))"
        if bound
        else "return len('\\t'.expandtabs(tabsize))"
    )
    source = (
        "v=Variable()\n@export\ndef probe(tabsize: int):\n"
        "    v.set(tabsize)\n    " + operation + "\n"
    )
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_string_budget", source, owner=None)
        driver.commit()
        common = {
            "driver": driver,
            "contract_name": "con_string_budget",
            "function_name": "probe",
            "context": {"caller": "alice", "signer": "alice", "this": "con_string_budget"},
            "meter": True,
            "chi_budget_raw": 50_000,
        }
        small = execute_contract(**common, kwargs={"tabsize": 1})
        assert small.status_code == 0 and small.result == 1
        exhausted = execute_contract(**common, kwargs={"tabsize": 100_000})
        assert exhausted.status_code == 1 and "Out of chi" in str(exhausted.result)
        assert exhausted.writes == {} and exhausted.events == []


def test_large_custom_strip_membership_is_shared_by_all_variants(tmp_path):
    case = {
        "id": "large_strip_membership",
        "source": "@export\ndef probe():\n    chars = 'a' * 20000 + '中'\n    text = '中' * 10000 + 'value' + '中' * 10000\n    return [text.strip(chars), len(text.lstrip(chars)), len(text.rstrip(chars))]\n",
        "function_name": "probe",
        "kwargs": {},
    }
    expected = recorded_python_observation(case)
    assert expected["status_code"] == 0, expected
    assert expected["result"] == ["value", 10005, 10005]
    assert _run_native_case(case, tmp_path / "native") == expected


@pytest.mark.parametrize("bound", [False, True])
def test_custom_strip_work_is_charged_and_rolls_back(tmp_path, bound):
    from xian_vm_core import execute_contract

    from contracting.storage.driver import Driver

    operation = "f = 'aaaa'.strip\n    return f(chars)" if bound else "return 'aaaa'.strip(chars)"
    source = "v=Variable()\n@export\ndef probe(chars: str):\n    v.set(1)\n    " + operation + "\n"
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_strip_budget", source, owner=None)
        driver.commit()
        common = {
            "driver": driver,
            "contract_name": "con_strip_budget",
            "function_name": "probe",
            "context": {"caller": "alice", "signer": "alice", "this": "con_strip_budget"},
            "meter": True,
            "chi_budget_raw": 50_000,
        }
        small = execute_contract(**common, kwargs={"chars": "a"})
        assert small.status_code == 0 and small.result == ""
        exhausted = execute_contract(**common, kwargs={"chars": "b" * 20000 + "a"})
        assert exhausted.status_code == 1 and "Out of chi" in str(exhausted.result)
        assert exhausted.writes == {} and exhausted.events == []
