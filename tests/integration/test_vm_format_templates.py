"""Bounded format templates resolve fields with ordinary VM value semantics."""

import pytest

from tests.compatibility.runner import encode, run_case

pytestmark = pytest.mark.optional_native

CASES = [
    ("'{name}:{value}'.format(name='item', value=7)", "item:7"),
    ("'{} {label} {}'.format('a', 'b', label='x')", "a x b"),
    ("'{0[1]}:{1[key]}'.format(['a', 'b'], {'key': 3})", "b:3"),
    ("'{0.year}-{0.month}'.format(datetime.datetime(2026, 11, 1))", "2026-11"),
    ("'{0[items][0]}'.format({'items': [9]})", "9"),
    ("'{value!r}|{value!s}|{value!a}'.format(value='é')", "'é'|é|'\\xe9'"),
    ("'{number:0{width}d}'.format(number=7, width=4)", "0007"),
    ("'{0:{1}.{2}s}'.format('abcdef', 6, 3)", "abc   "),
    ("'{item!r:>{width}}'.format(item='x', width=5)", "  'x'"),
    ("'{{{name}}}'.format(name='x')", "{x}"),
    ("'{x}:{y[1]}'.format_map({'x': 4, 'y': [5, 6]})", "4:6"),
    ("'{value:>{width}}'.format_map({'value': 'x', 'width': 4})", "   x"),
    ("'{0[-1]}'.format({'-1': 'key'})", "key"),
    ("'{0[a:b]}'.format({'a:b': 'colon'})", "colon"),
    ("'{0[a!b]}'.format({'a!b': 'bang'})", "bang"),
    ("'{0[}]}'.format({'}': 'brace'})", "brace"),
    ("'{00}:{1}'.format('a', 'b')", "a:b"),
    ("'plain'.format_map(1)", "plain"),
    ("'{١}:{0[٢]}'.format([1, 2, 3], 'unicode')", "unicode:3"),
]


@pytest.mark.parametrize(("expression", "expected"), CASES)
def test_format_template_result(tmp_path, expression, expected):
    actual = run_case(
        {"id": "format_template", "source": f"@export\ndef probe():\n    return {expression}\n"},
        tmp_path,
    )
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode(expected), actual


@pytest.mark.parametrize(
    "expression",
    [
        "'{missing}'.format(x=1)",
        "'{0!q}'.format(1)",
        "'{0!rr}'.format(1)",
        "'{0:{1:{2}}}'.format(1, 2, 3)",
        "'{} {0}'.format(1)",
        "'{0} {}'.format(1)",
        "'{0[x]tail}'.format({'x': 1})",
        "'{0[]}'.format({})",
        "'{0[missing]}'.format({})",
        "'{x}'.format_map({})",
        "'{}'.format_map({})",
        "'{0}'.format_map({'0': 1})",
        "'x'.format_map({}, {})",
        "'x'.format_map(mapping={})",
    ],
)
def test_format_template_invalid(tmp_path, expression):
    actual = run_case(
        {"id": "format_invalid", "source": f"@export\ndef probe():\n    return {expression}\n"},
        tmp_path,
    )
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 1, actual


@pytest.mark.optional_native
@pytest.mark.parametrize("field", ["{0.__class__}", "{0._datetime}", "{0.year.__class__}"])
def test_template_fields_cannot_bypass_private_attribute_policy(tmp_path, field):
    actual = run_case(
        {
            "id": "format_private",
            "source": f"@export\ndef probe():\n    return {field!r}.format(datetime.datetime(2026, 1, 1))\n",
        },
        tmp_path,
    )
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 1, actual


def test_format_map_reads_hash_through_storage_boundary(tmp_path):
    actual = run_case(
        {
            "id": "format_hash",
            "source": "entries=Hash(default_value=0)\n@export\ndef probe():\n    entries['n']=7\n    return '{n}:{missing}'.format_map(entries)\n",
        },
        tmp_path,
    )
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode("7:0"), actual


def test_repeated_named_fields_use_exact_keyword_values(tmp_path):
    actual = run_case(
        {
            "id": "format_keywords",
            "source": "@export\ndef probe():\n    keywords={str(i): i for i in range(200)}\n    keywords['target']='x'\n    return ('{target}'*200).format(**keywords)\n",
        },
        tmp_path,
    )
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode("x" * 200), actual
