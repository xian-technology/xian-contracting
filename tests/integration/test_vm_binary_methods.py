"""Authored binary APIs and deterministic codec boundaries."""

import pytest

from tests.compatibility.runner import encode, run_case

_CASES = [
    "b'abc'.decode()",
    "b'ababa'.find(b'ba', 2)",
    "b'ababa'.rfind(b'ba')",
    "b'ababa'.count(97)",
    "b'abc'.startswith((b'x', b'a'))",
    "b'abc'.endswith(b'c')",
    "b'a,b,c'.split(b',', maxsplit=1)",
    "b'a,b,c'.rsplit(b',', 1)",
    "b' a b '.split(None, 0)",
    "b' a b '.rsplit(None, 0)",
    r"b'a\r\nb\rc\n'.splitlines(keepends=True)",
    "b'a=b=c'.partition(b'=')",
    "b'a=b=c'.rpartition(b'=')",
    "b' x '.strip()",
    "b'xxabxx'.lstrip(b'x')",
    "b'xxabxx'.rstrip(b'x')",
    "b'abc'.removeprefix(b'a')",
    "b'abc'.removesuffix(b'c')",
    "b'a'.center(4, b'.')",
    "b'a'.ljust(3, b'.')",
    "b'a'.rjust(3, b'.')",
    "b'-1'.zfill(4)",
    "b'a\tb'.expandtabs(tabsize=4)",
    "b'aBc'.swapcase()",
    "b'hELLO wORLD'.title()",
    "b'hELLO'.capitalize()",
    "b'ABC'.lower()",
    "b'abc'.upper()",
    "b'AB12'.isalnum()",
    "b'ABC'.isalpha()",
    "b'123'.isdigit()",
    "b'abc'.islower()",
    "b'ABC'.isupper()",
    "b'Hello World'.istitle()",
    "b' \t'.isspace()",
    "b'abc'.isascii()",
    "b'-'.join([b'a', bytearray(b'b')])",
    "b'ab'.replace(b'', b'-', 2)",
    "b'abc'.translate(None, delete=b'b')",
    "b'abc'.translate(b''.maketrans(b'ab', b'xy'))",
    "b'ABCDE'.hex(sep=':', bytes_per_sep=-2)",
    "bytearray().fromhex('41 42')",
    "bytearray(b'abc').replace(b'b', b'xy')",
    "bytearray(b'a,b').split(b',')",
    "bytearray(b'ab').partition(b'b')",
]


_EXPECTED = [
    "abc",
    3,
    3,
    3,
    True,
    True,
    [b"a", b"b,c"],
    [b"a,b", b"c"],
    [b"a b "],
    [b" a b"],
    [b"a\r\n", b"b\r", b"c\n"],
    (b"a", b"=", b"b=c"),
    (b"a=b", b"=", b"c"),
    b"x",
    b"abxx",
    b"xxab",
    b"bc",
    b"ab",
    b".a..",
    b"a..",
    b"..a",
    b"-001",
    b"a   b",
    b"AbC",
    b"Hello World",
    b"Hello",
    b"abc",
    b"ABC",
    True,
    True,
    True,
    True,
    True,
    True,
    True,
    True,
    b"a-b",
    b"-a-b",
    b"ac",
    b"xyc",
    "4142:4344:45",
    bytearray(b"AB"),
    bytearray(b"axyc"),
    [bytearray(b"a"), bytearray(b"b")],
    (bytearray(b"a"), bytearray(b"b"), bytearray()),
]


@pytest.mark.optional_native
@pytest.mark.parametrize("expression,expected", list(zip(_CASES, _EXPECTED, strict=True)))
def test_binary_methods_match_explicit_values(tmp_path, expression, expected):
    # Rendering observes bytes/bytearray and tuple/list types as well as contents.
    source = "@export\ndef probe():\n    return str(" + expression + ")\n"
    actual = run_case({"id": "binary_method", "source": source}, tmp_path)
    assert actual["admission"] == "accepted" and actual["status_code"] == 0
    assert actual["result"] == encode(str(expected))
    assert actual["writes"] == encode({}) and actual["events"] == encode([])


@pytest.mark.optional_native
@pytest.mark.parametrize(
    "operation,expected", [("insert(1, 99)", b"acb"), ("remove(98)", b"a"), ("reverse()", b"ba")]
)
def test_bytearray_mutation_keeps_alias(tmp_path, operation, expected):
    source = (
        "@export\ndef probe():\n    value=bytearray(b'ab')\n    alias=value\n"
        f"    result=value.{operation}\n    return [str(value),str(alias),result,alias is value]\n"
    )
    actual = run_case({"id": "binary_alias", "source": source}, tmp_path)
    assert actual["status_code"] == 0, actual
    rendered = str(bytearray(expected))
    assert actual["result"] == encode([rendered, rendered, None, True])
    assert actual["writes"] == encode({}) and actual["events"] == encode([])


_DECODE_EXPECTED = {
    "utf-8": {
        "strict": None,
        "ignore": "X",
        "replace": "\ufffdX\ufffd",
        "backslashreplace": "\\xe2\\x82X\\xff",
    },
    "ascii": {
        "strict": None,
        "ignore": "X",
        "replace": "\ufffd\ufffdX\ufffd",
        "backslashreplace": "\\xe2\\x82X\\xff",
    },
    "latin-1": {
        error: "\u00e2\u0082X\u00ff"
        for error in ("strict", "ignore", "replace", "backslashreplace")
    },
}


@pytest.mark.optional_native
@pytest.mark.parametrize("encoding", ["utf-8", "ascii", "latin-1"])
@pytest.mark.parametrize("errors", ["strict", "ignore", "replace", "backslashreplace"])
def test_binary_decode_matches_explicit_codec_policy(tmp_path, encoding, errors):
    source = (
        f"@export\ndef probe():\n    return b'\\xe2\\x82X\\xff'.decode({encoding!r},{errors!r})\n"
    )
    actual = run_case({"id": "binary_decode", "source": source}, tmp_path)
    expected = _DECODE_EXPECTED[encoding][errors]
    assert actual["admission"] == "accepted", actual
    assert actual["status_code"] == (1 if expected is None else 0), actual
    assert actual["writes"] == encode({}) and actual["events"] == encode([])
    if expected is not None:
        assert actual["result"] == encode(expected), actual


@pytest.mark.optional_native
@pytest.mark.parametrize(
    "expression", ["b'a'.decode('utf-16')", "b'a'.decode('utf8','surrogateescape')"]
)
def test_binary_rejects_codecs_outside_deterministic_policy(tmp_path, expression):
    result = run_case(
        {
            "id": "binary_codec_policy",
            "source": "@export\ndef probe():\n    return " + expression + "\n",
        },
        tmp_path,
        native=True,
    )
    assert result["admission"] == "accepted" and result["status_code"] == 1
    assert "unsupported deterministic" in result["diagnostic"]


@pytest.mark.optional_native
def test_native_binary_factories_preserve_class_result_types(tmp_path):
    source = """@export
def probe():
    return [bytes.maketrans(b'ab',b'xy'),bytearray.maketrans(b'ab',b'xy'),bytearray.fromhex('41 42')]
"""
    actual = run_case({"id": "binary_factories", "source": source}, tmp_path)
    table = bytes.maketrans(b"ab", b"xy")
    assert actual["status_code"] == 0, actual
    assert actual["result"] == encode([table, table, bytearray(b"AB")])


@pytest.mark.optional_native
@pytest.mark.parametrize("constructor", ["bytes", "bytearray"])
def test_native_binary_factories_bound_hex_output(tmp_path, constructor):
    from contracting.constants import MAX_BINARY_ALLOCATION_BYTES
    from tests.integration.test_vm_language_conformance import _run_native_case

    case = {
        "id": "binary_factory_limit",
        "function_name": "probe",
        "source": f"@export\ndef probe(text: str):\n    return len({constructor}.fromhex(text))\n",
        "kwargs": {"text": "41" * (MAX_BINARY_ALLOCATION_BYTES + 1)},
    }
    actual = _run_native_case(case, tmp_path)
    assert actual["status_code"] == 1, actual
    assert "allocation" in str(actual["result"]), actual
    assert actual["writes"] == {} and actual["events"] == []
