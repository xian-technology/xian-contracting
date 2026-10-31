"""Authored binary APIs and deterministic codec boundaries."""

import pytest

from tests.compatibility.runner import comparable, run_case

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


@pytest.mark.optional_native
@pytest.mark.parametrize("expression", _CASES)
def test_binary_method_matches_python(tmp_path, expression):
    # str checks bytes/bytearray and tuple/list result types as well as contents.
    source = "@export\ndef probe():\n    return str(" + expression + ")\n"
    case = {"id": "binary_method", "source": source}
    python = run_case(case, tmp_path / "python")
    native = run_case(case, tmp_path / "native", native=True)
    assert python["admission"] == "accepted" and python["status_code"] == 0
    assert comparable(native) == comparable(python)


@pytest.mark.optional_native
@pytest.mark.parametrize("operation", ["insert(1, 99)", "remove(98)", "reverse()"])
def test_bytearray_mutation_keeps_alias(tmp_path, operation):
    source = (
        "@export\ndef probe():\n    value=bytearray(b'ab')\n    alias=value\n"
        f"    result=value.{operation}\n    return [str(value),str(alias),result,alias is value]\n"
    )
    case = {"id": "binary_alias", "source": source}
    assert comparable(run_case(case, tmp_path / "native", native=True)) == comparable(
        run_case(case, tmp_path / "python")
    )


@pytest.mark.optional_native
@pytest.mark.parametrize("encoding", ["utf-8", "ascii", "latin-1"])
@pytest.mark.parametrize("errors", ["strict", "ignore", "replace", "backslashreplace"])
def test_binary_decode_error_policy_matches_python(tmp_path, encoding, errors):
    source = (
        f"@export\ndef probe():\n    return b'\\xe2\\x82X\\xff'.decode({encoding!r},{errors!r})\n"
    )
    case = {"id": "binary_decode", "source": source}
    assert comparable(run_case(case, tmp_path / "native", native=True)) == comparable(
        run_case(case, tmp_path / "python")
    )


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


def test_guarded_binary_factories_preserve_historical_class_surface():
    from contracting.stdlib.builtins import safe_bytearray, safe_bytes

    assert safe_bytes.maketrans(b"ab", b"xy") == bytes.maketrans(b"ab", b"xy")
    assert safe_bytearray.maketrans(b"ab", b"xy") == bytearray.maketrans(b"ab", b"xy")
    value = safe_bytearray.fromhex("41 42")
    assert type(value) is bytearray and value == b"AB"


def test_guarded_binary_factories_bound_inputs():
    from contracting.constants import MAX_BINARY_ALLOCATION_BYTES
    from contracting.stdlib.builtins import safe_bytearray, safe_bytes

    with pytest.raises(AssertionError, match="allocation"):
        safe_bytearray.fromhex("41" * (MAX_BINARY_ALLOCATION_BYTES + 1))
    for factory in (safe_bytes.maketrans, safe_bytearray.maketrans):
        with pytest.raises(AssertionError, match="allocation"):
            factory(
                b"a" * (MAX_BINARY_ALLOCATION_BYTES + 1), b"b" * (MAX_BINARY_ALLOCATION_BYTES + 1)
            )
