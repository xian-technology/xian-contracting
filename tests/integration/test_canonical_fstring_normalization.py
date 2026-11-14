"""Use canonical Rust artifacts, not the Python-only local Driver compiler."""

import ast

import pytest

from contracting.artifacts import compile_contract_source
from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native


def execute_canonical(home, source, kwargs):
    from tests.vm_calls import execute_contract

    name = "con_string_probe"
    artifact = compile_contract_source(module_name=name, source=source)
    with Driver(storage_home=home) as driver:
        driver.set_contract(name=name, source=artifact["source"], vm_ir_json=artifact["vm_ir_json"])
        driver.commit()
        return artifact, execute_contract(
            driver=driver,
            contract_name=name,
            function_name="probe",
            kwargs=kwargs,
            context={"caller": "alice", "signer": "alice", "this": name},
            meter=True,
            chi_budget_raw=1_000_000,
        )


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("f\"{data['key']}\"", "hello"),
        ("f\"{value:{data['width']}}\"", "   7"),
        ("f\"{f'{value}'}\"", "7"),
        ("f\"line\\n\\t\\\\{data['key']} {{literal}}\"", "line\n\t\\hello {literal}"),
        ('f"{ {1: value} }"', "{1: 7}"),
        ('f"nul\\x00{value}"', "nul\x007"),
        ('f"control\\b{value}"', "control\b7"),
    ],
)
def test_canonical_interpolation_preserves_expression(tmp_path, expression, expected):
    source = (
        "@export\ndef probe(value: int):\n"
        "    data = {'key': 'hello', 'width': 4}\n"
        f"    return {expression}\n"
    )
    _, result = execute_canonical(tmp_path, source, {"value": 7})
    assert result.status_code == 0, result.result
    assert result.result == expected


@pytest.mark.parametrize(
    ("expression", "canonical_expression", "expected"),
    [
        ('f"value={value}"', "f'value={value}'", "value=7"),
        ('f"{{value}}={value}"', "f'{{value}}={value}'", "{value}=7"),
        ('f"slash\\\\n{value}"', "f'slash\\\\n{value}'", "slash\\n7"),
    ],
)
def test_established_canonical_source_result_and_chi_are_unchanged(
    tmp_path, expression, canonical_expression, expected
):
    source = f"@export\ndef probe(value: int):\n    return {expression}\n"
    artifact, result = execute_canonical(tmp_path, source, {"value": 7})
    assert (
        artifact["source"] == f"@export\ndef probe(value: int):\n    return {canonical_expression}"
    )
    assert result.status_code == 0, result.result
    assert result.result == expected
    # Captured with installed pre-fix native compiler+VM (runtime-current.json).
    assert result.chi_used == 10


@pytest.mark.parametrize(
    "literal",
    [
        '"""first\nC:\\\\new"""',
        '"""first\n\\x00"""',
        "'''first\ncontains \"\"\" and \\\\n'''",
    ],
)
def test_canonical_multiline_literal_keeps_python_value(tmp_path, literal):
    source = f"@export\ndef probe(value: int):\n    {literal}\n    return value\n"
    artifact, result = execute_canonical(tmp_path, source, {"value": 7})
    assert ast.dump(ast.parse(artifact["source"]), include_attributes=False) == ast.dump(
        ast.parse(source), include_attributes=False
    )
    assert result.status_code == 0, result.result
    assert result.result == 7


@pytest.mark.parametrize("count", range(1, 7))
@pytest.mark.parametrize("prefix", ["", "    marker = 1\n"])
def test_canonical_multiline_trailing_quotes_preserve_value(tmp_path, count, prefix):
    quotes = '"' * count
    source = (
        "@export\ndef probe(value: int):\n"
        f"{prefix}    '''first\nends{quotes}'''\n"
        "    return value\n"
    )
    artifact, result = execute_canonical(tmp_path, source, {"value": 7})
    assert ast.dump(ast.parse(artifact["source"]), include_attributes=False) == ast.dump(
        ast.parse(source), include_attributes=False
    )
    assert result.status_code == 0, result.result
    assert result.result == 7
