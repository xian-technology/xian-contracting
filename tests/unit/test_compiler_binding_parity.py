from __future__ import annotations

import json
from pathlib import Path

import pytest
import xian_compiler_core

FIXTURE_DIR = (
    Path(__file__).resolve().parents[2]
    / "packages"
    / "xian-compiler-core"
    / "tests"
    / "fixtures"
)


@pytest.mark.parametrize("fixture_path", sorted(FIXTURE_DIR.glob("*.json")))
def test_python_binding_matches_shared_compiler_fixture(fixture_path: Path) -> None:
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    diagnostics = xian_compiler_core.diagnose_contract(
        fixture["module_name"],
        fixture["input_source"],
        lint=True,
        vm_profile=fixture["vm_profile"],
    )
    assert diagnostics == fixture["diagnostics"]

    if fixture["expected"]["accepted"]:
        artifact = xian_compiler_core.compile_contract_artifact(
            fixture["module_name"],
            fixture["input_source"],
            lint=True,
            vm_profile=fixture["vm_profile"],
        )
        assert artifact == fixture["artifact"]
    else:
        with pytest.raises(xian_compiler_core.CompilerError):
            xian_compiler_core.compile_contract_artifact(
                fixture["module_name"],
                fixture["input_source"],
                lint=True,
                vm_profile=fixture["vm_profile"],
            )


def _limits() -> dict[str, int]:
    return xian_compiler_core.compiler_version()["limits"]


def _diagnostic_code(source: str) -> str:
    diagnostics = xian_compiler_core.diagnose_contract("con_limit", source)
    assert len(diagnostics) == 1
    return diagnostics[0]["code"]


def test_python_binding_enforces_source_byte_limit() -> None:
    assert _diagnostic_code("a" * (_limits()["max_source_bytes"] + 1)) == (
        "xian.limit.source_bytes"
    )


def test_python_binding_enforces_total_token_limit() -> None:
    source = "a=0\n" * ((_limits()["max_tokens"] // 4) + 1)
    assert _diagnostic_code(source) == "xian.limit.tokens"


def test_python_binding_enforces_logical_line_token_limit() -> None:
    source = f"value = {'not ' * _limits()['max_logical_line_tokens']}True\n"
    assert _diagnostic_code(source) == "xian.limit.logical_line_tokens"


def test_python_binding_enforces_syntax_node_limit() -> None:
    source = "a=0\n" * ((_limits()["max_syntax_nodes"] // 3) + 1)
    assert _diagnostic_code(source) == "xian.limit.syntax_nodes"


def test_python_binding_enforces_syntax_depth_limit() -> None:
    source = (
        "@export\ndef value():\n    return "
        + ("not " * _limits()["max_syntax_depth"])
        + "True\n"
    )
    assert _diagnostic_code(source) == "xian.limit.syntax_depth"
