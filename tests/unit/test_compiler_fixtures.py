from __future__ import annotations

import json

from contracting.compiler.fixtures import (
    COMPILER_FIXTURE_SCHEMA_V1,
    build_compiler_fixture,
    fixture_name_for_module,
)


def test_build_compiler_fixture_records_artifact_contract() -> None:
    source = """
counter = Variable()

@export
def get():
    return counter.get()
"""

    fixture = build_compiler_fixture(
        module_name="con_counter",
        source=source,
        lint=False,
    )

    assert fixture["schema"] == COMPILER_FIXTURE_SCHEMA_V1
    assert fixture["expected"] == {"accepted": True}
    assert fixture["module_name"] == "con_counter"
    assert fixture["normalized_source"] == fixture["artifact"]["source"]
    assert fixture["artifact"]["module_name"] == "con_counter"
    assert fixture["artifact"]["vm_profile"] == "xian_vm_v1"
    assert fixture["artifact"]["hashes"]["source_sha256"]
    assert fixture["artifact"]["hashes"]["vm_ir_sha256"]
    assert json.loads(fixture["artifact"]["vm_ir_json"]) == fixture["vm_ir"]


def test_build_compiler_fixture_records_rejection() -> None:
    fixture = build_compiler_fixture(
        module_name="con_bad",
        source="def broken(:\n",
        lint=False,
    )

    assert fixture["expected"] == {"accepted": False}
    assert fixture["diagnostics"][0]["severity"] == "error"
    assert fixture["diagnostics"][0]["code"] in {
        "python_contracting.CompilerError",
        "python_contracting.SyntaxError",
    }
    assert "artifact" not in fixture


def test_fixture_name_for_module_is_filesystem_safe() -> None:
    assert fixture_name_for_module("con-demo.contract") == "con_demo_contract"
