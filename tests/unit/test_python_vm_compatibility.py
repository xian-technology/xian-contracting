from __future__ import annotations

from pathlib import Path

from contracting.compilation.python_compatibility import (
    PythonVmCompatibilityChecker,
    iter_authored_contract_sources,
    module_name_from_path,
)
from scripts.audit_python_vm_compatibility import main


def test_python_vm_compatibility_accepts_valid_contract() -> None:
    checker = PythonVmCompatibilityChecker()
    report = checker.check(
        "@export\ndef ping():\n    return 'pong'\n",
        module_name="con_probe",
    )

    assert report.compatible
    assert report.issues == ()


def test_python_vm_compatibility_rejects_invalid_contract() -> None:
    checker = PythonVmCompatibilityChecker()
    report = checker.check(
        "def broken(:\n    return 1\n",
        module_name="con_broken",
    )

    assert not report.compatible
    assert report.issues[0].stage == "normalize_source"


def test_iter_authored_contract_sources_ignores_non_contract_files(
    tmp_path: Path,
) -> None:
    contract_path = tmp_path / "con_probe.py"
    contract_path.write_text("@export\ndef ping():\n    return 'pong'\n")
    test_path = tmp_path / "tests" / "test_probe.py"
    test_path.parent.mkdir()
    test_path.write_text("def test_probe():\n    pass\n")

    discovered = iter_authored_contract_sources([tmp_path])

    assert discovered == [contract_path]
    assert module_name_from_path(contract_path) == "con_probe"


def test_audit_python_vm_compatibility_main_returns_failure_for_bad_source(
    tmp_path: Path,
) -> None:
    bad_path = tmp_path / "con_bad.py"
    bad_path.write_text("def broken(:\n    return 1\n", encoding="utf-8")

    exit_code = main([str(tmp_path), "--fail-on-issues"])

    assert exit_code == 1
