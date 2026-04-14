from __future__ import annotations

from pathlib import Path

from contracting.compilation.authored_conformance import (
    AuthoredConformanceAuditor,
)
from scripts.audit_authored_conformance import main


def test_authored_conformance_accepts_covered_contract_surface() -> None:
    auditor = AuthoredConformanceAuditor()
    report = auditor.check(
        """
import con_child

payload = Variable()

@construct
def seed():
    payload.set(1)

@export(typecheck=True)
def probe(value: int):
    assert value > 0
    return {
        "ctx": ctx.caller,
        "seen": con_child.lookup(account=ctx.caller),
    }
""",
        module_name="con_probe",
    )

    assert report.compatible
    assert "imports.static" in report.used_features
    assert "decorators.construct" in report.used_features
    assert "decorators.export.typecheck" in report.used_features
    assert report.missing_features == ()


def test_authored_conformance_reports_uncovered_tracked_features() -> None:
    auditor = AuthoredConformanceAuditor()
    auditor._covered_features.clear()

    report = auditor.check(
        """
import con_child

@export
def probe():
    raise Exception("boom")
""",
        module_name="con_probe",
    )

    assert not report.compatible
    assert report.missing_features == (
        "decorators.export",
        "imports.static",
        "syntax.raise",
    )


def test_authored_conformance_tracks_exact_method_features() -> None:
    auditor = AuthoredConformanceAuditor()
    report = auditor.check(
        """
@export
def probe():
    values = ["Alpha"]
    values.append("Beta")
    return {
        "lower": "MIXED".lower(),
        "joined": "-".join(values),
    }
""",
        module_name="con_probe",
    )

    assert report.compatible
    assert "methods.list.append" in report.used_features
    assert "methods.string.lower" in report.used_features
    assert "methods.string.join" in report.used_features


def test_audit_authored_conformance_main_returns_success_for_covered_contract(
    tmp_path: Path,
) -> None:
    contract_path = tmp_path / "con_probe.py"
    contract_path.write_text(
        "import con_child\n\n@export\ndef probe():\n    raise Exception('boom')\n",
        encoding="utf-8",
    )

    exit_code = main([str(tmp_path), "--fail-on-issues"])

    assert exit_code == 0
