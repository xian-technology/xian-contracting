"""Provenance of the published pre-VM application corpus.

The applications are V1 contracts (floats among others). Current code no
longer executes V1 (single-engine plan, decision 6); their sequences replay
on the pinned release.
"""

import hashlib
import json


from tests.compatibility.application_runner import FIXTURES, fixtures

MANIFEST, SOURCES, SEQUENCES = fixtures()
BASELINE = json.loads((FIXTURES / "legacy_baseline.json").read_text())


def test_application_baseline_provenance():
    assert BASELINE["revision"] == MANIFEST["runtime_revision"]
    assert BASELINE["python"] == "3.12.10"
    for name, expected in BASELINE["files_sha256"].items():
        assert hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() == expected
    for name, key in [
        ("application_runner.py", "runner_sha256"),
        ("runner.py", "typed_encoder_sha256"),
    ]:
        assert (
            hashlib.sha256((FIXTURES.parent / "historical" / name).read_bytes()).hexdigest()
            == BASELINE[key]
        )
    assert set(BASELINE["observations"]) == {case["id"] for case in SEQUENCES}
    assert all(len(case["steps"]) <= 64 for case in SEQUENCES)
