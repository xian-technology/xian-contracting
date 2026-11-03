"""New bounded workflows over byte-identical, published pre-VM applications."""

import hashlib
import json

import pytest

from tests.compatibility.application_expectations import expected_current
from tests.compatibility.application_runner import FIXTURES, comparison, fixtures, run_sequence

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
        assert hashlib.sha256((FIXTURES.parent / name).read_bytes()).hexdigest() == BASELINE[key]
    assert set(BASELINE["observations"]) == {case["id"] for case in SEQUENCES}
    assert all(len(case["steps"]) <= 64 for case in SEQUENCES)


@pytest.mark.parametrize(
    "engine",
    [
        "python",
        pytest.param("native", marks=pytest.mark.optional_native),
        pytest.param("native-metered", marks=pytest.mark.optional_native),
    ],
)
@pytest.mark.parametrize("sequence", SEQUENCES, ids=lambda item: item["id"])
def test_published_application_sequence(tmp_path, sequence, engine):
    actual = {sequence["id"]: run_sequence(sequence, SOURCES, tmp_path, engine)}
    expected = {sequence["id"]: BASELINE["observations"][sequence["id"]]}
    deviations = json.loads((FIXTURES / "current_policy_deviations.json").read_text())
    expected, _ = expected_current(expected, deviations)
    assert comparison(actual) == comparison(expected)
