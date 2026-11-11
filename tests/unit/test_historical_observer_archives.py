"""Historical captures retain their exact observers outside maintained execution."""

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from tests.compatibility import application_runner, runner

ROOT = Path(__file__).resolve().parents[2]
COMPATIBILITY = ROOT / "tests" / "compatibility"
ARCHIVE = COMPATIBILITY / "historical"


def test_archived_observers_match_the_existing_capture_hashes():
    language = json.loads((COMPATIBILITY / "legacy_baseline.json").read_text())
    applications = json.loads((COMPATIBILITY / "applications/legacy_baseline.json").read_text())
    for filename, expected in (
        ("runner.py", language["runner_sha256"]),
        ("runner.py", applications["typed_encoder_sha256"]),
        ("application_runner.py", applications["runner_sha256"]),
    ):
        assert hashlib.sha256((ARCHIVE / filename).read_bytes()).hexdigest() == expected


@pytest.mark.parametrize("engine", ["python", "historical-python", "invalid"])
def test_current_application_observer_rejects_non_native_engines_before_storage(tmp_path, engine):
    existing = set(tmp_path.rglob("*"))
    with pytest.raises(ValueError, match="native"):
        application_runner.run_sequence({}, {}, tmp_path, engine)
    assert set(tmp_path.rglob("*")) == existing


def test_current_language_observer_rejects_python_before_storage(tmp_path):
    existing = set(tmp_path.rglob("*"))
    with pytest.raises(ValueError, match="native"):
        runner.run_case({}, tmp_path, native=False)
    assert set(tmp_path.rglob("*")) == existing


def test_capture_stages_immutable_observers_and_original_corpus(tmp_path):
    path = ROOT / "scripts" / "capture-application-baseline.py"
    spec = importlib.util.spec_from_file_location("historical_application_capture", path)
    capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capture)
    staged = capture.stage_observer(tmp_path)
    assert staged == tmp_path / "application_runner.py"
    for name in ("application_runner.py", "runner.py", "application_expectations.py"):
        assert (tmp_path / name).read_bytes() == (ARCHIVE / name).read_bytes()
    for name in ("manifest.json", "sequences.json"):
        assert (tmp_path / "applications" / name).read_bytes() == (
            COMPATIBILITY / "applications" / name
        ).read_bytes()


@pytest.mark.parametrize(
    "name", ["application_runner.py", "runner.py", "application_expectations.py"]
)
def test_capture_rejects_modified_archived_observer(tmp_path, monkeypatch, name):
    path = ROOT / "scripts" / "capture-application-baseline.py"
    spec = importlib.util.spec_from_file_location("tampered_application_capture", path)
    capture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(capture)
    archive = tmp_path / "archive"
    shutil.copytree(ARCHIVE, archive)
    (archive / name).write_text("raise RuntimeError('modified observer')\n")
    monkeypatch.setattr(capture, "ARCHIVE", archive)
    staged = tmp_path / "staged"
    staged.mkdir()
    with pytest.raises(ValueError, match="observer digest mismatch"):
        capture.stage_observer(staged)
