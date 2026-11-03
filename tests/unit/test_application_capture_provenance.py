"""A reused historical checkout cannot authenticate modified installed code."""

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def capture():
    path = Path(__file__).resolve().parents[2] / "scripts" / "capture-application-baseline.py"
    spec = importlib.util.spec_from_file_location("application_capture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("fault", ["changed", "extra", "missing"])
def test_executed_package_verification_rejects_modified_installs(tmp_path, capture, fault):
    expected = {"__init__.py": b"VALUE = 1\n", "decimal.py": b"PRECISION = 91\n"}
    for name, data in expected.items():
        (tmp_path / name).write_bytes(data)
    if fault == "changed":
        (tmp_path / "decimal.py").write_bytes(b"PRECISION = 28\n")
    elif fault == "extra":
        (tmp_path / "override.py").write_bytes(b"VALUE = 2\n")
    else:
        (tmp_path / "decimal.py").unlink()
    with pytest.raises(ValueError, match="differs from pinned Git"):
        capture.verify_package(tmp_path, expected)


def test_executed_package_digest_is_independent_of_directory_order(tmp_path, capture):
    expected = {"__init__.py": b"", "time.py": b"VALUE = 1\n"}
    for name in reversed(expected):
        (tmp_path / name).write_bytes(expected[name])
    first = capture.verify_package(tmp_path, expected)
    (tmp_path / "time.py").unlink()
    (tmp_path / "time.py").write_bytes(expected["time.py"])
    assert capture.verify_package(tmp_path, expected) == first
