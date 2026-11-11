"""Regenerate evidence using the pinned pre-VM checkout, never today's compiler."""

import argparse
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

REVISION = "3b82001f2d587bbfb51f3d9235a2a8dcd0078a9a"
ROOT = Path(__file__).absolute().parents[1]
FIXTURES = ROOT / "tests" / "compatibility"
OBSERVER = FIXTURES / "historical" / "runner.py"


def capture(directory):
    baseline = json.loads((FIXTURES / "legacy_baseline.json").read_text())
    if hashlib.sha256(OBSERVER.read_bytes()).hexdigest() != baseline["runner_sha256"]:
        raise ValueError("Archived language observer digest mismatch")
    archive = subprocess.check_output(["git", "archive", REVISION], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(archive)) as files:
        files.extractall(directory, filter="data")
    subprocess.run(
        ["uv", "sync", "--frozen", "--python", "3.12.10", "--no-editable"],
        cwd=directory,
        check=True,
    )
    python = directory / ".venv" / "bin" / "python"
    home = directory / "observer-home"
    home.mkdir()
    env = dict(os.environ, HOME=str(home))
    env.pop("PYTHONPATH", None)
    origin = subprocess.check_output(
        [str(python), "-c", "import contracting; print(contracting.__file__)"],
        cwd=directory,
        env=env,
        text=True,
    ).strip()
    if not Path(origin).is_relative_to(directory):
        raise RuntimeError(f"Oracle imported an unintended installation: {origin}")
    observations = directory / "observations.json"
    subprocess.run(
        [str(python), str(OBSERVER), str(FIXTURES / "cases.json"), str(observations)],
        cwd=directory,
        env=env,
        check=True,
        timeout=120,
    )
    return {
        "revision": REVISION,
        "python": "3.12.10",
        "dependency_lock_sha256": hashlib.sha256((directory / "uv.lock").read_bytes()).hexdigest(),
        "cases_sha256": hashlib.sha256((FIXTURES / "cases.json").read_bytes()).hexdigest(),
        "runner_sha256": hashlib.sha256(OBSERVER.read_bytes()).hexdigest(),
        "observations": json.loads(observations.read_text()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=FIXTURES / "legacy_baseline.json")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="xian-legacy-oracle-") as temporary:
        baseline = capture(Path(temporary))
    args.output.write_text(json.dumps(baseline, indent=2) + "\n")


if __name__ == "__main__":
    main()
