"""Regenerate evidence using the pinned pre-VM checkout, never today's compiler."""

import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
from pathlib import Path

REVISION = "3b82001f2d587bbfb51f3d9235a2a8dcd0078a9a"
ROOT = Path(__file__).absolute().parents[1]
FIXTURES = ROOT / "tests" / "compatibility"


def capture(directory):
    archive = subprocess.check_output(["git", "archive", REVISION], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(archive)) as files:
        files.extractall(directory, filter="data")
    subprocess.run(
        ["uv", "sync", "--frozen", "--python", "3.12.10", "--no-editable"],
        cwd=directory,
        check=True,
    )
    python = directory / ".venv" / "bin" / "python"
    origin = subprocess.check_output(
        [str(python), "-c", "import contracting; print(contracting.__file__)"],
        cwd=directory,
        text=True,
    ).strip()
    if not Path(origin).is_relative_to(directory):
        raise RuntimeError(f"Oracle imported an unintended installation: {origin}")
    observations = directory / "observations.json"
    subprocess.run(
        [str(python), str(FIXTURES / "runner.py"), str(FIXTURES / "cases.json"), str(observations)],
        cwd=directory,
        check=True,
        timeout=120,
    )
    return {
        "revision": REVISION,
        "python": "3.12.10",
        "dependency_lock_sha256": hashlib.sha256((directory / "uv.lock").read_bytes()).hexdigest(),
        "cases_sha256": hashlib.sha256((FIXTURES / "cases.json").read_bytes()).hexdigest(),
        "runner_sha256": hashlib.sha256((FIXTURES / "runner.py").read_bytes()).hexdigest(),
        "observations": json.loads(observations.read_text()),
    }


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="xian-legacy-oracle-") as temporary:
        baseline = capture(Path(temporary))
    (FIXTURES / "legacy_baseline.json").write_text(json.dumps(baseline, indent=2) + "\n")
