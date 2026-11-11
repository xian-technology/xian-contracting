"""Capture real application sequences with the pinned pre-VM installation."""

import argparse
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "compatibility" / "applications"
REVISION = "3b82001f2d587bbfb51f3d9235a2a8dcd0078a9a"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pinned_files(prefix):
    names = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", REVISION, prefix], cwd=ROOT, text=True
    ).splitlines()
    return {
        name[len(prefix) :]: subprocess.check_output(
            ["git", "show", REVISION + ":" + name], cwd=ROOT
        )
        for name in names
        if name.endswith(".py")
    }


def verify_package(directory, expected):
    actual = {
        str(path.relative_to(directory)): path.read_bytes() for path in directory.rglob("*.py")
    }
    if actual != expected:
        changed = sorted(
            name
            for name in actual.keys() | expected.keys()
            if actual.get(name) != expected.get(name)
        )
        raise ValueError(
            f"Historical executed package differs from pinned Git: {directory}: {changed}"
        )
    entries = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(actual.items())}
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()


def verify_oracle(directory):
    """Verify executed installations, not just an unused source checkout."""
    lock = subprocess.check_output(["git", "show", REVISION + ":uv.lock"], cwd=ROOT)
    if (directory / "uv.lock").read_bytes() != lock:
        raise ValueError("Historical dependency lock differs from pinned Git")
    python = directory / ".venv" / "bin" / "python"
    script = (
        "import contracting,xian_runtime_types,sys,json; "
        "print(json.dumps([sys.version.split()[0],contracting.__file__,xian_runtime_types.__file__]))"
    )
    version, *origins = json.loads(
        subprocess.check_output([str(python), "-c", script], cwd=directory, text=True)
    )
    if version != "3.12.10" or any(
        not Path(origin).is_relative_to(directory) for origin in origins
    ):
        raise ValueError(f"Unexpected historical interpreter/import: {version}, {origins}")
    prefixes = ["src/contracting/", "packages/xian-runtime-types/src/xian_runtime_types/"]
    hashes = {}
    for origin, prefix in zip(origins, prefixes, strict=True):
        expected = pinned_files(prefix)
        verify_package(directory / prefix, expected)
        hashes[Path(origin).parent.name] = verify_package(Path(origin).parent, expected)
    return python, hashes


def capture(directory):
    python, package_hashes = verify_oracle(directory)
    runner = ROOT / "tests" / "compatibility" / "application_runner.py"
    with tempfile.TemporaryDirectory(prefix="xian-app-capture-") as temporary:
        output = Path(temporary) / "observations.json"
        env = dict(os.environ, HOME=temporary)
        env.pop("PYTHONPATH", None)
        subprocess.run(
            [str(python), str(runner), "--engine", "historical-python", "--output", str(output)],
            cwd=directory,
            env=env,
            check=True,
            timeout=120,
        )
        observations = json.loads(output.read_text())
    files = ["manifest.json", "sequences.json"]
    return {
        "schema": 1,
        "revision": REVISION,
        "python": "3.12.10",
        "dependency_lock_sha256": digest(directory / "uv.lock"),
        "executed_package_sha256": package_hashes,
        "files_sha256": {name: digest(CORPUS / name) for name in files},
        "runner_sha256": digest(runner),
        "typed_encoder_sha256": digest(runner.with_name("runner.py")),
        "observations": observations,
    }


def fresh_capture(directory):
    archive = subprocess.check_output(["git", "archive", REVISION], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(archive)) as files:
        files.extractall(directory, filter="data")
    subprocess.run(
        ["uv", "sync", "--frozen", "--python", "3.12.10", "--no-editable"],
        cwd=directory,
        check=True,
    )
    return capture(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--oracle-directory",
        type=Path,
        help="Reuse an installation after verifying pinned source bytes",
    )
    parser.add_argument("--output", type=Path, default=CORPUS / "legacy_baseline.json")
    args = parser.parse_args()
    if args.oracle_directory:
        baseline = capture(args.oracle_directory.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix="xian-application-oracle-") as directory:
            baseline = fresh_capture(Path(directory))
    args.output.write_text(json.dumps(baseline, indent=2) + "\n")


if __name__ == "__main__":
    main()
