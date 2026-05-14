from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_compiler_core_matches_python_reference_contract_corpus() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/audit_compiler_core_parity.py",
            "--lint-mode",
            "both",
            "--fail-on-mismatch",
        ],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
