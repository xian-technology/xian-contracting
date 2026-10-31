#!/usr/bin/env python3
"""Print the reviewed surface inventory; this is not a test execution result."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.surface.catalog import coverage_report  # noqa: E402

if __name__ == "__main__":
    report = coverage_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["discovery_matches"] else 1)
