#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from contracting.compilation.authored_conformance import (
    AuthoredConformanceAuditor,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Audit authored contract sources against the Python-vs-Xian-VM "
            "conformance matrix."
        )
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="contract file or directory paths to scan",
    )
    parser.add_argument(
        "--fail-on-issues",
        action="store_true",
        help="exit with code 1 when uncovered authored-contract features are found",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    auditor = AuthoredConformanceAuditor()
    paths = [Path(raw).resolve() for raw in args.paths]
    reports = auditor.audit_paths(paths)
    issues_by_file = [report.to_dict() for report in reports if not report.compatible]
    payload = {
        "files_scanned": len(reports),
        "compatible_files": sum(report.compatible for report in reports),
        "incompatible_files": len(issues_by_file),
        "issues_by_file": issues_by_file,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    if args.fail_on_issues and issues_by_file:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
