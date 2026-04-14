#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from contracting.compilation.python_compatibility import (
    PythonVmCompatibilityChecker,
    iter_authored_contract_sources,
    module_name_from_path,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Audit authored contract sources for Python VM executability."
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
        help="exit with code 1 when incompatible contracts are found",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    checker = PythonVmCompatibilityChecker()
    paths = [Path(raw).resolve() for raw in args.paths]
    contract_paths = iter_authored_contract_sources(paths)

    issues_by_file: list[dict[str, object]] = []
    compatible_files = 0

    for path in contract_paths:
        report = checker.check(
            path.read_text(encoding="utf-8"),
            module_name=module_name_from_path(path),
        )
        if report.compatible:
            compatible_files += 1
            continue
        issues_by_file.append(
            {
                "path": str(path),
                "report": report.to_dict(),
            }
        )

    payload = {
        "files_scanned": len(contract_paths),
        "compatible_files": compatible_files,
        "incompatible_files": len(issues_by_file),
        "issues_by_file": issues_by_file,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    if args.fail_on_issues and issues_by_file:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
