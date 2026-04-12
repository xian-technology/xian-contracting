#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from contracting.compilation.vm import (
    SUPPORTED_VM_PROFILES,
    VmCompatibilityChecker,
    iter_contract_sources,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit contract sources against a VM compatibility profile."
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="contract file or directory paths to scan",
    )
    parser.add_argument(
        "--profile",
        default=SUPPORTED_VM_PROFILES[0],
        choices=sorted(SUPPORTED_VM_PROFILES),
        help="VM validation profile to use",
    )
    parser.add_argument(
        "--fail-on-issues",
        action="store_true",
        help="exit with code 1 when incompatible contracts are found",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    checker = VmCompatibilityChecker()
    paths = [Path(raw).resolve() for raw in args.paths]
    contract_paths = iter_contract_sources(paths)

    feature_counts: Counter[str] = Counter()
    issues_by_file: list[dict[str, object]] = []
    compatible_files = 0

    for path in contract_paths:
        source = path.read_text(encoding="utf-8")
        report = checker.check(source, profile=args.profile)
        feature_counts.update(report.feature_counts)
        if report.compatible:
            compatible_files += 1
            continue
        issues_by_file.append(
            {
                "path": str(path),
                "errors": [error.to_dict() for error in report.errors],
            }
        )

    payload = {
        "profile": args.profile,
        "files_scanned": len(contract_paths),
        "compatible_files": compatible_files,
        "incompatible_files": len(issues_by_file),
        "feature_counts": dict(sorted(feature_counts.items())),
        "issues_by_file": issues_by_file,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    if args.fail_on_issues and issues_by_file:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
