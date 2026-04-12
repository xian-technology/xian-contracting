#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from contracting.compilation.compiler import ContractingCompiler
from contracting.compilation.vm import (
    SUPPORTED_VM_PROFILES,
    iter_contract_sources,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit contract sources against the current VM IR lowerer."
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
        help="exit with code 1 when lowering issues are found",
    )
    return parser


def infer_module_name(path: Path) -> str:
    name = path.name
    if name.endswith(".s.py"):
        return name[: -len(".s.py")]
    return path.stem


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = [Path(raw).resolve() for raw in args.paths]
    contract_paths = iter_contract_sources(paths)

    host_counts: Counter[str] = Counter()
    issues_by_file: list[dict[str, object]] = []
    lowered_files = 0

    for path in contract_paths:
        compiler = ContractingCompiler(module_name=infer_module_name(path))
        source = path.read_text(encoding="utf-8")
        try:
            ir = compiler.lower_to_ir(source, vm_profile=args.profile)
        except Exception as exc:
            issues_by_file.append(
                {
                    "path": str(path),
                    "error": str(exc),
                }
            )
            continue

        lowered_files += 1
        for dependency in ir["host_dependencies"]:
            host_counts[dependency["id"]] += 1

    payload = {
        "profile": args.profile,
        "files_scanned": len(contract_paths),
        "lowered_files": lowered_files,
        "failed_files": len(issues_by_file),
        "host_dependency_counts": dict(sorted(host_counts.items())),
        "issues_by_file": issues_by_file,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    if args.fail_on_issues and issues_by_file:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
