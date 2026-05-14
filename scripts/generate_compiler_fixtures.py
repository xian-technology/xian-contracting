#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from contracting.compilation.vm import (
    SUPPORTED_VM_PROFILES,
    iter_contract_sources,
)
from contracting.compiler.fixtures import (
    build_compiler_fixture_from_path,
    write_compiler_fixture,
)

DEFAULT_OUTPUT_DIR = Path("packages/xian-compiler-core/tests/fixtures")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate compiler fixtures from the current Python compiler output."
        )
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="contract source files or directories to include",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="directory that receives one JSON fixture per source",
    )
    parser.add_argument(
        "--profile",
        default=SUPPORTED_VM_PROFILES[0],
        choices=sorted(SUPPORTED_VM_PROFILES),
        help="VM profile to compile for",
    )
    parser.add_argument(
        "--no-lint",
        action="store_true",
        help="skip lint checks while generating fixtures",
    )
    parser.add_argument(
        "--fail-on-rejected",
        action="store_true",
        help="exit with code 1 if any generated fixture is rejected",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    input_paths = [Path(raw).resolve() for raw in args.paths]
    source_paths = iter_contract_sources(input_paths)

    written: list[str] = []
    rejected: list[str] = []
    output_dir = args.output_dir.resolve()

    for source_path in source_paths:
        fixture = build_compiler_fixture_from_path(
            source_path,
            vm_profile=args.profile,
            lint=not args.no_lint,
        )
        output_path = output_dir / f"{fixture['name']}.json"
        write_compiler_fixture(output_path, fixture)
        written.append(str(output_path))
        if not fixture["expected"]["accepted"]:
            rejected.append(str(source_path))

    print(
        json.dumps(
            {
                "schema": "xian.compiler_fixture_generation.v1",
                "vm_profile": args.profile,
                "sources": len(source_paths),
                "written": written,
                "rejected": rejected,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if args.fail_on_rejected and rejected else 0


if __name__ == "__main__":
    raise SystemExit(main())
