#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import xian_compiler_core

from contracting.compilation.compiler import ContractingCompiler
from contracting.compilation.vm import XIAN_VM_V1_PROFILE
from contracting.compiler.fixtures import infer_module_name

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT.parent

DEFAULT_ROOTS = (
    REPO_ROOT / "src/contracting/contracts",
    REPO_ROOT / "tests/integration/test_contracts",
    REPO_ROOT / "tests/performance/test_contracts",
    REPO_ROOT / "tests/security/contracts",
    REPO_ROOT / "tests/unit/contracts",
    REPO_ROOT / "tests/unit/test_sys_contracts",
    REPO_ROOT / "packages/xian-compiler-core/tests/sources",
    WORKSPACE_ROOT / "xian-abci/tests/integration/contracts",
    WORKSPACE_ROOT / "xian-configs/contracts",
    WORKSPACE_ROOT / "xian-configs/contract-packs",
    WORKSPACE_ROOT / "xian-configs/examples",
    WORKSPACE_ROOT / "xian-configs/templates",
    WORKSPACE_ROOT / "xian-contracts/contracts",
    WORKSPACE_ROOT / "xian-dex/src",
    WORKSPACE_ROOT / "xian-stable-protocol/contracts",
    WORKSPACE_ROOT / "xian-stack/workloads",
    WORKSPACE_ROOT / "xian-tg-bot/plg",
)

EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "site-packages",
        "target",
    }
)

CONTRACT_ARTIFACT_FORMAT_V1 = "xian_contract_artifact_v1"


@dataclass(frozen=True, slots=True)
class CompileResult:
    ok: bool
    artifact: dict[str, Any] | None = None
    error_type: str | None = None
    error_message: str | None = None


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_contract_source(path: Path) -> bool:
    name = path.name
    return name.endswith(".s.py") or (
        name.startswith("con_") and name.endswith(".py")
    )


def _is_excluded(path: Path) -> bool:
    return bool(EXCLUDED_PARTS.intersection(path.parts))


def discover_contract_sources(paths: list[Path]) -> list[Path]:
    discovered: list[Path] = []
    seen: set[Path] = set()
    for root in paths:
        root = root.resolve()
        if not root.exists() or _is_excluded(root):
            continue
        candidates = [root] if root.is_file() else sorted(root.rglob("*.py"))
        for candidate in candidates:
            if _is_excluded(candidate) or not _is_contract_source(candidate):
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            discovered.append(candidate)
    return discovered


def compile_with_python(
    *,
    module_name: str,
    source: str,
    lint: bool,
    vm_profile: str,
) -> CompileResult:
    try:
        compiler = ContractingCompiler(module_name=module_name)
        normalized_source = compiler.normalize_source(
            source,
            lint=lint,
            vm_profile=vm_profile,
        )
        vm_ir_json = compiler.lower_to_ir_json(
            normalized_source,
            lint=False,
            vm_profile=vm_profile,
            indent=None,
            sort_keys=True,
        )
        artifact = {
            "format": CONTRACT_ARTIFACT_FORMAT_V1,
            "module_name": module_name,
            "vm_profile": vm_profile,
            "source": normalized_source,
            "vm_ir_json": vm_ir_json,
            "hashes": {
                "input_source_sha256": _sha256_text(source),
                "source_sha256": _sha256_text(normalized_source),
                "vm_ir_sha256": _sha256_text(vm_ir_json),
            },
        }
        return CompileResult(ok=True, artifact=artifact)
    except Exception as exc:
        return CompileResult(
            ok=False,
            error_type=type(exc).__name__,
            error_message=str(exc),
        )


def compile_with_rust(
    *,
    module_name: str,
    source: str,
    lint: bool,
    vm_profile: str,
) -> CompileResult:
    try:
        artifact = xian_compiler_core.compile_contract_artifact(
            module_name,
            source,
            lint=lint,
            vm_profile=vm_profile,
        )
        return CompileResult(ok=True, artifact=artifact)
    except Exception as exc:
        return CompileResult(
            ok=False,
            error_type=type(exc).__name__,
            error_message=str(exc),
        )


def compare_artifacts(
    python_artifact: dict[str, Any],
    rust_artifact: dict[str, Any],
) -> list[str]:
    mismatches: list[str] = []
    for field in (
        "format",
        "module_name",
        "vm_profile",
        "source",
        "vm_ir_json",
    ):
        if python_artifact.get(field) != rust_artifact.get(field):
            mismatches.append(field)
    if python_artifact.get("hashes") != rust_artifact.get("hashes"):
        mismatches.append("hashes")
    return mismatches


def relative_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(WORKSPACE_ROOT))
    except ValueError:
        return str(path)


def audit_source(
    path: Path,
    *,
    lint_modes: tuple[bool, ...],
    vm_profile: str,
) -> list[dict[str, Any]]:
    source = path.read_text(encoding="utf-8")
    module_name = infer_module_name(path)
    records: list[dict[str, Any]] = []

    for lint in lint_modes:
        python_result = compile_with_python(
            module_name=module_name,
            source=source,
            lint=lint,
            vm_profile=vm_profile,
        )
        rust_result = compile_with_rust(
            module_name=module_name,
            source=source,
            lint=lint,
            vm_profile=vm_profile,
        )
        record: dict[str, Any] = {
            "path": relative_path(path),
            "module_name": module_name,
            "lint": lint,
            "python_ok": python_result.ok,
            "rust_ok": rust_result.ok,
            "status": "matched",
        }
        if python_result.ok and rust_result.ok:
            assert python_result.artifact is not None
            assert rust_result.artifact is not None
            mismatches = compare_artifacts(
                python_result.artifact,
                rust_result.artifact,
            )
            if mismatches:
                record["status"] = "mismatch"
                record["mismatches"] = mismatches
            records.append(record)
            continue

        if python_result.ok != rust_result.ok:
            record["status"] = "mismatch"
            record["python_error_type"] = python_result.error_type
            record["python_error_message"] = python_result.error_message
            record["rust_error_type"] = rust_result.error_type
            record["rust_error_message"] = rust_result.error_message
            records.append(record)
            continue

        record["status"] = "both_rejected"
        record["python_error_type"] = python_result.error_type
        record["rust_error_type"] = rust_result.error_type
        records.append(record)

    return records


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compare Python compiler output against xian_compiler_core.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="contract source files or directories to audit",
    )
    parser.add_argument(
        "--lint-mode",
        choices=("both", "lint", "no-lint"),
        default="both",
        help="which compiler lint setting to compare",
    )
    parser.add_argument(
        "--profile",
        default=XIAN_VM_V1_PROFILE,
        help="VM profile to compile for",
    )
    parser.add_argument(
        "--fail-on-mismatch",
        action="store_true",
        help="exit with status 1 if any mismatch is found",
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="include matched records in output",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    roots = args.paths or list(DEFAULT_ROOTS)
    source_paths = discover_contract_sources(roots)
    lint_modes = {
        "both": (False, True),
        "lint": (True,),
        "no-lint": (False,),
    }[args.lint_mode]

    records: list[dict[str, Any]] = []
    for source_path in source_paths:
        records.extend(
            audit_source(
                source_path,
                lint_modes=lint_modes,
                vm_profile=args.profile,
            )
        )

    mismatches = [
        record for record in records if record["status"] == "mismatch"
    ]
    both_rejected = [
        record for record in records if record["status"] == "both_rejected"
    ]
    output_records = records if args.show_all else mismatches + both_rejected

    print(
        json.dumps(
            {
                "schema": "xian.compiler_core_parity.v1",
                "profile": args.profile,
                "sources": len(source_paths),
                "comparisons": len(records),
                "matched": sum(
                    1 for record in records if record["status"] == "matched"
                ),
                "both_rejected": len(both_rejected),
                "mismatches": len(mismatches),
                "records": output_records,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if args.fail_on_mismatch and mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
