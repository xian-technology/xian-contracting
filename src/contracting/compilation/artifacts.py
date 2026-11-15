"""Contract artifacts, compiled by the Rust compiler core (xian_compiler_core).

Artifact assembly, hashing, normalization, the deploy compile pair and artifact
validation live in compiler-core and are shared with its WASM build. This module
only checks that the installed native compiler's host catalog matches the host
bindings this package's runtime implements, then delegates.
"""

from __future__ import annotations

from functools import lru_cache

import xian_compiler_core
from xian_compiler_core import CONTRACT_ARTIFACT_FORMAT_V1, DEFAULT_VM_PROFILE

from contracting.compilation.ir import HOST_BINDINGS, XIAN_VM_HOST_CATALOG_V1

__all__ = [
    "CONTRACT_ARTIFACT_FORMAT_V1",
    "build_contract_artifacts",
    "compile_contract_source",
    "diagnose_contract_source",
    "validate_contract_artifacts",
]


def diagnose_contract_source(
    *,
    module_name: str,
    source: str,
    lint: bool = True,
    vm_profile: str = DEFAULT_VM_PROFILE,
) -> list[dict[str, object]]:
    """Return authoritative Rust compiler diagnostics for contract source."""

    _assert_native_compiler_host_surface_current()
    return xian_compiler_core.diagnose_contract(
        module_name,
        source,
        lint=lint,
        vm_profile=vm_profile,
    )


@lru_cache(maxsize=1)
def _assert_native_compiler_host_surface_current() -> None:
    surface = xian_compiler_core.describe_vm_host_surface()
    catalog_version = surface.get("catalog_version")
    if catalog_version != XIAN_VM_HOST_CATALOG_V1:
        raise RuntimeError(
            "xian_compiler_core host catalog is stale relative to "
            "contracting.compilation.ir; rebuild xian-tech-compiler-core. "
            f"Expected catalog_version={XIAN_VM_HOST_CATALOG_V1!r}, "
            f"got {catalog_version!r}."
        )

    native_bindings = {
        spec.get("binding"): spec
        for spec in surface.get("bindings", [])
        if isinstance(spec, dict) and isinstance(spec.get("binding"), str)
    }
    missing = []
    mismatched = []
    for expected in HOST_BINDINGS:
        binding = expected["binding"]
        actual = native_bindings.get(binding)
        if actual is None:
            missing.append(binding)
            continue
        for field in ("id", "kind", "category"):
            if actual.get(field) != expected[field]:
                mismatched.append(
                    f"{binding}.{field}: expected {expected[field]!r}, got {actual.get(field)!r}"
                )

    if missing or mismatched:
        details = []
        if missing:
            details.append("missing bindings: " + ", ".join(sorted(missing)))
        if mismatched:
            details.append("mismatched bindings: " + "; ".join(mismatched))
        raise RuntimeError(
            "xian_compiler_core host catalog is stale relative to "
            "contracting.compilation.ir; rebuild xian-tech-compiler-core. " + " ".join(details)
        )


def build_contract_artifacts(
    *,
    module_name: str,
    source: str,
    lint: bool = True,
    vm_profile: str = DEFAULT_VM_PROFILE,
    compact: bool = False,
) -> dict[str, object]:
    """Compile ``source`` into its deployment artifact.

    ``compact`` is accepted so released callers keep working; artifacts have a
    single canonical form and it does not change the result.
    """
    del compact
    _assert_native_compiler_host_surface_current()
    return xian_compiler_core.compile_contract_artifact(
        module_name,
        source,
        lint=lint,
        vm_profile=vm_profile,
    )


@lru_cache(maxsize=256)
def _compile_contract_source(
    module_name: str,
    source: str,
    lint: bool,
    vm_profile: str,
) -> tuple[str, str]:
    compiled = xian_compiler_core.compile_contract_source(
        module_name,
        source,
        lint=lint,
        vm_profile=vm_profile,
    )
    return compiled["source"], compiled["vm_ir_json"]


def compile_contract_source(
    *,
    module_name: str,
    source: str,
    lint: bool = True,
    vm_profile: str = DEFAULT_VM_PROFILE,
) -> dict[str, str]:
    """Return the normalized source and canonical IR a node deploys for source."""

    _assert_native_compiler_host_surface_current()

    if not isinstance(source, str) or source == "":
        raise ValueError("contract source must be a non-empty string.")

    canonical_source, vm_ir_json = _compile_contract_source(module_name, source, lint, vm_profile)
    return {
        "source": canonical_source,
        "vm_ir_json": vm_ir_json,
    }


def validate_contract_artifacts(
    *,
    module_name: str,
    artifacts: dict[str, object],
    input_source: str | None = None,
    vm_profile: str = DEFAULT_VM_PROFILE,
) -> dict[str, str]:
    """Validate deployment artifacts; raises ``ValueError`` (``CompilerError``)."""

    _assert_native_compiler_host_surface_current()

    if not isinstance(artifacts, dict):
        raise TypeError("deployment_artifacts must be a dictionary.")

    return xian_compiler_core.validate_contract_artifact(
        module_name,
        artifacts,
        input_source=input_source,
        vm_profile=vm_profile,
    )
