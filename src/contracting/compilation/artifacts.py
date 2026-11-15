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
    vm_profile: str = DEFAULT_VM_PROFILE,
) -> list[dict[str, object]]:
    """Return authoritative Rust compiler diagnostics for contract source."""

    _assert_native_compiler_host_surface_current()
    return xian_compiler_core.diagnose_contract(module_name, source, vm_profile=vm_profile)


_STALE_CATALOG = (
    "xian_compiler_core host catalog is stale relative to "
    "contracting.compilation.ir; rebuild xian-tech-compiler-core. "
)


@lru_cache(maxsize=1)
def _assert_native_compiler_host_surface_current() -> None:
    surface = xian_compiler_core.describe_vm_host_surface()
    catalog_version = surface.get("catalog_version")
    if catalog_version != XIAN_VM_HOST_CATALOG_V1:
        raise RuntimeError(
            _STALE_CATALOG + f"Expected catalog_version={XIAN_VM_HOST_CATALOG_V1!r}, "
            f"got {catalog_version!r}."
        )
    problems = _host_binding_problems(_native_bindings_by_name(surface))
    if problems:
        raise RuntimeError(_STALE_CATALOG + " ".join(problems))


def _native_bindings_by_name(surface: dict) -> dict[str, dict]:
    return {
        spec["binding"]: spec
        for spec in surface.get("bindings", [])
        if isinstance(spec, dict) and isinstance(spec.get("binding"), str)
    }


def _host_binding_problems(native_bindings: dict[str, dict]) -> list[str]:
    """Describe how the native host catalog differs from this runtime's HOST_BINDINGS."""
    missing = sorted(
        expected["binding"]
        for expected in HOST_BINDINGS
        if expected["binding"] not in native_bindings
    )
    mismatched = [
        f"{expected['binding']}.{field}: expected {expected[field]!r}, got {actual.get(field)!r}"
        for expected in HOST_BINDINGS
        if (actual := native_bindings.get(expected["binding"])) is not None
        for field in ("id", "kind", "category")
        if actual.get(field) != expected[field]
    ]
    problems = []
    if missing:
        problems.append("missing bindings: " + ", ".join(missing))
    if mismatched:
        problems.append("mismatched bindings: " + "; ".join(mismatched))
    return problems


def build_contract_artifacts(
    *,
    module_name: str,
    source: str,
    vm_profile: str = DEFAULT_VM_PROFILE,
) -> dict[str, object]:
    """Compile ``source`` into its deployment artifact."""
    _assert_native_compiler_host_surface_current()
    return xian_compiler_core.compile_contract_artifact(module_name, source, vm_profile=vm_profile)


@lru_cache(maxsize=256)
def _compile_contract_source(module_name: str, source: str, vm_profile: str) -> tuple[str, str]:
    compiled = xian_compiler_core.compile_contract_source(
        module_name, source, vm_profile=vm_profile
    )
    return compiled["source"], compiled["vm_ir_json"]


def compile_contract_source(
    *,
    module_name: str,
    source: str,
    vm_profile: str = DEFAULT_VM_PROFILE,
) -> dict[str, str]:
    """Return the normalized source and canonical IR a node deploys for source."""

    _assert_native_compiler_host_surface_current()

    if not isinstance(source, str) or source == "":
        raise ValueError("contract source must be a non-empty string.")

    canonical_source, vm_ir_json = _compile_contract_source(module_name, source, vm_profile)
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
