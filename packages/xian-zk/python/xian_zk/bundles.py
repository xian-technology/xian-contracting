from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

BundleType = Literal["note", "command"]

_BUNDLE_ACTIONS: dict[BundleType, tuple[str, str, str]] = {
    "note": ("deposit", "transfer", "withdraw"),
    "command": ("deposit", "command", "withdraw"),
}

_SAFE_SINGLE_PARTY_MODES = {"insecure-dev", "single-party"}


def _require_mapping(value: Any, *, label: str) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    raise ValueError(f"{label} must be a JSON object")


def _require_string(
    value: Any, *, label: str, allow_empty: bool = False
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    if not allow_empty and value.strip() == "":
        raise ValueError(f"{label} must be non-empty")
    return value


def _require_non_negative_int(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _require_positive_int(value: Any, *, label: str) -> int:
    resolved = _require_non_negative_int(value, label=label)
    if resolved <= 0:
        raise ValueError(f"{label} must be positive")
    return resolved


def _require_hex_string(
    value: Any, *, label: str, allow_empty: bool = False
) -> str:
    resolved = _require_string(value, label=label, allow_empty=allow_empty)
    if allow_empty and resolved == "":
        return resolved
    if not resolved.startswith("0x"):
        raise ValueError(f"{label} must start with 0x")
    hex_body = resolved[2:]
    if len(hex_body) == 0 or len(hex_body) % 2 != 0:
        raise ValueError(f"{label} must contain an even-length hex payload")
    try:
        bytes.fromhex(hex_body)
    except ValueError as exc:
        raise ValueError(f"{label} must contain valid hex") from exc
    return resolved


def _validate_common_payload(
    payload: Mapping[str, Any], *, bundle_type: BundleType
) -> dict[str, Any]:
    setup_mode = _require_string(payload.get("setup_mode"), label="setup_mode")
    setup_ceremony = _require_string(
        payload.get("setup_ceremony", ""),
        label="setup_ceremony",
        allow_empty=True,
    )
    if (
        setup_mode.strip().lower() not in _SAFE_SINGLE_PARTY_MODES
        and setup_ceremony.strip() == ""
    ):
        raise ValueError(
            "setup_ceremony is required when setup_mode is not insecure-dev or single-party"
        )

    normalized = {
        "circuit_family": _require_string(
            payload.get("circuit_family"), label="circuit_family"
        ),
        "warning": _require_string(payload.get("warning"), label="warning"),
        "setup_mode": setup_mode,
        "setup_ceremony": setup_ceremony,
        "contract_name": _require_string(
            payload.get("contract_name"), label="contract_name"
        ),
        "tree_depth": _require_positive_int(
            payload.get("tree_depth"), label="tree_depth"
        ),
        "leaf_capacity": _require_positive_int(
            payload.get("leaf_capacity"), label="leaf_capacity"
        ),
        "max_inputs": _require_positive_int(
            payload.get("max_inputs"), label="max_inputs"
        ),
        "max_outputs": _require_positive_int(
            payload.get("max_outputs"), label="max_outputs"
        ),
    }
    if normalized["leaf_capacity"] < 2 ** normalized["tree_depth"]:
        raise ValueError(
            "leaf_capacity must be large enough to cover the declared tree_depth"
        )

    action_names = _BUNDLE_ACTIONS[bundle_type]
    vk_ids: set[str] = set()
    circuit_names: set[str] = set()
    versions: set[str] = set()
    for action in action_names:
        circuit = _require_mapping(payload.get(action), label=action)
        vk_id = _require_string(circuit.get("vk_id"), label=f"{action}.vk_id")
        circuit_name = _require_string(
            circuit.get("circuit_name"), label=f"{action}.circuit_name"
        )
        version = _require_string(
            circuit.get("version"), label=f"{action}.version"
        )
        if vk_id in vk_ids:
            raise ValueError(f"duplicate vk_id detected: {vk_id}")
        if circuit_name in circuit_names:
            raise ValueError(f"duplicate circuit_name detected: {circuit_name}")
        vk_ids.add(vk_id)
        circuit_names.add(circuit_name)
        versions.add(version)
        normalized[action] = {
            "vk_id": vk_id,
            "circuit_name": circuit_name,
            "version": version,
            "vk_hex": _require_hex_string(
                circuit.get("vk_hex"), label=f"{action}.vk_hex"
            ),
        }

    if len(versions) != 1:
        raise ValueError("all circuit versions in a bundle must match")
    return normalized


def validate_shielded_bundle_payload(
    bundle: str | Mapping[str, Any],
    *,
    bundle_type: BundleType,
    require_private_keys: bool = True,
) -> dict[str, Any]:
    if isinstance(bundle, str):
        try:
            decoded = json.loads(bundle)
        except json.JSONDecodeError as exc:
            raise ValueError("bundle JSON must be valid JSON") from exc
    else:
        decoded = bundle
    payload = _require_mapping(decoded, label=f"{bundle_type} bundle")
    normalized = _validate_common_payload(payload, bundle_type=bundle_type)

    for action in _BUNDLE_ACTIONS[bundle_type]:
        circuit = _require_mapping(payload.get(action), label=action)
        if require_private_keys:
            normalized[action]["pk_hex"] = _require_hex_string(
                circuit.get("pk_hex"), label=f"{action}.pk_hex"
            )
        elif "pk_hex" in circuit and circuit.get("pk_hex") not in (None, ""):
            normalized[action]["pk_hex"] = _require_hex_string(
                circuit.get("pk_hex"), label=f"{action}.pk_hex"
            )
    return normalized


def validate_shielded_note_bundle(
    bundle: str | Mapping[str, Any], *, require_private_keys: bool = True
) -> dict[str, Any]:
    return validate_shielded_bundle_payload(
        bundle,
        bundle_type="note",
        require_private_keys=require_private_keys,
    )


def validate_shielded_command_bundle(
    bundle: str | Mapping[str, Any], *, require_private_keys: bool = True
) -> dict[str, Any]:
    return validate_shielded_bundle_payload(
        bundle,
        bundle_type="command",
        require_private_keys=require_private_keys,
    )


def load_bundle_text(path: str | Path) -> str:
    return Path(path).expanduser().resolve().read_text()


def load_and_validate_bundle_text(
    path: str | Path,
    *,
    bundle_type: BundleType,
) -> tuple[str, dict[str, Any]]:
    bundle_text = load_bundle_text(path)
    normalized = validate_shielded_bundle_payload(
        bundle_text,
        bundle_type=bundle_type,
        require_private_keys=True,
    )
    return (
        json.dumps(normalized, sort_keys=True, indent=2) + "\n",
        normalized,
    )


def bundle_summary(
    bundle: Mapping[str, Any], *, bundle_type: BundleType
) -> str:
    version = bundle[_BUNDLE_ACTIONS[bundle_type][0]]["version"]
    return (
        f"{bundle['circuit_family']} v{version} "
        f"({bundle['setup_mode'] or 'unknown setup'})"
    )


__all__ = [
    "BundleType",
    "bundle_summary",
    "load_and_validate_bundle_text",
    "load_bundle_text",
    "validate_shielded_bundle_payload",
    "validate_shielded_command_bundle",
    "validate_shielded_note_bundle",
]
