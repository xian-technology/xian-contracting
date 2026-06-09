from __future__ import annotations

from collections.abc import Mapping
from typing import Any

RUNTIME_FEATURE_ZK = "zk"
SUPPORTED_RUNTIME_FEATURES = frozenset({RUNTIME_FEATURE_ZK})
RUNTIME_FEATURE_STATE_PREFIX = "__runtime_features."
RUNTIME_FEATURE_DRIVER_ATTR = "_xian_runtime_features"

DEFAULT_CHAIN_RUNTIME_FEATURES = {
    RUNTIME_FEATURE_ZK: False,
}
DEFAULT_LOCAL_RUNTIME_FEATURES = {
    RUNTIME_FEATURE_ZK: True,
}


def runtime_feature_state_key(feature: str) -> str:
    _assert_supported_feature(feature)
    return f"{RUNTIME_FEATURE_STATE_PREFIX}{feature}"


def normalize_runtime_features(
    features: Mapping[str, Any] | None = None,
    *,
    default: Mapping[str, Any] | None = None,
) -> dict[str, bool]:
    resolved = {
        feature: _coerce_runtime_feature_value(value, feature=feature)
        for feature, value in (default or DEFAULT_CHAIN_RUNTIME_FEATURES).items()
        if feature in SUPPORTED_RUNTIME_FEATURES
    }
    for feature, value in (features or {}).items():
        _assert_supported_feature(feature)
        resolved[feature] = _coerce_runtime_feature_value(value, feature=feature)
    for feature, value in DEFAULT_CHAIN_RUNTIME_FEATURES.items():
        resolved.setdefault(feature, value)
    return resolved


def set_driver_runtime_features(driver, features: Mapping[str, Any] | None) -> dict[str, bool]:
    resolved = normalize_runtime_features(features)
    setattr(driver, RUNTIME_FEATURE_DRIVER_ATTR, resolved)
    return resolved


def get_driver_runtime_features(
    driver,
    *,
    default: Mapping[str, Any] | None = None,
) -> dict[str, bool]:
    state_features = {}
    driver_get = getattr(driver, "get", None)
    if driver_get is not None:
        for feature in SUPPORTED_RUNTIME_FEATURES:
            value = driver_get(runtime_feature_state_key(feature))
            if value is not None:
                state_features[feature] = value
    if state_features:
        return normalize_runtime_features(state_features, default=default)

    attr_features = getattr(driver, RUNTIME_FEATURE_DRIVER_ATTR, None)
    if isinstance(attr_features, Mapping):
        return normalize_runtime_features(attr_features, default=default)

    return normalize_runtime_features(default or DEFAULT_LOCAL_RUNTIME_FEATURES)


def runtime_feature_enabled(
    driver,
    feature: str,
    *,
    default_enabled: bool = True,
) -> bool:
    _assert_supported_feature(feature)
    return get_driver_runtime_features(
        driver,
        default={feature: default_enabled},
    )[feature]


def module_ir_uses_runtime_feature(module_ir: Mapping[str, Any] | None, feature: str) -> bool:
    _assert_supported_feature(feature)
    if not isinstance(module_ir, Mapping):
        return False
    if feature == RUNTIME_FEATURE_ZK:
        return _module_ir_uses_zk(module_ir)
    return False


def module_ir_uses_zk(module_ir: Mapping[str, Any] | None) -> bool:
    return module_ir_uses_runtime_feature(module_ir, RUNTIME_FEATURE_ZK)


def _module_ir_uses_zk(module_ir: Mapping[str, Any]) -> bool:
    dependencies = module_ir.get("host_dependencies")
    if not isinstance(dependencies, list):
        return False
    for dependency in dependencies:
        if not isinstance(dependency, Mapping):
            continue
        if dependency.get("category") == RUNTIME_FEATURE_ZK:
            return True
        for key in ("id", "binding"):
            value = dependency.get(key)
            if isinstance(value, str) and value.startswith("zk."):
                return True
    return False


def _assert_supported_feature(feature: str) -> None:
    if feature not in SUPPORTED_RUNTIME_FEATURES:
        raise ValueError(f"unsupported runtime feature {feature!r}")


def _coerce_runtime_feature_value(value: Any, *, feature: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    raise ValueError(f"runtime feature {feature!r} must be a boolean")
