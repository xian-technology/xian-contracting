from functools import lru_cache
from types import ModuleType

from cachetools import LRUCache

from contracting import constants
from contracting.execution.runtime import rt
from contracting.storage.driver import Driver


@lru_cache(maxsize=1)
def _native_verifier_bindings():
    try:
        from xian_zk import (
            ZkEncodingError,
            ZkVerifierError,
            prepare_groth16_bn254_vk,
            verify_groth16_bn254,
            verify_groth16_bn254_prepared,
        )
    except ImportError:
        return None

    return {
        "prepare_groth16_bn254_vk": prepare_groth16_bn254_vk,
        "verify_groth16_bn254": verify_groth16_bn254,
        "verify_groth16_bn254_prepared": verify_groth16_bn254_prepared,
        "ZkEncodingError": ZkEncodingError,
        "ZkVerifierError": ZkVerifierError,
    }


PREPARED_VK_CACHE = LRUCache(maxsize=128)


def _hex_payload_bytes(value: str) -> int:
    return (len(value) - 2) // 2


def _payload_metering_cost(
    vk_hex: str,
    proof_hex: str,
    public_inputs: list[str],
) -> int:
    payload_bytes = _hex_payload_bytes(vk_hex) + _hex_payload_bytes(proof_hex)
    payload_bytes += sum(_hex_payload_bytes(value) for value in public_inputs)
    return (
        constants.ZK_VERIFY_GROTH16_BASE_COST
        + (
            len(public_inputs)
            * constants.ZK_VERIFY_GROTH16_PER_PUBLIC_INPUT_COST
        )
        + (payload_bytes * constants.ZK_VERIFY_GROTH16_PER_PAYLOAD_BYTE_COST)
    )


def _registry_metering_cost(
    vk_id: str,
    proof_hex: str,
    public_inputs: list[str],
) -> int:
    payload_bytes = len(vk_id.encode("utf-8"))
    payload_bytes += _hex_payload_bytes(proof_hex)
    payload_bytes += sum(_hex_payload_bytes(value) for value in public_inputs)
    return (
        constants.ZK_VERIFY_GROTH16_REGISTRY_BASE_COST
        + constants.ZK_VERIFY_GROTH16_REGISTRY_PREPARE_COST
        + (
            len(public_inputs)
            * constants.ZK_VERIFY_GROTH16_REGISTRY_PER_PUBLIC_INPUT_COST
        )
        + (
            payload_bytes
            * constants.ZK_VERIFY_GROTH16_REGISTRY_PER_PAYLOAD_BYTE_COST
        )
    )


def _validate_hex_payload(name: str, value: str, max_chars: int):
    assert isinstance(value, str), f"{name} must be a string!"
    assert value.startswith("0x"), f"{name} must be 0x-prefixed hex!"
    assert len(value) > 2, f"{name} must not be empty!"
    assert len(value) <= max_chars, f"{name} exceeds the maximum size!"
    assert len(value) % 2 == 0, f"{name} must contain whole bytes of hex!"
    assert all(char in "0123456789abcdefABCDEF" for char in value[2:]), (
        f"{name} must be valid hex!"
    )


def _validate_public_inputs(public_inputs):
    assert isinstance(public_inputs, list), "public_inputs must be a list!"
    assert len(public_inputs) <= constants.MAX_ZK_PUBLIC_INPUTS, (
        "Too many public inputs for zk verification!"
    )
    for index, value in enumerate(public_inputs):
        _validate_hex_payload(
            f"public_inputs[{index}]",
            value,
            66,
        )
        assert len(value) == 66, (
            f"public_inputs[{index}] must be exactly 32 bytes!"
        )


def _validate_vk_id(vk_id: str):
    assert isinstance(vk_id, str), "vk_id must be a string!"
    assert vk_id != "", "vk_id must not be empty!"
    assert len(vk_id) <= constants.MAX_ZK_VERIFYING_KEY_ID_CHARS, (
        "vk_id exceeds the maximum size!"
    )


def _driver():
    return rt.env.get("__Driver") or Driver()


def _registry_field(vk_id: str, field: str):
    return _driver().get_var(
        constants.ZK_REGISTRY_CONTRACT_NAME,
        "verifying_keys",
        [vk_id, field],
    )


def _registered_vk_record(vk_id: str):
    _validate_vk_id(vk_id)

    vk_hex = _registry_field(vk_id, "vk_hex")
    assert vk_hex is not None, f"Unknown verifying key id '{vk_id}'!"

    record = {
        "vk_id": vk_id,
        "scheme": _registry_field(vk_id, "scheme"),
        "curve": _registry_field(vk_id, "curve"),
        "vk_hex": vk_hex,
        "vk_hash": _registry_field(vk_id, "vk_hash"),
        "active": _registry_field(vk_id, "active"),
    }

    assert record["scheme"] == "groth16", (
        f"Verifying key '{vk_id}' must use Groth16!"
    )
    assert record["curve"] == "bn254", (
        f"Verifying key '{vk_id}' must use BN254!"
    )
    assert record["active"] is True, f"Verifying key '{vk_id}' is inactive!"
    assert isinstance(record["vk_hash"], str) and record["vk_hash"] != "", (
        f"Verifying key '{vk_id}' is missing vk_hash!"
    )
    _validate_hex_payload(
        "registered vk_hex",
        record["vk_hex"],
        constants.MAX_ZK_VERIFYING_KEY_HEX_CHARS,
    )

    return record


def _prepared_vk(bindings, vk_id: str, vk_hex: str, vk_hash: str):
    cache_key = (vk_id, vk_hash)
    prepared = PREPARED_VK_CACHE.get(cache_key)
    if prepared is None:
        try:
            prepared = bindings["prepare_groth16_bn254_vk"](vk_hex)
        except (
            bindings["ZkEncodingError"],
            bindings["ZkVerifierError"],
        ) as exc:
            raise AssertionError(str(exc)) from exc
        PREPARED_VK_CACHE[cache_key] = prepared
    return prepared


def is_available():
    return _native_verifier_bindings() is not None


def has_verifying_key(vk_id: str):
    try:
        record = _registered_vk_record(vk_id)
    except AssertionError:
        return False
    return record["active"] is True


def verify_groth16_bn254(vk_hex: str, proof_hex: str, public_inputs: list[str]):
    _validate_hex_payload(
        "vk_hex",
        vk_hex,
        constants.MAX_ZK_VERIFYING_KEY_HEX_CHARS,
    )
    _validate_hex_payload(
        "proof_hex",
        proof_hex,
        constants.MAX_ZK_PROOF_HEX_CHARS,
    )
    _validate_public_inputs(public_inputs)

    rt.deduct_execution_cost(
        _payload_metering_cost(vk_hex, proof_hex, public_inputs)
    )

    bindings = _native_verifier_bindings()
    assert bindings is not None, (
        "Native zk verifier is not installed in this runtime. "
        "Install xian-contracting[zk] or xian-zk."
    )

    try:
        return bindings["verify_groth16_bn254"](
            vk_hex,
            proof_hex,
            public_inputs,
        )
    except (
        bindings["ZkEncodingError"],
        bindings["ZkVerifierError"],
    ) as exc:
        raise AssertionError(str(exc)) from exc


def verify_groth16(vk_id: str, proof_hex: str, public_inputs: list[str]):
    _validate_vk_id(vk_id)
    _validate_hex_payload(
        "proof_hex",
        proof_hex,
        constants.MAX_ZK_PROOF_HEX_CHARS,
    )
    _validate_public_inputs(public_inputs)

    rt.deduct_execution_cost(
        _registry_metering_cost(vk_id, proof_hex, public_inputs)
    )

    bindings = _native_verifier_bindings()
    assert bindings is not None, (
        "Native zk verifier is not installed in this runtime. "
        "Install xian-contracting[zk] or xian-zk."
    )

    record = _registered_vk_record(vk_id)
    prepared = _prepared_vk(
        bindings,
        vk_id,
        record["vk_hex"],
        record["vk_hash"],
    )

    try:
        return bindings["verify_groth16_bn254_prepared"](
            prepared,
            proof_hex,
            public_inputs,
        )
    except (
        bindings["ZkEncodingError"],
        bindings["ZkVerifierError"],
    ) as exc:
        raise AssertionError(str(exc)) from exc


def clear_prepared_vk_cache():
    PREPARED_VK_CACHE.clear()


zk_module = ModuleType("zk")
zk_module.clear_prepared_vk_cache = clear_prepared_vk_cache
zk_module.has_verifying_key = has_verifying_key
zk_module.is_available = is_available
zk_module.verify_groth16 = verify_groth16
zk_module.verify_groth16_bn254 = verify_groth16_bn254

exports = {"zk": zk_module}
