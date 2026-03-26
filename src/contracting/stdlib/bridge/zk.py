from functools import lru_cache
from types import ModuleType

from contracting import constants
from contracting.execution.runtime import rt


@lru_cache(maxsize=1)
def _native_verifier_bindings():
    try:
        from xian_zk import (
            ZkEncodingError,
            ZkVerifierError,
            verify_groth16_bn254,
        )
    except ImportError:
        return None

    return {
        "verify_groth16_bn254": verify_groth16_bn254,
        "ZkEncodingError": ZkEncodingError,
        "ZkVerifierError": ZkVerifierError,
    }


def _payload_metering_cost(
    vk_hex: str,
    proof_hex: str,
    public_inputs: list[str],
) -> int:
    payload_chars = len(vk_hex) + len(proof_hex)
    payload_chars += sum(len(value) for value in public_inputs)
    return (
        constants.ZK_VERIFY_GROTH16_BASE_COST
        + (
            len(public_inputs)
            * constants.ZK_VERIFY_GROTH16_PER_PUBLIC_INPUT_COST
        )
        + (payload_chars * constants.ZK_VERIFY_GROTH16_PER_PAYLOAD_BYTE_COST)
    )


def _validate_hex_payload(name: str, value: str, max_chars: int):
    assert isinstance(value, str), f"{name} must be a string!"
    assert value.startswith("0x"), f"{name} must be 0x-prefixed hex!"
    assert len(value) <= max_chars, f"{name} exceeds the maximum size!"
    assert len(value) % 2 == 0, f"{name} must contain whole bytes of hex!"


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


def is_available():
    return _native_verifier_bindings() is not None


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


zk_module = ModuleType("zk")
zk_module.is_available = is_available
zk_module.verify_groth16_bn254 = verify_groth16_bn254

exports = {"zk": zk_module}
