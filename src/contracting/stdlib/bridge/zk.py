import json
from functools import lru_cache
from types import ModuleType

from contracting import constants
from contracting.execution.runtime import rt

_UNAVAILABLE = (
    "Native zk verifier is not installed in this runtime. "
    "Install xian-tech-vm-core, which links it."
)


@lru_cache(maxsize=1)
def _native_verifier_bindings():
    # The VM links the zk verifier, so this runtime and the Rust block
    # executor verify with one library and share the node's proof caches.
    try:
        from xian_vm_core._native import (
            ZkEncodingError,
            ZkVerifierError,
            zk_clear_prepared_vk_cache,
            zk_clear_verified_proof_cache,
            zk_shielded_command_binding,
            zk_shielded_command_execution_tag,
            zk_shielded_command_nullifier_digest,
            zk_shielded_command_public_inputs,
            zk_shielded_deposit_public_inputs,
            zk_shielded_note_append_tree_state_json,
            zk_shielded_output_payload_hash,
            zk_shielded_output_payload_hashes,
            zk_shielded_transfer_public_inputs,
            zk_shielded_withdraw_public_inputs,
            zk_verify_groth16_bn254,
            zk_verify_registered,
            zk_warm_registered,
        )
    except ImportError:
        return None

    return {
        "clear_prepared_vk_cache": zk_clear_prepared_vk_cache,
        "clear_verified_proof_cache": zk_clear_verified_proof_cache,
        "shielded_command_public_inputs": zk_shielded_command_public_inputs,
        "shielded_command_binding": zk_shielded_command_binding,
        "shielded_command_execution_tag": zk_shielded_command_execution_tag,
        "shielded_command_nullifier_digest": zk_shielded_command_nullifier_digest,
        "shielded_deposit_public_inputs": zk_shielded_deposit_public_inputs,
        "shielded_note_append_tree_state_json": zk_shielded_note_append_tree_state_json,
        "shielded_output_payload_hashes": zk_shielded_output_payload_hashes,
        "shielded_output_payload_hash": zk_shielded_output_payload_hash,
        "shielded_transfer_public_inputs": zk_shielded_transfer_public_inputs,
        "shielded_withdraw_public_inputs": zk_shielded_withdraw_public_inputs,
        "verify_groth16_bn254": zk_verify_groth16_bn254,
        "verify_registered": zk_verify_registered,
        "warm_registered": zk_warm_registered,
        "ZkEncodingError": ZkEncodingError,
        "ZkVerifierError": ZkVerifierError,
    }


def _native_bindings():
    bindings = _native_verifier_bindings()
    assert bindings is not None, _UNAVAILABLE
    return bindings


def _native(name: str, *args):
    """A native zk call; a verifier failure is an AssertionError (the shielded
    helpers' own ValueError passes through)."""
    bindings = _native_bindings()
    try:
        return bindings[name](*args)
    except (
        bindings["ZkEncodingError"],
        bindings["ZkVerifierError"],
    ) as exc:
        raise AssertionError(str(exc)) from exc


def _validate_hex_payload(name: str, value: str, max_chars: int):
    assert isinstance(value, str), f"{name} must be a string!"
    assert value.startswith("0x"), f"{name} must be 0x-prefixed hex!"
    assert len(value) > 2, f"{name} must not be empty!"
    assert len(value) <= max_chars, f"{name} exceeds the maximum size!"
    assert len(value) % 2 == 0, f"{name} must contain whole bytes of hex!"
    assert all(char in "0123456789abcdefABCDEF" for char in value[2:]), f"{name} must be valid hex!"


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
        assert len(value) == 66, f"public_inputs[{index}] must be exactly 32 bytes!"


def _validate_field_values(label: str, values, *, minimum: int, maximum: int):
    assert isinstance(values, list), f"{label} must be a list!"
    assert minimum <= len(values) <= maximum, f"{label} has invalid length!"
    for index, value in enumerate(values):
        _validate_hex_payload(f"{label}[{index}]", value, 66)
        assert len(value) == 66, f"{label}[{index}] must be exactly 32 bytes!"


def _validate_vk_id(vk_id: str):
    assert isinstance(vk_id, str), "vk_id must be a string!"
    assert vk_id != "", "vk_id must not be empty!"
    assert len(vk_id) <= constants.MAX_ZK_VERIFYING_KEY_ID_CHARS, "vk_id exceeds the maximum size!"


def _driver():
    driver = rt.env.get("__Driver")
    if driver is not None:
        return driver
    # The storage engine loads the native VM module, which loads this bridge.
    from contracting.storage.driver import Driver

    return Driver()


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

    assert record["scheme"] == "groth16", f"Verifying key '{vk_id}' must use Groth16!"
    assert record["curve"] == "bn254", f"Verifying key '{vk_id}' must use BN254!"
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


def is_available():
    return _native_verifier_bindings() is not None


def has_verifying_key(vk_id: str):
    try:
        record = _registered_vk_record(vk_id)
    except AssertionError:
        return False
    return record["active"] is True


def get_vk_info(vk_id: str):
    _validate_vk_id(vk_id)

    vk_hex = _registry_field(vk_id, "vk_hex")
    if vk_hex is None:
        return None

    return {
        "vk_id": vk_id,
        "scheme": _registry_field(vk_id, "scheme"),
        "curve": _registry_field(vk_id, "curve"),
        "vk_hash": _registry_field(vk_id, "vk_hash"),
        "active": _registry_field(vk_id, "active"),
        "circuit_name": _registry_field(vk_id, "circuit_name"),
        "version": _registry_field(vk_id, "version"),
        "created_at": _registry_field(vk_id, "created_at"),
        "circuit_family": _registry_field(vk_id, "circuit_family"),
        "statement_version": _registry_field(vk_id, "statement_version"),
        "contract_name": _registry_field(vk_id, "contract_name"),
        "artifact_contract_name": _registry_field(vk_id, "artifact_contract_name"),
        "tree_depth": _registry_field(vk_id, "tree_depth"),
        "leaf_capacity": _registry_field(vk_id, "leaf_capacity"),
        "max_inputs": _registry_field(vk_id, "max_inputs"),
        "max_outputs": _registry_field(vk_id, "max_outputs"),
        "setup_mode": _registry_field(vk_id, "setup_mode"),
        "setup_ceremony": _registry_field(vk_id, "setup_ceremony"),
        "artifact_hash": _registry_field(vk_id, "artifact_hash"),
        "bundle_hash": _registry_field(vk_id, "bundle_hash"),
        "warning": _registry_field(vk_id, "warning"),
        "deprecated": _registry_field(vk_id, "deprecated") is True,
        "deprecated_at": _registry_field(vk_id, "deprecated_at"),
        "replacement_vk_id": _registry_field(vk_id, "replacement_vk_id"),
        "index": _registry_field(vk_id, "index"),
    }


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

    return _native(
        "verify_groth16_bn254",
        vk_hex,
        proof_hex,
        public_inputs,
    )


def verify_groth16(vk_id: str, proof_hex: str, public_inputs: list[str]):
    _validate_vk_id(vk_id)
    _validate_hex_payload(
        "proof_hex",
        proof_hex,
        constants.MAX_ZK_PROOF_HEX_CHARS,
    )
    _validate_public_inputs(public_inputs)

    _native_bindings()
    record = _registered_vk_record(vk_id)
    # A result the node verified before (this block's pre-verification
    # included) comes from the node's proof cache.
    return _native(
        "verify_registered",
        vk_id,
        record["vk_hash"],
        record["vk_hex"],
        proof_hex,
        public_inputs,
    )


def _clear_cache(name: str) -> None:
    bindings = _native_verifier_bindings()
    if bindings is not None:
        bindings[name]()


def clear_prepared_vk_cache():
    _clear_cache("clear_prepared_vk_cache")


def clear_verified_proof_cache():
    _clear_cache("clear_verified_proof_cache")


def warm_verified_proofs(requests: list[dict]) -> list[bool]:
    assert isinstance(requests, list), "requests must be a list!"

    _native_bindings()
    proofs = []
    for index, request in enumerate(requests):
        assert isinstance(request, dict), f"requests[{index}] must be a dict!"
        vk_id = request.get("vk_id")
        proof_hex = request.get("proof_hex")
        public_inputs = request.get("public_inputs")
        _validate_vk_id(vk_id)
        _validate_hex_payload(
            f"requests[{index}].proof_hex",
            proof_hex,
            constants.MAX_ZK_PROOF_HEX_CHARS,
        )
        _validate_public_inputs(public_inputs)

        record = _registered_vk_record(vk_id)
        proofs.append((vk_id, record["vk_hash"], record["vk_hex"], proof_hex, public_inputs))

    # The proofs not in the node's proof cache are verified together and
    # their results cached.
    return list(_native("warm_registered", proofs))


def shielded_note_append_commitments(
    note_count: int,
    filled_subtrees: list[str],
    commitments: list[str],
):
    assert isinstance(note_count, int), "note_count must be an integer!"
    assert note_count >= 0, "note_count must be non-negative!"
    _validate_field_values(
        "filled_subtrees",
        filled_subtrees,
        minimum=1,
        maximum=64,
    )
    _validate_field_values(
        "commitments",
        commitments,
        minimum=1,
        maximum=constants.MAX_ZK_PUBLIC_INPUTS,
    )

    encoded = _native(
        "shielded_note_append_tree_state_json",
        note_count,
        filled_subtrees,
        commitments,
    )

    try:
        decoded = json.loads(encoded)
    except json.JSONDecodeError as exc:
        raise AssertionError("Native shielded tree append returned invalid JSON") from exc
    assert isinstance(decoded, dict), "Native shielded tree append returned invalid result!"
    return decoded


def shielded_command_nullifier_digest(input_nullifiers: list[str]):
    _validate_field_values(
        "input_nullifiers",
        input_nullifiers,
        minimum=1,
        maximum=constants.MAX_ZK_PUBLIC_INPUTS,
    )

    return _native("shielded_command_nullifier_digest", input_nullifiers)


def shielded_command_binding(
    nullifier_digest: str,
    target_digest: str,
    payload_digest: str,
    relayer_digest: str,
    expiry_digest: str,
    chain_digest: str,
    entrypoint_digest: str,
    version_digest: str,
    fee: int,
    public_amount: int,
):
    _validate_field_values(
        "binding_fields",
        [
            nullifier_digest,
            target_digest,
            payload_digest,
            relayer_digest,
            expiry_digest,
            chain_digest,
            entrypoint_digest,
            version_digest,
        ],
        minimum=8,
        maximum=8,
    )
    assert isinstance(fee, int) and fee >= 0, "fee must be a non-negative integer!"
    assert isinstance(public_amount, int) and public_amount >= 0, (
        "public_amount must be a non-negative integer!"
    )

    return _native(
        "shielded_command_binding",
        nullifier_digest,
        target_digest,
        payload_digest,
        relayer_digest,
        expiry_digest,
        chain_digest,
        entrypoint_digest,
        version_digest,
        fee,
        public_amount,
    )


def shielded_command_execution_tag(
    nullifier_digest: str,
    command_binding: str,
):
    _validate_field_values(
        "execution_tag_fields",
        [nullifier_digest, command_binding],
        minimum=2,
        maximum=2,
    )

    return _native(
        "shielded_command_execution_tag",
        nullifier_digest,
        command_binding,
    )


def shielded_output_payload_hash(payload_hex: str):
    if payload_hex is None or payload_hex == "":
        return "0x" + "00" * 32

    _validate_hex_payload(
        "payload_hex",
        payload_hex,
        constants.MAX_ZK_PROOF_HEX_CHARS * 4,
    )

    return _native("shielded_output_payload_hash", payload_hex)


def shielded_output_payload_hashes(payload_hexes: list[str]) -> list[str]:
    assert isinstance(payload_hexes, list), "payload_hexes must be a list!"

    normalized = []
    for index, payload_hex in enumerate(payload_hexes):
        if payload_hex is None or payload_hex == "":
            normalized.append("")
            continue
        _validate_hex_payload(
            f"payload_hexes[{index}]",
            payload_hex,
            constants.MAX_ZK_PROOF_HEX_CHARS * 4,
        )
        normalized.append(payload_hex)

    result = _native("shielded_output_payload_hashes", normalized)

    _validate_field_values(
        "payload_hashes",
        result,
        minimum=len(normalized),
        maximum=max(len(normalized), 1),
    )
    return result


def shielded_deposit_public_inputs(
    contract_name: str,
    old_root: str,
    amount: int,
    commitments: list[str],
    payload_hashes: list[str],
) -> list[str]:
    assert isinstance(contract_name, str) and contract_name != "", (
        "contract_name must be a non-empty string!"
    )
    assert isinstance(amount, int) and amount >= 0, "amount must be a non-negative integer!"
    _validate_field_values(
        "commitments",
        commitments,
        minimum=1,
        maximum=4,
    )
    _validate_field_values(
        "payload_hashes",
        payload_hashes,
        minimum=len(commitments),
        maximum=4,
    )
    assert len(payload_hashes) == len(commitments), "payload_hashes length must match commitments!"
    _validate_hex_payload("old_root", old_root, 66)

    return _native(
        "shielded_deposit_public_inputs",
        contract_name,
        old_root,
        amount,
        commitments,
        payload_hashes,
    )


def shielded_transfer_public_inputs(
    contract_name: str,
    old_root: str,
    input_nullifiers: list[str],
    commitments: list[str],
    payload_hashes: list[str],
) -> list[str]:
    assert isinstance(contract_name, str) and contract_name != "", (
        "contract_name must be a non-empty string!"
    )
    _validate_hex_payload("old_root", old_root, 66)
    _validate_field_values(
        "input_nullifiers",
        input_nullifiers,
        minimum=1,
        maximum=4,
    )
    _validate_field_values(
        "commitments",
        commitments,
        minimum=1,
        maximum=4,
    )
    _validate_field_values(
        "payload_hashes",
        payload_hashes,
        minimum=len(commitments),
        maximum=4,
    )
    assert len(payload_hashes) == len(commitments), "payload_hashes length must match commitments!"

    return _native(
        "shielded_transfer_public_inputs",
        contract_name,
        old_root,
        input_nullifiers,
        commitments,
        payload_hashes,
    )


def shielded_withdraw_public_inputs(
    contract_name: str,
    old_root: str,
    amount: int,
    recipient: str,
    input_nullifiers: list[str],
    commitments: list[str],
    payload_hashes: list[str],
) -> list[str]:
    assert isinstance(contract_name, str) and contract_name != "", (
        "contract_name must be a non-empty string!"
    )
    assert isinstance(amount, int) and amount >= 0, "amount must be a non-negative integer!"
    assert isinstance(recipient, str) and recipient != "", "recipient must be a non-empty string!"
    _validate_hex_payload("old_root", old_root, 66)
    _validate_field_values(
        "input_nullifiers",
        input_nullifiers,
        minimum=1,
        maximum=4,
    )
    _validate_field_values(
        "commitments",
        commitments,
        minimum=0,
        maximum=4,
    )
    _validate_field_values(
        "payload_hashes",
        payload_hashes,
        minimum=len(commitments),
        maximum=4,
    )
    assert len(payload_hashes) == len(commitments), "payload_hashes length must match commitments!"

    return _native(
        "shielded_withdraw_public_inputs",
        contract_name,
        old_root,
        amount,
        recipient,
        input_nullifiers,
        commitments,
        payload_hashes,
    )


def shielded_command_public_inputs(
    contract_name: str,
    old_root: str,
    command_binding: str,
    execution_tag: str,
    fee: int,
    public_amount: int,
    input_nullifiers: list[str],
    commitments: list[str],
    payload_hashes: list[str],
) -> list[str]:
    assert isinstance(contract_name, str) and contract_name != "", (
        "contract_name must be a non-empty string!"
    )
    _validate_hex_payload("old_root", old_root, 66)
    _validate_field_values(
        "command_public_fields",
        [command_binding, execution_tag],
        minimum=2,
        maximum=2,
    )
    assert isinstance(fee, int) and fee >= 0, "fee must be a non-negative integer!"
    assert isinstance(public_amount, int) and public_amount >= 0, (
        "public_amount must be a non-negative integer!"
    )
    _validate_field_values(
        "input_nullifiers",
        input_nullifiers,
        minimum=1,
        maximum=4,
    )
    _validate_field_values(
        "commitments",
        commitments,
        minimum=0,
        maximum=4,
    )
    _validate_field_values(
        "payload_hashes",
        payload_hashes,
        minimum=len(commitments),
        maximum=4,
    )
    assert len(payload_hashes) == len(commitments), "payload_hashes length must match commitments!"

    return _native(
        "shielded_command_public_inputs",
        contract_name,
        old_root,
        command_binding,
        execution_tag,
        fee,
        public_amount,
        input_nullifiers,
        commitments,
        payload_hashes,
    )


zk_module = ModuleType("zk")
zk_module.clear_prepared_vk_cache = clear_prepared_vk_cache
zk_module.clear_verified_proof_cache = clear_verified_proof_cache
zk_module.get_vk_info = get_vk_info
zk_module.has_verifying_key = has_verifying_key
zk_module.is_available = is_available
zk_module.shielded_command_public_inputs = shielded_command_public_inputs
zk_module.shielded_command_binding = shielded_command_binding
zk_module.shielded_command_execution_tag = shielded_command_execution_tag
zk_module.shielded_command_nullifier_digest = shielded_command_nullifier_digest
zk_module.shielded_deposit_public_inputs = shielded_deposit_public_inputs
zk_module.shielded_note_append_commitments = shielded_note_append_commitments
zk_module.shielded_output_payload_hash = shielded_output_payload_hash
zk_module.shielded_output_payload_hashes = shielded_output_payload_hashes
zk_module.shielded_transfer_public_inputs = shielded_transfer_public_inputs
zk_module.shielded_withdraw_public_inputs = shielded_withdraw_public_inputs
zk_module.warm_verified_proofs = warm_verified_proofs
zk_module.verify_groth16 = verify_groth16
zk_module.verify_groth16_bn254 = verify_groth16_bn254

exports = {"zk": zk_module}
