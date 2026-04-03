from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from xian_zk._native import (
    build_insecure_dev_shielded_command_bundle_json,
    build_random_shielded_command_bundle_json,
    load_shielded_command_prover_bundle,
    prove_shielded_command_deposit,
    prove_shielded_command_execute,
    prove_shielded_command_withdraw,
)
from xian_zk._native import (
    shielded_command_binding as native_command_binding,
)
from xian_zk._native import (
    shielded_command_execution_tag as native_command_execution_tag,
)
from xian_zk.shielded_notes import (
    ShieldedDepositRequest,
    ShieldedInput,
    ShieldedNote,
    ShieldedOutput,
    ShieldedProofResult,
    ShieldedTreeState,
    ShieldedWithdrawRequest,
    recipient_digest,
)

_FIELD_ZERO_HEX = "0x" + "00" * 32


def _request_json(request: Any) -> str:
    return json.dumps(request, sort_keys=True)


def canonicalize_command_payload(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, dict):
        items = []
        for key in sorted(value.keys()):
            items.append(f"{key}:{canonicalize_command_payload(value[key])}")
        return "{" + ",".join(items) + "}"
    if isinstance(value, list):
        return "[" + ",".join(canonicalize_command_payload(item) for item in value) + "]"
    return str(value)


def command_target_digest(target_contract: str) -> str:
    if not isinstance(target_contract, str) or target_contract == "":
        raise ValueError("target_contract must be a non-empty string")
    return recipient_digest(target_contract)


def command_payload_digest(payload: dict[str, Any] | None = None) -> str:
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dict or None")
    return recipient_digest(canonicalize_command_payload(payload))


def command_relayer_digest(relayer: str) -> str:
    if not isinstance(relayer, str) or relayer == "":
        raise ValueError("relayer must be a non-empty string")
    return recipient_digest(relayer)


def command_expiry_digest(expires_at: Any = None) -> str:
    if expires_at is None:
        return _FIELD_ZERO_HEX
    if isinstance(expires_at, str) and expires_at == "":
        return _FIELD_ZERO_HEX
    return recipient_digest(str(expires_at))


def command_binding(
    *,
    input_nullifier: str,
    target_contract: str,
    payload: dict[str, Any] | None,
    relayer: str,
    fee: int,
    expires_at: Any = None,
) -> str:
    return native_command_binding(
        input_nullifier,
        command_target_digest(target_contract),
        command_payload_digest(payload),
        command_relayer_digest(relayer),
        command_expiry_digest(expires_at),
        fee,
    )


def command_execution_tag(
    *,
    input_nullifier: str,
    command_binding_value: str,
) -> str:
    return native_command_execution_tag(input_nullifier, command_binding_value)


@dataclass(frozen=True)
class ShieldedCommandRequest:
    asset_id: str
    old_root: str
    append_state: ShieldedTreeState
    fee: int
    input: ShieldedInput
    outputs: list[ShieldedOutput]
    target_contract: str
    payload: dict[str, Any] | None
    relayer: str
    expires_at: Any = None


@dataclass(frozen=True)
class ShieldedCommandProofResult:
    proof_hex: str
    old_root: str
    expected_new_root: str
    public_inputs: list[str]
    command_binding: str
    execution_tag: str
    input_nullifier: str
    output_commitments: list[str]

    @classmethod
    def from_json(cls, payload: str) -> "ShieldedCommandProofResult":
        return cls(**json.loads(payload))


class ShieldedCommandProver:
    def __init__(self, bundle_json: str):
        self.bundle_json = bundle_json
        self.bundle = json.loads(bundle_json)
        self._bundle_handle = load_shielded_command_prover_bundle(bundle_json)

    @classmethod
    def build_insecure_dev_bundle(cls) -> "ShieldedCommandProver":
        return cls(build_insecure_dev_shielded_command_bundle_json())

    @classmethod
    def build_random_bundle(
        cls,
        *,
        contract_name: str,
        vk_id_prefix: str,
    ) -> "ShieldedCommandProver":
        return cls(
            build_random_shielded_command_bundle_json(
                contract_name,
                vk_id_prefix,
            )
        )

    def registry_manifest(self) -> dict[str, Any]:
        return shielded_command_registry_manifest(self)

    def prove_deposit(
        self, request: ShieldedDepositRequest
    ) -> ShieldedProofResult:
        return ShieldedProofResult.from_json(
            prove_shielded_command_deposit(
                self._bundle_handle,
                _request_json(asdict(request)),
            )
        )

    def prove_execute(
        self, request: ShieldedCommandRequest
    ) -> ShieldedCommandProofResult:
        input_note = ShieldedNote(
            owner_secret=request.input.owner_secret,
            amount=request.input.amount,
            rho=request.input.rho,
            blind=request.input.blind,
        )
        input_nullifier = input_note.nullifier(request.asset_id)
        binding = command_binding(
            input_nullifier=input_nullifier,
            target_contract=request.target_contract,
            payload=request.payload,
            relayer=request.relayer,
            fee=request.fee,
            expires_at=request.expires_at,
        )
        native_request = {
            "asset_id": request.asset_id,
            "old_root": request.old_root,
            "append_state": asdict(request.append_state),
            "fee": request.fee,
            "input": asdict(request.input),
            "outputs": [asdict(output) for output in request.outputs],
            "command_binding": binding,
        }
        return ShieldedCommandProofResult.from_json(
            prove_shielded_command_execute(
                self._bundle_handle,
                _request_json(native_request),
            )
        )

    def prove_withdraw(
        self, request: ShieldedWithdrawRequest
    ) -> ShieldedProofResult:
        return ShieldedProofResult.from_json(
            prove_shielded_command_withdraw(
                self._bundle_handle,
                _request_json(asdict(request)),
            )
        )


def shielded_command_registry_manifest(
    bundle: ShieldedCommandProver | dict[str, Any],
) -> dict[str, Any]:
    if isinstance(bundle, ShieldedCommandProver):
        payload = bundle.bundle
    elif isinstance(bundle, dict):
        payload = bundle
    else:
        raise TypeError("bundle must be a ShieldedCommandProver or dict")

    entries = []
    configure_actions = []
    for action in ("deposit", "command", "withdraw"):
        circuit = payload[action]
        entries.append(
            {
                "vk_id": circuit["vk_id"],
                "vk_hex": circuit["vk_hex"],
                "circuit_name": circuit["circuit_name"],
                "version": circuit["version"],
            }
        )
        configure_actions.append(
            {
                "action": action,
                "vk_id": circuit["vk_id"],
            }
        )

    return {
        "contract_name": payload["contract_name"],
        "circuit_family": payload["circuit_family"],
        "tree_depth": payload["tree_depth"],
        "leaf_capacity": payload["leaf_capacity"],
        "max_inputs": payload["max_inputs"],
        "max_outputs": payload["max_outputs"],
        "warning": payload["warning"],
        "registry_entries": entries,
        "configure_actions": configure_actions,
    }


__all__ = [
    "ShieldedCommandProofResult",
    "ShieldedCommandProver",
    "ShieldedCommandRequest",
    "canonicalize_command_payload",
    "command_binding",
    "command_execution_tag",
    "command_expiry_digest",
    "command_payload_digest",
    "command_relayer_digest",
    "command_target_digest",
    "shielded_command_registry_manifest",
]
