from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from xian_zk._native import (
    build_insecure_dev_shielded_command_bundle_json,
    build_random_shielded_command_bundle_json,
    load_shielded_command_prover_bundle,
    prove_shielded_command_execute,
)
from xian_zk._native import (
    shielded_command_binding as native_command_binding,
)
from xian_zk._native import (
    shielded_command_execution_tag as native_command_execution_tag,
)
from xian_zk._native import (
    shielded_command_nullifier_digest as native_command_nullifier_digest,
)
from xian_zk.shielded_commands import (
    command_chain_digest,
    command_expiry_digest,
    command_relayer_digest,
)
from xian_zk.shielded_notes import (
    ShieldedInput,
    ShieldedNote,
    ShieldedOutput,
    ShieldedRecipient,
    ShieldedTreeState,
    ShieldedWallet,
    ShieldedWalletNote,
    generate_field_hex,
    output_payload_hashes,
    recipient_digest,
)

_RELAY_ACTION = "relay_transfer"
_RELAY_TARGET = "shielded-note-relay-transfer"
_RELAY_PAYLOAD = "transfer"
_RELAY_ENTRYPOINT = "relay_transfer_shielded"
_RELAY_VERSION = "shielded-note-relay-v1"


def _request_json(request: Any) -> str:
    return json.dumps(request, sort_keys=True)


def _sha3_hex(value: str) -> str:
    import hashlib

    return "0x" + hashlib.sha3_256(value.encode("utf-8")).hexdigest()


def relay_transfer_target_digest() -> str:
    return recipient_digest(_RELAY_TARGET)


def relay_transfer_payload_digest() -> str:
    return recipient_digest(_RELAY_PAYLOAD)


def relay_transfer_entrypoint_digest() -> str:
    return recipient_digest(_RELAY_ENTRYPOINT)


def relay_transfer_version_digest() -> str:
    return recipient_digest(_RELAY_VERSION)


def relay_transfer_nullifier_digest(input_nullifiers: list[str]) -> str:
    if not isinstance(input_nullifiers, list) or len(input_nullifiers) == 0:
        raise ValueError("input_nullifiers must be a non-empty list")
    return native_command_nullifier_digest(input_nullifiers)


def relay_transfer_binding(
    *,
    input_nullifiers: list[str],
    relayer: str,
    chain_id: str,
    fee: int,
    expires_at: Any = None,
) -> str:
    if fee < 0:
        raise ValueError("fee must be non-negative")
    return native_command_binding(
        relay_transfer_nullifier_digest(input_nullifiers),
        relay_transfer_target_digest(),
        relay_transfer_payload_digest(),
        command_relayer_digest(relayer),
        command_expiry_digest(expires_at),
        command_chain_digest(chain_id),
        relay_transfer_entrypoint_digest(),
        relay_transfer_version_digest(),
        fee,
        0,
    )


def relay_transfer_execution_tag(
    *,
    input_nullifiers: list[str],
    relay_binding: str,
) -> str:
    return native_command_execution_tag(
        relay_transfer_nullifier_digest(input_nullifiers),
        relay_binding,
    )


@dataclass(frozen=True)
class ShieldedRelayTransferRequest:
    asset_id: str
    old_root: str
    append_state: ShieldedTreeState
    fee: int
    inputs: list[ShieldedInput]
    outputs: list[ShieldedOutput]
    relayer: str
    chain_id: str
    expires_at: Any = None
    output_payload_hashes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ShieldedRelayTransferProofResult:
    proof_hex: str
    old_root: str
    expected_new_root: str
    public_inputs: list[str]
    relay_binding: str
    execution_tag: str
    relayer_fee: int
    input_nullifiers: list[str]
    output_commitments: list[str]
    output_payload_hashes: list[str]


@dataclass(frozen=True)
class ShieldedWalletRelayTransferPlan:
    request: ShieldedRelayTransferRequest
    input_notes: list[ShieldedWalletNote]
    recipient_output: ShieldedOutput
    change_note: ShieldedNote | None
    output_payloads: list[str]
    output_payload_hashes: list[str]
    relay_binding: str
    execution_tag: str
    relayer_fee: int

    def to_relay_args(self) -> dict[str, Any]:
        return {
            "old_root": self.request.old_root,
            "relayer_fee": self.request.fee,
            "expires_at": self.request.expires_at,
            "output_payloads": list(self.output_payloads),
        }


class ShieldedRelayTransferWallet(ShieldedWallet):
    def build_relay_transfer(
        self,
        *,
        recipient: ShieldedRecipient,
        amount: int,
        relayer: str,
        chain_id: str,
        fee: int,
        expires_at: Any = None,
        old_root: str | None = None,
        append_state: ShieldedTreeState | None = None,
        membership_commitments: list[str] | None = None,
        viewers=(),
        recipient_memo: str | None = None,
        change_memo: str | None = None,
        max_inputs: int = 4,
    ) -> ShieldedWalletRelayTransferPlan:
        if fee < 0:
            raise ValueError("fee must be non-negative")
        required_amount = amount + fee
        if required_amount <= 0:
            raise ValueError("amount + fee must be positive")
        if old_root is None:
            old_root = self.current_root()
        if append_state is None:
            append_state = self.tree_state()

        commitments = self._validated_membership_commitments(
            old_root, membership_commitments
        )
        input_notes = self.select_notes(required_amount, max_inputs=max_inputs)
        total_input = sum(note.amount for note in input_notes)
        change_amount = total_input - required_amount

        recipient_output = ShieldedOutput.for_recipient(
            recipient,
            amount=amount,
            rho=generate_field_hex(),
            blind=generate_field_hex(),
        )
        outputs = [recipient_output]
        payloads = [
            recipient_output.encrypt_for(
                asset_id=self.asset_id,
                viewing_public_key=recipient.viewing_public_key,
                viewers=viewers,
                memo=recipient_memo,
            )
        ]

        change_note = None
        if change_amount > 0:
            change_note = ShieldedNote(
                owner_secret=self.owner_secret,
                amount=change_amount,
                rho=generate_field_hex(),
                blind=generate_field_hex(),
            )
            outputs.append(change_note.to_output())
            payloads.append(
                change_note.to_output().encrypt_for(
                    asset_id=self.asset_id,
                    viewing_public_key=self.viewing_public_key,
                    memo=change_memo,
                )
            )

        input_nullifiers = [note.nullifier for note in input_notes]
        payload_hash_values = output_payload_hashes(payloads)
        binding = relay_transfer_binding(
            input_nullifiers=input_nullifiers,
            relayer=relayer,
            chain_id=chain_id,
            fee=fee,
            expires_at=expires_at,
        )
        execution_tag = relay_transfer_execution_tag(
            input_nullifiers=input_nullifiers,
            relay_binding=binding,
        )
        request = ShieldedRelayTransferRequest(
            asset_id=self.asset_id,
            old_root=old_root,
            append_state=append_state,
            fee=fee,
            inputs=[note.to_input(commitments) for note in input_notes],
            outputs=outputs,
            relayer=relayer,
            chain_id=chain_id,
            expires_at=expires_at,
            output_payload_hashes=payload_hash_values,
        )
        return ShieldedWalletRelayTransferPlan(
            request=request,
            input_notes=input_notes,
            recipient_output=recipient_output,
            change_note=change_note,
            output_payloads=payloads,
            output_payload_hashes=payload_hash_values,
            relay_binding=binding,
            execution_tag=execution_tag,
            relayer_fee=fee,
        )


class ShieldedRelayTransferProver:
    def __init__(self, bundle_json: str):
        self.bundle_json = bundle_json
        self.bundle = json.loads(bundle_json)
        self._bundle_handle = load_shielded_command_prover_bundle(bundle_json)

    @classmethod
    def build_insecure_dev_bundle(cls) -> "ShieldedRelayTransferProver":
        return cls(build_insecure_dev_shielded_command_bundle_json())

    @classmethod
    def build_random_bundle(
        cls,
        *,
        contract_name: str,
        vk_id_prefix: str,
    ) -> "ShieldedRelayTransferProver":
        return cls(
            build_random_shielded_command_bundle_json(
                contract_name,
                vk_id_prefix,
            )
        )

    def registry_manifest(
        self, *, artifact_contract_name: str | None = None
    ) -> dict[str, Any]:
        return shielded_relay_registry_manifest(
            self, artifact_contract_name=artifact_contract_name
        )

    def prove_relay_transfer(
        self, request: ShieldedRelayTransferRequest
    ) -> ShieldedRelayTransferProofResult:
        if len(request.inputs) == 0:
            raise ValueError(
                "shielded relay transfer requires at least one input"
            )

        input_nullifiers = []
        for shielded_input in request.inputs:
            input_note = ShieldedNote(
                owner_secret=shielded_input.owner_secret,
                amount=shielded_input.amount,
                rho=shielded_input.rho,
                blind=shielded_input.blind,
            )
            input_nullifiers.append(input_note.nullifier(request.asset_id))

        binding = relay_transfer_binding(
            input_nullifiers=input_nullifiers,
            relayer=request.relayer,
            chain_id=request.chain_id,
            fee=request.fee,
            expires_at=request.expires_at,
        )
        native_request = {
            "asset_id": request.asset_id,
            "old_root": request.old_root,
            "append_state": asdict(request.append_state),
            "fee": request.fee,
            "public_amount": 0,
            "inputs": [asdict(shielded_input) for shielded_input in request.inputs],
            "outputs": [asdict(output) for output in request.outputs],
            "command_binding": binding,
            "output_payload_hashes": list(request.output_payload_hashes),
        }
        result = json.loads(
            prove_shielded_command_execute(
                self._bundle_handle,
                _request_json(native_request),
            )
        )
        return ShieldedRelayTransferProofResult(
            proof_hex=result["proof_hex"],
            old_root=result["old_root"],
            expected_new_root=result["expected_new_root"],
            public_inputs=result["public_inputs"],
            relay_binding=result["command_binding"],
            execution_tag=result["execution_tag"],
            relayer_fee=request.fee,
            input_nullifiers=result["input_nullifiers"],
            output_commitments=result["output_commitments"],
            output_payload_hashes=result["output_payload_hashes"],
        )


def shielded_relay_registry_manifest(
    bundle: ShieldedRelayTransferProver | dict[str, Any],
    *,
    artifact_contract_name: str | None = None,
) -> dict[str, Any]:
    if isinstance(bundle, ShieldedRelayTransferProver):
        payload = bundle.bundle
    elif isinstance(bundle, dict):
        payload = bundle
    else:
        raise TypeError("bundle must be a ShieldedRelayTransferProver or dict")

    artifact_name = artifact_contract_name or payload["contract_name"]
    payload_json = json.dumps(payload, sort_keys=True)
    bundle_hash = _sha3_hex(payload_json)
    circuit = payload["command"]
    entry = {
        "action": _RELAY_ACTION,
        "vk_id": circuit["vk_id"],
        "vk_hex": circuit["vk_hex"],
        "circuit_name": circuit["circuit_name"],
        "version": circuit["version"],
        "artifact_contract_name": artifact_name,
        "circuit_family": payload["circuit_family"],
        "statement_version": circuit["version"],
        "tree_depth": payload["tree_depth"],
        "leaf_capacity": payload["leaf_capacity"],
        "max_inputs": payload["max_inputs"],
        "max_outputs": payload["max_outputs"],
        "setup_mode": payload.get("setup_mode", ""),
        "setup_ceremony": payload.get("setup_ceremony", ""),
        "bundle_hash": bundle_hash,
        "artifact_hash": _sha3_hex(json.dumps(circuit, sort_keys=True)),
        "warning": payload["warning"],
    }

    return {
        "contract_name": artifact_name,
        "circuit_family": payload["circuit_family"],
        "tree_depth": payload["tree_depth"],
        "leaf_capacity": payload["leaf_capacity"],
        "max_inputs": payload["max_inputs"],
        "max_outputs": payload["max_outputs"],
        "warning": payload["warning"],
        "setup_mode": payload.get("setup_mode", ""),
        "setup_ceremony": payload.get("setup_ceremony", ""),
        "bundle_hash": bundle_hash,
        "registry_entries": [entry],
        "configure_actions": [{"action": _RELAY_ACTION, "vk_id": circuit["vk_id"]}],
    }


__all__ = [
    "ShieldedRelayTransferProofResult",
    "ShieldedRelayTransferProver",
    "ShieldedRelayTransferRequest",
    "ShieldedRelayTransferWallet",
    "ShieldedWalletRelayTransferPlan",
    "relay_transfer_binding",
    "relay_transfer_entrypoint_digest",
    "relay_transfer_execution_tag",
    "relay_transfer_nullifier_digest",
    "relay_transfer_payload_digest",
    "relay_transfer_target_digest",
    "relay_transfer_version_digest",
    "shielded_relay_registry_manifest",
]
