from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
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
from xian_zk._native import (
    shielded_command_nullifier_digest as native_command_nullifier_digest,
)
from xian_zk.shielded_notes import (
    ShieldedDepositRequest,
    ShieldedInput,
    ShieldedNote,
    ShieldedOutput,
    ShieldedProofResult,
    ShieldedTreeState,
    ShieldedWallet,
    ShieldedWalletNote,
    ShieldedWithdrawRequest,
    generate_field_hex,
    output_payload_hashes,
    recipient_digest,
)

_FIELD_ZERO_HEX = "0x" + "00" * 32
_COMMAND_BINDING_VERSION = "shielded-command-v4"
_COMMAND_ENTRYPOINT = "interact"


def _sha3_hex(value: str) -> str:
    return "0x" + hashlib.sha3_256(value.encode("utf-8")).hexdigest()


def _request_json(request: Any) -> str:
    return json.dumps(request, sort_keys=True)


def _encode_payload_part(prefix: str, value: str) -> str:
    return f"{prefix}:{len(value)}:{value}"


def canonicalize_command_payload(value: Any) -> str:
    if value is None:
        return "n"
    if isinstance(value, bool):
        return "b:1" if value else "b:0"
    if isinstance(value, int):
        return f"i:{value}"
    if isinstance(value, str):
        return _encode_payload_part("s", value)
    if isinstance(value, dict):
        items = []
        for key in sorted(value.keys()):
            if not isinstance(key, str):
                raise TypeError("payload dict keys must be strings")
            items.append(_encode_payload_part("k", key))
            items.append(
                _encode_payload_part(
                    "v",
                    canonicalize_command_payload(value[key]),
                )
            )
        return f"d:{len(value)}:" + "".join(items)
    if isinstance(value, list):
        items = [
            _encode_payload_part("e", canonicalize_command_payload(item))
            for item in value
        ]
        return f"l:{len(value)}:" + "".join(items)
    raise TypeError("unsupported payload value type")


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


def command_chain_digest(chain_id: str) -> str:
    if not isinstance(chain_id, str) or chain_id == "":
        raise ValueError("chain_id must be a non-empty string")
    return recipient_digest(chain_id)


def command_expiry_digest(expires_at: Any = None) -> str:
    if expires_at is None:
        return _FIELD_ZERO_HEX
    if isinstance(expires_at, str) and expires_at == "":
        return _FIELD_ZERO_HEX
    return recipient_digest(str(expires_at))


def command_entrypoint_digest() -> str:
    return recipient_digest(_COMMAND_ENTRYPOINT)


def command_version_digest() -> str:
    return recipient_digest(_COMMAND_BINDING_VERSION)


def command_nullifier_digest(input_nullifiers: list[str]) -> str:
    if not isinstance(input_nullifiers, list) or len(input_nullifiers) == 0:
        raise ValueError("input_nullifiers must be a non-empty list")
    return native_command_nullifier_digest(input_nullifiers)


def command_binding(
    *,
    input_nullifiers: list[str],
    target_contract: str,
    payload: dict[str, Any] | None,
    relayer: str,
    chain_id: str,
    fee: int,
    public_amount: int = 0,
    expires_at: Any = None,
) -> str:
    return native_command_binding(
        command_nullifier_digest(input_nullifiers),
        command_target_digest(target_contract),
        command_payload_digest(payload),
        command_relayer_digest(relayer),
        command_expiry_digest(expires_at),
        command_chain_digest(chain_id),
        command_entrypoint_digest(),
        command_version_digest(),
        fee,
        public_amount,
    )


def command_execution_tag(
    *,
    input_nullifiers: list[str],
    command_binding_value: str,
) -> str:
    return native_command_execution_tag(
        command_nullifier_digest(input_nullifiers),
        command_binding_value,
    )


@dataclass(frozen=True)
class ShieldedCommandRequest:
    asset_id: str
    old_root: str
    append_state: ShieldedTreeState
    fee: int
    public_amount: int
    inputs: list[ShieldedInput]
    outputs: list[ShieldedOutput]
    target_contract: str
    payload: dict[str, Any] | None
    relayer: str
    chain_id: str
    expires_at: Any = None
    output_payload_hashes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ShieldedCommandProofResult:
    proof_hex: str
    old_root: str
    expected_new_root: str
    public_inputs: list[str]
    command_binding: str
    execution_tag: str
    public_amount: int
    input_nullifiers: list[str]
    output_commitments: list[str]
    output_payload_hashes: list[str]

    @classmethod
    def from_json(cls, payload: str) -> "ShieldedCommandProofResult":
        return cls(**json.loads(payload))


@dataclass(frozen=True)
class ShieldedCommandPlan:
    request: ShieldedCommandRequest
    input_notes: list[ShieldedWalletNote]
    change_note: ShieldedNote | None
    output_payloads: list[str]
    output_payload_hashes: list[str]
    command_binding: str
    execution_tag: str
    public_amount: int

    def to_execute_args(self) -> dict[str, Any]:
        return {
            "target_contract": self.request.target_contract,
            "old_root": self.request.old_root,
            "output_payloads": list(self.output_payloads),
            "relayer_fee": self.request.fee,
            "public_amount": self.public_amount,
            "payload": self.request.payload,
            "expires_at": self.request.expires_at,
        }


class ShieldedCommandWallet(ShieldedWallet):
    def build_command(
        self,
        *,
        target_contract: str,
        relayer: str,
        chain_id: str,
        fee: int,
        public_amount: int = 0,
        payload: dict[str, Any] | None = None,
        expires_at: Any = None,
        old_root: str | None = None,
        append_state: ShieldedTreeState | None = None,
        membership_commitments: list[str] | None = None,
        change_memo: str | None = None,
        max_inputs: int = 4,
    ) -> "ShieldedCommandPlan":
        if fee < 0:
            raise ValueError("fee must be non-negative")
        if public_amount < 0:
            raise ValueError("public_amount must be non-negative")
        required_amount = fee + public_amount
        if required_amount <= 0:
            raise ValueError("fee + public_amount must be positive")
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

        outputs: list[ShieldedOutput] = []
        payloads: list[str] = []
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
        binding = command_binding(
            input_nullifiers=input_nullifiers,
            target_contract=target_contract,
            payload=payload,
            relayer=relayer,
            chain_id=chain_id,
            fee=fee,
            public_amount=public_amount,
            expires_at=expires_at,
        )
        execution_tag = command_execution_tag(
            input_nullifiers=input_nullifiers,
            command_binding_value=binding,
        )
        request = ShieldedCommandRequest(
            asset_id=self.asset_id,
            old_root=old_root,
            append_state=append_state,
            fee=fee,
            public_amount=public_amount,
            inputs=[note.to_input(commitments) for note in input_notes],
            outputs=outputs,
            target_contract=target_contract,
            payload=payload,
            relayer=relayer,
            chain_id=chain_id,
            expires_at=expires_at,
            output_payload_hashes=payload_hash_values,
        )
        return ShieldedCommandPlan(
            request=request,
            input_notes=input_notes,
            change_note=change_note,
            output_payloads=payloads,
            output_payload_hashes=payload_hash_values,
            command_binding=binding,
            execution_tag=execution_tag,
            public_amount=public_amount,
        )


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
        if len(request.inputs) == 0:
            raise ValueError(
                "Shielded command execution requires at least one input"
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

        binding = command_binding(
            input_nullifiers=input_nullifiers,
            target_contract=request.target_contract,
            payload=request.payload,
            relayer=request.relayer,
            chain_id=request.chain_id,
            fee=request.fee,
            public_amount=request.public_amount,
            expires_at=request.expires_at,
        )
        native_request = {
            "asset_id": request.asset_id,
            "old_root": request.old_root,
            "append_state": asdict(request.append_state),
            "fee": request.fee,
            "public_amount": request.public_amount,
            "inputs": [
                asdict(shielded_input) for shielded_input in request.inputs
            ],
            "outputs": [asdict(output) for output in request.outputs],
            "command_binding": binding,
            "output_payload_hashes": list(request.output_payload_hashes),
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

    payload_json = json.dumps(payload, sort_keys=True)
    bundle_hash = _sha3_hex(payload_json)
    entries = []
    configure_actions = []
    for action in ("deposit", "command", "withdraw"):
        circuit = payload[action]
        entries.append(
            {
                "action": action,
                "vk_id": circuit["vk_id"],
                "vk_hex": circuit["vk_hex"],
                "circuit_name": circuit["circuit_name"],
                "version": circuit["version"],
                "artifact_contract_name": payload["contract_name"],
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
        "setup_mode": payload.get("setup_mode", ""),
        "setup_ceremony": payload.get("setup_ceremony", ""),
        "bundle_hash": bundle_hash,
        "registry_entries": entries,
        "configure_actions": configure_actions,
    }


__all__ = [
    "ShieldedCommandPlan",
    "ShieldedCommandProofResult",
    "ShieldedCommandProver",
    "ShieldedCommandRequest",
    "ShieldedCommandWallet",
    "canonicalize_command_payload",
    "command_binding",
    "command_chain_digest",
    "command_execution_tag",
    "command_expiry_digest",
    "command_nullifier_digest",
    "command_payload_digest",
    "command_relayer_digest",
    "command_target_digest",
    "shielded_command_registry_manifest",
]
