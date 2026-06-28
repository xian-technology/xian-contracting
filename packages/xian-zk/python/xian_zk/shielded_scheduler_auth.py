from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any

from xian_zk._native import (
    build_insecure_dev_shielded_scheduler_auth_bundle_json,
    build_random_shielded_scheduler_auth_bundle_json,
    load_shielded_scheduler_auth_prover_bundle,
    prove_shielded_scheduler_auth,
)
from xian_zk._native import (
    shielded_scheduler_owner_commitment as native_scheduler_owner_commitment,
)
from xian_zk._native import (
    shielded_scheduler_update_nullifier as native_scheduler_update_nullifier,
)
from xian_zk._native import (
    shielded_scheduler_update_public_inputs as native_scheduler_update_public_inputs,
)
from xian_zk.bundles import validate_shielded_scheduler_auth_bundle


def _sha3_hex(value: str) -> str:
    return "0x" + hashlib.sha3_256(value.encode("utf-8")).hexdigest()


def _request_json(request: Any) -> str:
    return json.dumps(request, sort_keys=True)


def scheduler_owner_commitment(owner_secret: str) -> str:
    return native_scheduler_owner_commitment(owner_secret)


def scheduler_update_nullifier(owner_secret: str, update_digest: str) -> str:
    return native_scheduler_update_nullifier(owner_secret, update_digest)


def scheduler_update_public_inputs(
    *,
    owner_commitment: str,
    update_digest: str,
    update_nullifier: str,
) -> list[str]:
    return native_scheduler_update_public_inputs(
        owner_commitment,
        update_digest,
        update_nullifier,
    )


@dataclass(frozen=True)
class ShieldedSchedulerAuthRequest:
    owner_secret: str
    update_digest: str


@dataclass(frozen=True)
class ShieldedSchedulerAuthProofResult:
    proof_hex: str
    public_inputs: list[str]
    owner_commitment: str
    update_digest: str
    update_nullifier: str

    @classmethod
    def from_json(cls, payload: str) -> "ShieldedSchedulerAuthProofResult":
        return cls(**json.loads(payload))


class ShieldedSchedulerAuthProver:
    def __init__(self, bundle_json: str):
        normalized_bundle = validate_shielded_scheduler_auth_bundle(bundle_json)
        self.bundle = normalized_bundle
        self.bundle_json = json.dumps(normalized_bundle, sort_keys=True)
        self._bundle_handle = load_shielded_scheduler_auth_prover_bundle(self.bundle_json)

    @classmethod
    def build_insecure_dev_bundle(cls) -> "ShieldedSchedulerAuthProver":
        return cls(build_insecure_dev_shielded_scheduler_auth_bundle_json())

    @classmethod
    def build_random_bundle(
        cls,
        *,
        contract_name: str,
        vk_id_prefix: str,
    ) -> "ShieldedSchedulerAuthProver":
        return cls(
            build_random_shielded_scheduler_auth_bundle_json(
                contract_name,
                vk_id_prefix,
            )
        )

    def registry_manifest(self) -> dict[str, Any]:
        return shielded_scheduler_auth_registry_manifest(self)

    def prove_update(
        self,
        request: ShieldedSchedulerAuthRequest,
    ) -> ShieldedSchedulerAuthProofResult:
        return ShieldedSchedulerAuthProofResult.from_json(
            prove_shielded_scheduler_auth(
                self._bundle_handle,
                _request_json(asdict(request)),
            )
        )


def shielded_scheduler_auth_registry_manifest(
    bundle: ShieldedSchedulerAuthProver | dict[str, Any],
) -> dict[str, Any]:
    if isinstance(bundle, ShieldedSchedulerAuthProver):
        payload = bundle.bundle
    elif isinstance(bundle, dict):
        payload = validate_shielded_scheduler_auth_bundle(
            bundle,
            require_private_keys=False,
        )
    else:
        raise TypeError("bundle must be a ShieldedSchedulerAuthProver or dict")

    payload_json = json.dumps(payload, sort_keys=True)
    bundle_hash = _sha3_hex(payload_json)
    circuit = payload["action"]
    entry = {
        "action": "authorize_update",
        "vk_id": circuit["vk_id"],
        "vk_hex": circuit["vk_hex"],
        "circuit_name": circuit["circuit_name"],
        "version": circuit["version"],
        "artifact_contract_name": payload["contract_name"],
        "circuit_family": payload["circuit_family"],
        "statement_version": circuit["version"],
        "tree_depth": payload.get("tree_depth", 0),
        "leaf_capacity": payload.get("leaf_capacity", 0),
        "max_inputs": payload.get("max_inputs", 0),
        "max_outputs": payload.get("max_outputs", 0),
        "setup_mode": payload.get("setup_mode", ""),
        "setup_ceremony": payload.get("setup_ceremony", ""),
        "bundle_hash": bundle_hash,
        "artifact_hash": _sha3_hex(json.dumps(circuit, sort_keys=True)),
        "warning": payload["warning"],
    }
    return {
        "contract_name": payload["contract_name"],
        "circuit_family": payload["circuit_family"],
        "tree_depth": payload.get("tree_depth", 0),
        "leaf_capacity": payload.get("leaf_capacity", 0),
        "max_inputs": payload.get("max_inputs", 0),
        "max_outputs": payload.get("max_outputs", 0),
        "warning": payload["warning"],
        "setup_mode": payload.get("setup_mode", ""),
        "setup_ceremony": payload.get("setup_ceremony", ""),
        "bundle_hash": bundle_hash,
        "registry_entries": [entry],
        "configure_actions": [
            {
                "action": "authorize_update",
                "vk_id": circuit["vk_id"],
            }
        ],
    }


__all__ = [
    "ShieldedSchedulerAuthProofResult",
    "ShieldedSchedulerAuthProver",
    "ShieldedSchedulerAuthRequest",
    "scheduler_owner_commitment",
    "scheduler_update_nullifier",
    "scheduler_update_public_inputs",
    "shielded_scheduler_auth_registry_manifest",
]
