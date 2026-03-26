from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Sequence

from xian_zk._native import (
    build_insecure_dev_shielded_note_bundle_json,
    load_shielded_note_prover_bundle,
    prove_shielded_note_deposit,
    prove_shielded_note_transfer,
    prove_shielded_note_withdraw,
    shielded_note_asset_id,
    shielded_note_note_commitment,
    shielded_note_nullifier,
    shielded_note_recipient_digest,
    shielded_note_root,
    shielded_note_zero_root,
)


@dataclass(frozen=True)
class ShieldedNote:
    owner_secret: str
    amount: int
    rho: str
    blind: str

    def to_output(self) -> "ShieldedOutput":
        return ShieldedOutput(
            owner_secret=self.owner_secret,
            amount=self.amount,
            rho=self.rho,
            blind=self.blind,
        )

    def commitment(self, asset_id: str) -> str:
        return shielded_note_note_commitment(
            asset_id,
            self.owner_secret,
            self.amount,
            self.rho,
            self.blind,
        )

    def nullifier(self, asset_id: str) -> str:
        return shielded_note_nullifier(asset_id, self.owner_secret, self.rho)


@dataclass(frozen=True)
class ShieldedOutput:
    owner_secret: str
    amount: int
    rho: str
    blind: str


@dataclass(frozen=True)
class ShieldedInput:
    owner_secret: str
    amount: int
    rho: str
    blind: str
    leaf_index: int

    @classmethod
    def from_note(cls, note: ShieldedNote, leaf_index: int) -> "ShieldedInput":
        return cls(
            owner_secret=note.owner_secret,
            amount=note.amount,
            rho=note.rho,
            blind=note.blind,
            leaf_index=leaf_index,
        )


@dataclass(frozen=True)
class ShieldedDepositRequest:
    asset_id: str
    old_commitments: list[str]
    amount: int
    outputs: list[ShieldedOutput]


@dataclass(frozen=True)
class ShieldedTransferRequest:
    asset_id: str
    old_commitments: list[str]
    inputs: list[ShieldedInput]
    outputs: list[ShieldedOutput]


@dataclass(frozen=True)
class ShieldedWithdrawRequest:
    asset_id: str
    old_commitments: list[str]
    amount: int
    recipient: str
    inputs: list[ShieldedInput]
    outputs: list[ShieldedOutput]


@dataclass(frozen=True)
class ShieldedProofResult:
    proof_hex: str
    old_root: str
    expected_new_root: str
    public_inputs: list[str]
    input_nullifiers: list[str]
    output_commitments: list[str]

    @classmethod
    def from_json(cls, payload: str) -> "ShieldedProofResult":
        return cls(**json.loads(payload))


@dataclass(frozen=True)
class ShieldedDiscoveredNote:
    note: ShieldedNote
    commitment: str
    leaf_index: int

    def to_input(self) -> ShieldedInput:
        return ShieldedInput.from_note(self.note, self.leaf_index)


class ShieldedNoteProver:
    def __init__(self, bundle_json: str):
        self.bundle_json = bundle_json
        self.bundle = json.loads(bundle_json)
        self._bundle_handle = load_shielded_note_prover_bundle(bundle_json)

    @classmethod
    def build_insecure_dev_bundle(cls) -> "ShieldedNoteProver":
        return cls(build_insecure_dev_shielded_note_bundle_json())

    def prove_deposit(
        self, request: ShieldedDepositRequest
    ) -> ShieldedProofResult:
        return ShieldedProofResult.from_json(
            prove_shielded_note_deposit(
                self._bundle_handle,
                _request_json(request),
            )
        )

    def prove_transfer(
        self, request: ShieldedTransferRequest
    ) -> ShieldedProofResult:
        return ShieldedProofResult.from_json(
            prove_shielded_note_transfer(
                self._bundle_handle,
                _request_json(request),
            )
        )

    def prove_withdraw(
        self, request: ShieldedWithdrawRequest
    ) -> ShieldedProofResult:
        return ShieldedProofResult.from_json(
            prove_shielded_note_withdraw(
                self._bundle_handle,
                _request_json(request),
            )
        )


def asset_id_for_contract(contract_name: str) -> str:
    return shielded_note_asset_id(contract_name)


def recipient_digest(recipient: str) -> str:
    return shielded_note_recipient_digest(recipient)


def zero_root() -> str:
    return shielded_note_zero_root()


def merkle_root(commitments: Sequence[str]) -> str:
    return shielded_note_root(list(commitments))


def scan_notes(
    *, asset_id: str, commitments: Sequence[str], notes: Sequence[ShieldedNote]
) -> list[ShieldedDiscoveredNote]:
    indexed_commitments = {
        commitment: index for index, commitment in enumerate(commitments)
    }
    discovered: list[ShieldedDiscoveredNote] = []
    for note in notes:
        commitment = note.commitment(asset_id)
        leaf_index = indexed_commitments.get(commitment)
        if leaf_index is None:
            continue
        discovered.append(
            ShieldedDiscoveredNote(
                note=note,
                commitment=commitment,
                leaf_index=leaf_index,
            )
        )
    return discovered


def _request_json(request: Any) -> str:
    return json.dumps(asdict(request), sort_keys=True)
