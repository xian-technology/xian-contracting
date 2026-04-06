from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Callable, Sequence

from nacl.bindings import (
    crypto_sign_ed25519_pk_to_curve25519,
    crypto_sign_ed25519_sk_to_curve25519,
)
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey

from xian_zk._native import (
    build_insecure_dev_shielded_note_bundle_json,
    build_random_shielded_note_bundle_json,
    load_shielded_note_prover_bundle,
    prove_shielded_note_deposit,
    prove_shielded_note_transfer,
    prove_shielded_note_withdraw,
    shielded_note_asset_id,
    shielded_note_auth_path,
    shielded_note_note_commitment,
    shielded_note_nullifier,
    shielded_note_output_commitment,
    shielded_note_owner_public,
    shielded_note_recipient_digest,
    shielded_note_root,
    shielded_note_tree_state_json,
    shielded_note_zero_root,
    shielded_output_payload_hash,
)

_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
_FIELD_ZERO_HEX = "0x" + "00" * 32
_PAYLOAD_VERSION = 1
_SHIELDED_NOTE_MAX_INPUTS = 4
_SHIELDED_NOTE_MAX_OUTPUTS = 4


def _sha3_hex(value: str) -> str:
    return "0x" + hashlib.sha3_256(value.encode("utf-8")).hexdigest()


def _canonical_field_hex(value: int) -> str:
    return f"0x{value:064x}"


def _canonical_hex(raw: bytes) -> str:
    return "0x" + raw.hex()


def _normalize_hex_bytes(
    value: str, *, expected_len: int | None = None
) -> bytes:
    if not isinstance(value, str):
        raise ValueError("hex value must be a string")
    trimmed = value[2:] if value.startswith("0x") else value
    raw = bytes.fromhex(trimmed)
    if expected_len is not None and len(raw) != expected_len:
        raise ValueError(f"expected {expected_len} bytes")
    return raw


def _signing_key_from_private_key(private_key: str) -> SigningKey:
    return SigningKey(_normalize_hex_bytes(private_key, expected_len=32))


def _public_key_from_private_key(private_key: str) -> str:
    return _signing_key_from_private_key(private_key).verify_key.encode().hex()


def _x25519_public_key_from_ed25519(public_key: str) -> PublicKey:
    ed25519_key = _normalize_hex_bytes(public_key, expected_len=32)
    return PublicKey(crypto_sign_ed25519_pk_to_curve25519(ed25519_key))


def _x25519_private_key_from_ed25519(private_key: str) -> PrivateKey:
    signing_key = _signing_key_from_private_key(private_key)
    full_secret = signing_key.encode() + signing_key.verify_key.encode()
    return PrivateKey(crypto_sign_ed25519_sk_to_curve25519(full_secret))


def _encode_payload_json(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return _canonical_hex(payload)


def _decode_payload_json(payload_hex: str) -> dict[str, object] | None:
    try:
        raw = _normalize_hex_bytes(payload_hex)
        decoded = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(decoded, dict):
        return None
    return decoded


def _resolve_viewing_public_key(
    viewing_private_key: str,
    viewing_public_key: str | None = None,
) -> str:
    if viewing_public_key is not None:
        return viewing_public_key
    return _public_key_from_private_key(viewing_private_key)


def _normalize_viewer(
    viewer: "ShieldedViewer | ShieldedRecipient | str",
) -> "ShieldedViewer":
    if isinstance(viewer, ShieldedViewer):
        return viewer
    if isinstance(viewer, ShieldedRecipient):
        return ShieldedViewer(
            viewing_public_key=viewer.viewing_public_key,
            label=viewer.label,
        )
    if isinstance(viewer, str):
        return ShieldedViewer(viewing_public_key=viewer)
    raise TypeError(
        "viewer must be a ShieldedViewer, ShieldedRecipient, or hex key"
    )


def _encrypt_message_for_public_key(
    message: str,
    viewing_public_key: str,
) -> str:
    sealed_box = SealedBox(_x25519_public_key_from_ed25519(viewing_public_key))
    ciphertext = sealed_box.encrypt(message.encode("utf-8"))
    return _canonical_hex(ciphertext)


def generate_owner_secret() -> str:
    return _canonical_field_hex(secrets.randbelow(_FIELD_MODULUS))


def generate_field_hex() -> str:
    return _canonical_field_hex(secrets.randbelow(_FIELD_MODULUS))


def owner_public(owner_secret: str) -> str:
    return shielded_note_owner_public(owner_secret)


def output_commitment(
    asset_id: str,
    owner_public_hex: str,
    amount: int,
    rho: str,
    blind: str,
) -> str:
    return shielded_note_output_commitment(
        asset_id,
        owner_public_hex,
        amount,
        rho,
        blind,
    )


def output_payload_hash(payload_hex: str | None = None) -> str:
    if payload_hex in (None, ""):
        return _FIELD_ZERO_HEX
    return shielded_output_payload_hash(payload_hex)


def output_payload_hashes(payloads: Sequence[str | None]) -> list[str]:
    return [output_payload_hash(payload) for payload in payloads]


@dataclass(frozen=True)
class ShieldedViewer:
    viewing_public_key: str
    label: str | None = None


@dataclass(frozen=True)
class ShieldedRecipient:
    owner_public: str
    viewing_public_key: str
    label: str | None = None

    @property
    def viewer(self) -> ShieldedViewer:
        return ShieldedViewer(
            viewing_public_key=self.viewing_public_key,
            label=self.label,
        )


@dataclass(frozen=True)
class ShieldedViewingKeyBundle:
    viewing_private_key: str
    viewing_public_key: str

    @classmethod
    def generate(cls) -> "ShieldedViewingKeyBundle":
        signing_key = SigningKey.generate()
        private_key = signing_key.encode().hex()
        return cls(
            viewing_private_key=private_key,
            viewing_public_key=signing_key.verify_key.encode().hex(),
        )

    @classmethod
    def from_private_key(
        cls, viewing_private_key: str
    ) -> "ShieldedViewingKeyBundle":
        return cls(
            viewing_private_key=viewing_private_key,
            viewing_public_key=_public_key_from_private_key(
                viewing_private_key
            ),
        )

    @property
    def viewer(self) -> ShieldedViewer:
        return ShieldedViewer(viewing_public_key=self.viewing_public_key)


@dataclass(frozen=True)
class ShieldedKeyBundle:
    owner_secret: str
    viewing_private_key: str
    viewing_public_key: str

    @classmethod
    def generate(cls) -> "ShieldedKeyBundle":
        viewing = ShieldedViewingKeyBundle.generate()
        return cls(
            owner_secret=generate_owner_secret(),
            viewing_private_key=viewing.viewing_private_key,
            viewing_public_key=viewing.viewing_public_key,
        )

    @classmethod
    def from_parts(
        cls,
        *,
        owner_secret: str,
        viewing_private_key: str,
    ) -> "ShieldedKeyBundle":
        viewing = ShieldedViewingKeyBundle.from_private_key(viewing_private_key)
        return cls(
            owner_secret=owner_secret,
            viewing_private_key=viewing.viewing_private_key,
            viewing_public_key=viewing.viewing_public_key,
        )

    @property
    def owner_public(self) -> str:
        return owner_public(self.owner_secret)

    @property
    def recipient(self) -> ShieldedRecipient:
        return ShieldedRecipient(
            owner_public=self.owner_public,
            viewing_public_key=self.viewing_public_key,
        )

    @property
    def viewer(self) -> ShieldedViewer:
        return ShieldedViewer(viewing_public_key=self.viewing_public_key)

    @property
    def viewing_bundle(self) -> ShieldedViewingKeyBundle:
        return ShieldedViewingKeyBundle(
            viewing_private_key=self.viewing_private_key,
            viewing_public_key=self.viewing_public_key,
        )


@dataclass(frozen=True)
class ShieldedNote:
    owner_secret: str
    amount: int
    rho: str
    blind: str

    def owner_public(self) -> str:
        return owner_public(self.owner_secret)

    def to_output(self) -> "ShieldedOutput":
        return ShieldedOutput(
            owner_public=self.owner_public(),
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
    owner_public: str
    amount: int
    rho: str
    blind: str

    @classmethod
    def for_owner_secret(
        cls,
        owner_secret: str,
        amount: int,
        rho: str,
        blind: str,
    ) -> "ShieldedOutput":
        return cls(
            owner_public=owner_public(owner_secret),
            amount=amount,
            rho=rho,
            blind=blind,
        )

    @classmethod
    def for_recipient(
        cls,
        recipient: ShieldedRecipient,
        amount: int,
        rho: str,
        blind: str,
    ) -> "ShieldedOutput":
        return cls(
            owner_public=recipient.owner_public,
            amount=amount,
            rho=rho,
            blind=blind,
        )

    def commitment(self, asset_id: str) -> str:
        return output_commitment(
            asset_id,
            self.owner_public,
            self.amount,
            self.rho,
            self.blind,
        )

    def to_message(
        self,
        asset_id: str,
        memo: str | None = None,
    ) -> "ShieldedNoteMessage":
        return ShieldedNoteMessage.from_output(asset_id, self, memo=memo)

    def encrypt_for(
        self,
        *,
        asset_id: str,
        viewing_public_key: str,
        viewers: Sequence[ShieldedViewer | ShieldedRecipient | str] = (),
        memo: str | None = None,
    ) -> str:
        return encrypt_note_message(
            self.to_message(asset_id, memo=memo),
            viewing_public_key=viewing_public_key,
            viewers=viewers,
        )


@dataclass(frozen=True)
class ShieldedNoteMessage:
    asset_id: str
    owner_public: str
    amount: int
    rho: str
    blind: str
    commitment: str
    memo: str | None = None
    version: int = 1

    @classmethod
    def from_output(
        cls,
        asset_id: str,
        output: ShieldedOutput,
        memo: str | None = None,
    ) -> "ShieldedNoteMessage":
        return cls(
            asset_id=asset_id,
            owner_public=output.owner_public,
            amount=output.amount,
            rho=output.rho,
            blind=output.blind,
            commitment=output.commitment(asset_id),
            memo=memo,
        )

    @classmethod
    def from_json(cls, payload: str) -> "ShieldedNoteMessage":
        return cls(**json.loads(payload))

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    def to_output(self) -> ShieldedOutput:
        return ShieldedOutput(
            owner_public=self.owner_public,
            amount=self.amount,
            rho=self.rho,
            blind=self.blind,
        )

    def to_owned_note(self, owner_secret: str) -> ShieldedNote:
        if owner_public(owner_secret) != self.owner_public:
            raise ValueError("owner_secret does not match note owner_public")
        note = ShieldedNote(
            owner_secret=owner_secret,
            amount=self.amount,
            rho=self.rho,
            blind=self.blind,
        )
        if note.commitment(self.asset_id) != self.commitment:
            raise ValueError(
                "note message commitment does not match note fields"
            )
        return note


@dataclass(frozen=True)
class ShieldedPayloadCiphertext:
    viewing_public_key: str
    ciphertext: str
    label: str | None = None


@dataclass(frozen=True)
class ShieldedNotePayload:
    ciphertexts: list[ShieldedPayloadCiphertext]
    version: int = _PAYLOAD_VERSION

    @classmethod
    def encrypt(
        cls,
        message: ShieldedNoteMessage,
        viewers: Sequence[ShieldedViewer | ShieldedRecipient | str],
    ) -> "ShieldedNotePayload":
        plaintext = message.to_json()
        unique: dict[str, ShieldedPayloadCiphertext] = {}
        for raw_viewer in viewers:
            viewer = _normalize_viewer(raw_viewer)
            unique[viewer.viewing_public_key] = ShieldedPayloadCiphertext(
                viewing_public_key=viewer.viewing_public_key,
                ciphertext=_encrypt_message_for_public_key(
                    plaintext, viewer.viewing_public_key
                ),
                label=viewer.label,
            )
        return cls(ciphertexts=list(unique.values()))

    @classmethod
    def from_hex(cls, payload_hex: str) -> "ShieldedNotePayload | None":
        decoded = _decode_payload_json(payload_hex)
        if decoded is None:
            return None
        if decoded.get("version") != _PAYLOAD_VERSION:
            return None
        ciphertexts = decoded.get("ciphertexts")
        if not isinstance(ciphertexts, list):
            return None

        entries: list[ShieldedPayloadCiphertext] = []
        for item in ciphertexts:
            if not isinstance(item, dict):
                return None
            viewing_public_key = item.get("viewing_public_key")
            ciphertext = item.get("ciphertext")
            label = item.get("label")
            if not isinstance(viewing_public_key, str) or not isinstance(
                ciphertext, str
            ):
                return None
            if label is not None and not isinstance(label, str):
                return None
            entries.append(
                ShieldedPayloadCiphertext(
                    viewing_public_key=viewing_public_key,
                    ciphertext=ciphertext,
                    label=label,
                )
            )
        return cls(ciphertexts=entries)

    def to_hex(self) -> str:
        return _encode_payload_json(asdict(self))


@dataclass(frozen=True)
class ShieldedTreeState:
    root: str
    note_count: int
    filled_subtrees: list[str]


@dataclass(frozen=True)
class ShieldedInput:
    owner_secret: str
    amount: int
    rho: str
    blind: str
    leaf_index: int
    merkle_path: list[str]

    @classmethod
    def from_note(
        cls, note: ShieldedNote, leaf_index: int, merkle_path: list[str]
    ) -> "ShieldedInput":
        return cls(
            owner_secret=note.owner_secret,
            amount=note.amount,
            rho=note.rho,
            blind=note.blind,
            leaf_index=leaf_index,
            merkle_path=merkle_path,
        )


@dataclass(frozen=True)
class ShieldedDepositRequest:
    asset_id: str
    old_root: str
    append_state: ShieldedTreeState
    amount: int
    outputs: list[ShieldedOutput]
    output_payload_hashes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ShieldedTransferRequest:
    asset_id: str
    old_root: str
    append_state: ShieldedTreeState
    inputs: list[ShieldedInput]
    outputs: list[ShieldedOutput]
    output_payload_hashes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ShieldedWithdrawRequest:
    asset_id: str
    old_root: str
    append_state: ShieldedTreeState
    amount: int
    recipient: str
    inputs: list[ShieldedInput]
    outputs: list[ShieldedOutput]
    output_payload_hashes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ShieldedProofResult:
    proof_hex: str
    old_root: str
    expected_new_root: str
    public_inputs: list[str]
    input_nullifiers: list[str]
    output_commitments: list[str]
    output_payload_hashes: list[str]

    @classmethod
    def from_json(cls, payload: str) -> "ShieldedProofResult":
        return cls(**json.loads(payload))


@dataclass(frozen=True)
class ShieldedDiscoveredNote:
    note: ShieldedNote
    commitment: str
    leaf_index: int
    merkle_path: list[str]

    def to_input(self) -> ShieldedInput:
        return ShieldedInput.from_note(
            self.note, self.leaf_index, self.merkle_path
        )


@dataclass(frozen=True)
class ShieldedViewableNote:
    message: ShieldedNoteMessage
    commitment: str
    leaf_index: int
    disclosure_label: str | None = None

    def to_owned_note(self, owner_secret: str) -> ShieldedNote:
        return self.message.to_owned_note(owner_secret)


@dataclass(frozen=True)
class ShieldedNoteRecord:
    index: int
    commitment: str
    payload: str | None = None
    payload_hash: str | None = None
    created_at: Any = None

    @classmethod
    def from_value(
        cls, value: "ShieldedNoteRecord | dict[str, Any]"
    ) -> "ShieldedNoteRecord":
        if isinstance(value, cls):
            return value
        if not isinstance(value, dict):
            raise TypeError(
                "note record must be a ShieldedNoteRecord or mapping"
            )

        index = value.get("index")
        commitment = value.get("commitment")
        payload = value.get("payload")
        payload_hash = value.get("payload_hash")

        if not isinstance(index, int):
            raise ValueError("note record index must be an integer")
        if not isinstance(commitment, str):
            raise ValueError("note record commitment must be a string")
        if payload is not None and not isinstance(payload, str):
            raise ValueError("note record payload must be a string or None")
        if payload_hash is not None and not isinstance(payload_hash, str):
            raise ValueError(
                "note record payload_hash must be a string or None"
            )

        return cls(
            index=index,
            commitment=commitment,
            payload=payload,
            payload_hash=payload_hash,
            created_at=value.get("created_at"),
        )


def _transaction_mapping(
    value: Any,
) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    raw = getattr(value, "raw", None)
    if isinstance(raw, Mapping):
        return raw
    raise TypeError("transaction must be a mapping or have a raw mapping")


def _transaction_json_mapping(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if not isinstance(value, str) or value == "":
        return None
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return None
    return decoded if isinstance(decoded, Mapping) else None


def _transaction_int(raw: Mapping[str, Any], key: str) -> int:
    value = raw.get(key)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _transaction_success(raw: Mapping[str, Any]) -> bool:
    success = raw.get("success")
    if isinstance(success, bool):
        return success

    status_code = raw.get("status_code")
    if isinstance(status_code, int):
        return status_code == 0
    if isinstance(status_code, str) and status_code.isdigit():
        return int(status_code) == 0

    result = raw.get("result")
    if isinstance(result, Mapping):
        status = result.get("status")
        if isinstance(status, int):
            return status == 0
        if isinstance(status, str) and status.isdigit():
            return int(status) == 0

    return True


def note_records_from_transactions(
    transactions: Sequence[Any],
    *,
    functions: Sequence[str] | None = None,
    starting_index: int = 0,
) -> list[ShieldedNoteRecord]:
    allowed_functions = set(functions) if functions is not None else None
    normalized = sorted(
        (_transaction_mapping(tx) for tx in transactions),
        key=lambda raw: (
            _transaction_int(raw, "block_height"),
            _transaction_int(raw, "tx_index"),
            _transaction_int(raw, "nonce"),
            str(raw.get("tx_hash") or raw.get("hash") or ""),
        ),
    )

    records: list[ShieldedNoteRecord] = []
    next_index = starting_index

    for raw in normalized:
        if not _transaction_success(raw):
            continue

        payload = _transaction_json_mapping(raw.get("payload"))
        if payload is None:
            envelope = _transaction_json_mapping(raw.get("envelope"))
            if envelope is not None:
                payload = _transaction_json_mapping(envelope.get("payload"))
        if payload is None:
            continue

        function = payload.get("function")
        if allowed_functions is not None and function not in allowed_functions:
            continue

        kwargs = _transaction_json_mapping(payload.get("kwargs"))
        if kwargs is None:
            continue

        commitments = kwargs.get("output_commitments")
        if commitments is None:
            continue
        if not isinstance(commitments, list):
            raise ValueError("transaction output_commitments must be a list")

        payloads = kwargs.get("output_payloads")
        if payloads is None:
            payloads = [""] * len(commitments)
        elif not isinstance(payloads, list):
            raise ValueError("transaction output_payloads must be a list")
        elif len(payloads) != len(commitments):
            raise ValueError(
                "transaction output_payloads length must match commitments"
            )

        created_at = raw.get("created_at") or raw.get("created")
        for commitment, payload_hex in zip(commitments, payloads, strict=True):
            if not isinstance(commitment, str):
                raise ValueError("transaction commitment must be a string")
            if payload_hex in (None, ""):
                normalized_payload = None
            elif not isinstance(payload_hex, str):
                raise ValueError("transaction output payload must be a string")
            else:
                normalized_payload = payload_hex

            records.append(
                ShieldedNoteRecord(
                    index=next_index,
                    commitment=commitment,
                    payload=normalized_payload,
                    payload_hash=output_payload_hash(normalized_payload),
                    created_at=created_at,
                )
            )
            next_index += 1

    return records


@dataclass(frozen=True)
class ShieldedWalletNote:
    note: ShieldedNote
    commitment: str
    leaf_index: int
    nullifier: str
    memo: str | None = None
    created_at: Any = None
    spent: bool = False

    @property
    def amount(self) -> int:
        return self.note.amount

    def to_input(self, commitments: Sequence[str]) -> ShieldedInput:
        commitment_list = list(commitments)
        if self.leaf_index >= len(commitment_list):
            raise ValueError("wallet note leaf_index is out of range")
        if commitment_list[self.leaf_index] != self.commitment:
            raise ValueError(
                "wallet note commitment does not match membership set"
            )
        return ShieldedInput.from_note(
            self.note,
            self.leaf_index,
            shielded_note_auth_path(commitment_list, self.leaf_index),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "note": asdict(self.note),
            "commitment": self.commitment,
            "leaf_index": self.leaf_index,
            "nullifier": self.nullifier,
            "memo": self.memo,
            "created_at": self.created_at,
            "spent": self.spent,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ShieldedWalletNote":
        note_payload = value.get("note")
        if not isinstance(note_payload, dict):
            raise ValueError("wallet note payload is missing note fields")
        return cls(
            note=ShieldedNote(**note_payload),
            commitment=value["commitment"],
            leaf_index=value["leaf_index"],
            nullifier=value["nullifier"],
            memo=value.get("memo"),
            created_at=value.get("created_at"),
            spent=bool(value.get("spent", False)),
        )


@dataclass(frozen=True)
class ShieldedWalletSyncResult:
    scanned_record_count: int
    discovered_notes: list[ShieldedWalletNote]
    last_scanned_index: int


@dataclass(frozen=True)
class ShieldedWalletDepositPlan:
    request: ShieldedDepositRequest
    created_notes: list[ShieldedNote]
    output_payloads: list[str]
    output_payload_hashes: list[str]


@dataclass(frozen=True)
class ShieldedWalletTransferPlan:
    request: ShieldedTransferRequest
    input_notes: list[ShieldedWalletNote]
    recipient_output: ShieldedOutput
    change_note: ShieldedNote | None
    output_payloads: list[str]
    output_payload_hashes: list[str]


@dataclass(frozen=True)
class ShieldedWalletWithdrawPlan:
    request: ShieldedWithdrawRequest
    input_notes: list[ShieldedWalletNote]
    change_note: ShieldedNote | None
    output_payloads: list[str]
    output_payload_hashes: list[str]


class ShieldedWallet:
    def __init__(
        self,
        *,
        asset_id: str,
        key_bundle: ShieldedKeyBundle,
        commitments: Sequence[str] = (),
        notes: Sequence[ShieldedWalletNote] = (),
        last_scanned_index: int = 0,
    ):
        self.asset_id = asset_id
        self.key_bundle = key_bundle
        self._commitments = list(commitments)
        self._notes: dict[str, ShieldedWalletNote] = {
            note.commitment: note for note in notes
        }
        self.last_scanned_index = last_scanned_index

    @classmethod
    def generate(cls, asset_id: str) -> "ShieldedWallet":
        return cls(asset_id=asset_id, key_bundle=ShieldedKeyBundle.generate())

    @classmethod
    def from_parts(
        cls,
        *,
        asset_id: str,
        owner_secret: str,
        viewing_private_key: str,
    ) -> "ShieldedWallet":
        return cls(
            asset_id=asset_id,
            key_bundle=ShieldedKeyBundle.from_parts(
                owner_secret=owner_secret,
                viewing_private_key=viewing_private_key,
            ),
        )

    @classmethod
    def from_json(cls, payload: str) -> "ShieldedWallet":
        decoded = json.loads(payload)
        if not isinstance(decoded, dict):
            raise ValueError("wallet snapshot must be a JSON object")

        notes_payload = decoded.get("notes", [])
        if not isinstance(notes_payload, list):
            raise ValueError("wallet snapshot notes must be a list")

        commitments = decoded.get("commitments", [])
        if not isinstance(commitments, list):
            raise ValueError("wallet snapshot commitments must be a list")

        return cls(
            asset_id=decoded["asset_id"],
            key_bundle=ShieldedKeyBundle.from_parts(
                owner_secret=decoded["owner_secret"],
                viewing_private_key=decoded["viewing_private_key"],
            ),
            commitments=commitments,
            notes=[
                ShieldedWalletNote.from_dict(note) for note in notes_payload
            ],
            last_scanned_index=decoded.get(
                "last_scanned_index", len(commitments)
            ),
        )

    @classmethod
    def from_seed_json(cls, payload: str) -> "ShieldedWallet":
        decoded = json.loads(payload)
        if not isinstance(decoded, dict):
            raise ValueError("wallet seed must be a JSON object")
        return cls.from_parts(
            asset_id=decoded["asset_id"],
            owner_secret=decoded["owner_secret"],
            viewing_private_key=decoded["viewing_private_key"],
        )

    @property
    def owner_secret(self) -> str:
        return self.key_bundle.owner_secret

    @property
    def owner_public(self) -> str:
        return self.key_bundle.owner_public

    @property
    def viewing_private_key(self) -> str:
        return self.key_bundle.viewing_private_key

    @property
    def viewing_public_key(self) -> str:
        return self.key_bundle.viewing_public_key

    @property
    def recipient(self) -> ShieldedRecipient:
        return self.key_bundle.recipient

    @property
    def viewer(self) -> ShieldedViewer:
        return self.key_bundle.viewer

    def export_seed_json(self) -> str:
        return json.dumps(
            {
                "asset_id": self.asset_id,
                "owner_secret": self.owner_secret,
                "viewing_private_key": self.viewing_private_key,
            },
            sort_keys=True,
        )

    def to_json(self) -> str:
        return json.dumps(
            {
                "asset_id": self.asset_id,
                "owner_secret": self.owner_secret,
                "viewing_private_key": self.viewing_private_key,
                "last_scanned_index": self.last_scanned_index,
                "commitments": list(self._commitments),
                "notes": [
                    note.to_dict() for note in self.notes(include_spent=True)
                ],
            },
            sort_keys=True,
        )

    def commitments(self) -> list[str]:
        return list(self._commitments)

    def current_root(self) -> str:
        return (
            merkle_root(self._commitments) if self._commitments else zero_root()
        )

    def tree_state(self) -> ShieldedTreeState:
        return tree_state(self._commitments)

    def notes(self, *, include_spent: bool = False) -> list[ShieldedWalletNote]:
        values = sorted(self._notes.values(), key=lambda note: note.leaf_index)
        if include_spent:
            return values
        return [note for note in values if not note.spent]

    def spendable_notes(self) -> list[ShieldedWalletNote]:
        return self.notes(include_spent=False)

    def available_balance(self) -> int:
        return sum(note.amount for note in self.spendable_notes())

    def sync_records(
        self,
        records: Sequence[ShieldedNoteRecord | dict[str, Any]],
    ) -> ShieldedWalletSyncResult:
        normalized = sorted(
            (ShieldedNoteRecord.from_value(record) for record in records),
            key=lambda record: record.index,
        )
        discovered: list[ShieldedWalletNote] = []

        for record in normalized:
            if record.index < 0:
                raise ValueError("note record index must be non-negative")

            if record.index < len(self._commitments):
                if self._commitments[record.index] != record.commitment:
                    raise ValueError(
                        "wallet commitment history does not match record"
                    )
            elif record.index == len(self._commitments):
                self._commitments.append(record.commitment)
            else:
                raise ValueError(
                    "note records must be synced without index gaps"
                )

            if record.index + 1 > self.last_scanned_index:
                self.last_scanned_index = record.index + 1

            if record.commitment in self._notes:
                continue
            if record.payload in (None, ""):
                continue

            try:
                message = decrypt_note_message(
                    record.payload,
                    viewing_private_key=self.viewing_private_key,
                    viewing_public_key=self.viewing_public_key,
                )
                if message.asset_id != self.asset_id:
                    continue
                if message.commitment != record.commitment:
                    continue
                note = message.to_owned_note(self.owner_secret)
            except Exception:
                continue

            wallet_note = ShieldedWalletNote(
                note=note,
                commitment=record.commitment,
                leaf_index=record.index,
                nullifier=note.nullifier(self.asset_id),
                memo=message.memo,
                created_at=record.created_at,
            )
            self._notes[record.commitment] = wallet_note
            discovered.append(wallet_note)

        return ShieldedWalletSyncResult(
            scanned_record_count=len(normalized),
            discovered_notes=discovered,
            last_scanned_index=self.last_scanned_index,
        )

    def sync_transactions(
        self,
        transactions: Sequence[Any],
        *,
        functions: Sequence[str] | None = None,
        starting_index: int = 0,
    ) -> ShieldedWalletSyncResult:
        return self.sync_records(
            note_records_from_transactions(
                transactions,
                functions=functions,
                starting_index=starting_index,
            )
        )

    def apply_spent_nullifiers(
        self, spent_nullifiers: Sequence[str]
    ) -> list[str]:
        spent_set = set(spent_nullifiers)
        updated: list[str] = []
        for commitment, note in list(self._notes.items()):
            if note.spent or note.nullifier not in spent_set:
                continue
            self._notes[commitment] = replace(note, spent=True)
            updated.append(commitment)
        return updated

    def refresh_spent_status(
        self, is_nullifier_spent: Callable[[str], bool]
    ) -> list[str]:
        spent: list[str] = []
        for note in self.notes(include_spent=False):
            if is_nullifier_spent(note.nullifier):
                self._notes[note.commitment] = replace(note, spent=True)
                spent.append(note.commitment)
        return spent

    def select_notes(
        self,
        amount: int,
        *,
        max_inputs: int = _SHIELDED_NOTE_MAX_INPUTS,
    ) -> list[ShieldedWalletNote]:
        if amount <= 0:
            raise ValueError("amount must be positive")
        if max_inputs <= 0:
            raise ValueError("max_inputs must be positive")

        candidates = sorted(
            self.spendable_notes(),
            key=lambda note: (-note.amount, note.leaf_index),
        )
        if sum(note.amount for note in candidates) < amount:
            raise ValueError("insufficient shielded balance")

        prefix_amounts = [0]
        for note in candidates:
            prefix_amounts.append(prefix_amounts[-1] + note.amount)

        best_choice: list[ShieldedWalletNote] | None = None
        best_key: tuple[int, int, list[int]] | None = None

        def max_reachable(start: int, slots: int) -> int:
            end = min(len(candidates), start + slots)
            return prefix_amounts[end] - prefix_amounts[start]

        def maybe_record(selection: list[ShieldedWalletNote], total: int):
            nonlocal best_choice, best_key
            ordered = sorted(selection, key=lambda note: note.leaf_index)
            key = (
                len(ordered),
                total - amount,
                [note.leaf_index for note in ordered],
            )
            if best_key is None or key < best_key:
                best_choice = ordered
                best_key = key

        def search(
            start: int,
            selection: list[ShieldedWalletNote],
            total: int,
        ):
            if total >= amount:
                maybe_record(selection, total)
                return
            if len(selection) == max_inputs:
                return
            if best_key is not None and len(selection) >= best_key[0]:
                return
            if (
                total + max_reachable(start, max_inputs - len(selection))
                < amount
            ):
                return

            for index in range(start, len(candidates)):
                selection.append(candidates[index])
                search(index + 1, selection, total + candidates[index].amount)
                selection.pop()

        search(0, [], 0)
        if best_choice is None:
            raise ValueError("could not satisfy amount within max_inputs")
        return best_choice

    def _default_membership_commitments(
        self,
        membership_commitments: Sequence[str] | None,
    ) -> list[str]:
        if membership_commitments is None:
            return self.commitments()
        return list(membership_commitments)

    def _validated_membership_commitments(
        self,
        old_root: str,
        membership_commitments: Sequence[str] | None,
    ) -> list[str]:
        commitments = self._default_membership_commitments(
            membership_commitments
        )
        derived_root = merkle_root(commitments) if commitments else zero_root()
        if derived_root != old_root:
            raise ValueError("membership commitments do not match old_root")
        return commitments

    def build_deposit(
        self,
        *,
        amount: int,
        old_root: str | None = None,
        append_state: ShieldedTreeState | None = None,
        output_amounts: Sequence[int] | None = None,
        memos: Sequence[str | None] | None = None,
    ) -> ShieldedWalletDepositPlan:
        if output_amounts is None:
            output_amounts = [amount]
        amounts = list(output_amounts)
        if not amounts or len(amounts) > _SHIELDED_NOTE_MAX_OUTPUTS:
            raise ValueError("deposit output count is out of range")
        if any(value <= 0 for value in amounts):
            raise ValueError("deposit outputs must be positive")
        if sum(amounts) != amount:
            raise ValueError("deposit output amounts must sum to amount")

        if memos is None:
            memo_values = [None] * len(amounts)
        else:
            memo_values = list(memos)
            if len(memo_values) != len(amounts):
                raise ValueError("deposit memos length must match outputs")

        if old_root is None:
            old_root = self.current_root()
        if append_state is None:
            append_state = self.tree_state()

        created_notes: list[ShieldedNote] = []
        outputs: list[ShieldedOutput] = []
        payloads: list[str] = []
        for index in range(len(amounts)):
            note = ShieldedNote(
                owner_secret=self.owner_secret,
                amount=amounts[index],
                rho=generate_field_hex(),
                blind=generate_field_hex(),
            )
            created_notes.append(note)
            output = note.to_output()
            outputs.append(output)
            payloads.append(
                output.encrypt_for(
                    asset_id=self.asset_id,
                    viewing_public_key=self.viewing_public_key,
                    memo=memo_values[index],
                )
            )

        payload_hashes = output_payload_hashes(payloads)

        return ShieldedWalletDepositPlan(
            request=ShieldedDepositRequest(
                asset_id=self.asset_id,
                old_root=old_root,
                append_state=append_state,
                amount=amount,
                outputs=outputs,
                output_payload_hashes=payload_hashes,
            ),
            created_notes=created_notes,
            output_payloads=payloads,
            output_payload_hashes=payload_hashes,
        )

    def build_transfer(
        self,
        *,
        recipient: ShieldedRecipient,
        amount: int,
        old_root: str | None = None,
        append_state: ShieldedTreeState | None = None,
        membership_commitments: Sequence[str] | None = None,
        viewers: Sequence[ShieldedViewer | ShieldedRecipient | str] = (),
        recipient_memo: str | None = None,
        change_memo: str | None = None,
        max_inputs: int = _SHIELDED_NOTE_MAX_INPUTS,
    ) -> ShieldedWalletTransferPlan:
        if old_root is None:
            old_root = self.current_root()
        if append_state is None:
            append_state = self.tree_state()

        commitments = self._validated_membership_commitments(
            old_root, membership_commitments
        )
        input_notes = self.select_notes(amount, max_inputs=max_inputs)
        total_input = sum(note.amount for note in input_notes)
        change_amount = total_input - amount

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

        payload_hashes = output_payload_hashes(payloads)

        return ShieldedWalletTransferPlan(
            request=ShieldedTransferRequest(
                asset_id=self.asset_id,
                old_root=old_root,
                append_state=append_state,
                inputs=[note.to_input(commitments) for note in input_notes],
                outputs=outputs,
                output_payload_hashes=payload_hashes,
            ),
            input_notes=input_notes,
            recipient_output=recipient_output,
            change_note=change_note,
            output_payloads=payloads,
            output_payload_hashes=payload_hashes,
        )

    def build_withdraw(
        self,
        *,
        amount: int,
        recipient: str,
        old_root: str | None = None,
        append_state: ShieldedTreeState | None = None,
        membership_commitments: Sequence[str] | None = None,
        change_memo: str | None = None,
        max_inputs: int = _SHIELDED_NOTE_MAX_INPUTS,
    ) -> ShieldedWalletWithdrawPlan:
        if old_root is None:
            old_root = self.current_root()
        if append_state is None:
            append_state = self.tree_state()

        commitments = self._validated_membership_commitments(
            old_root, membership_commitments
        )
        input_notes = self.select_notes(amount, max_inputs=max_inputs)
        total_input = sum(note.amount for note in input_notes)
        change_amount = total_input - amount

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

        payload_hashes = output_payload_hashes(payloads)

        return ShieldedWalletWithdrawPlan(
            request=ShieldedWithdrawRequest(
                asset_id=self.asset_id,
                old_root=old_root,
                append_state=append_state,
                amount=amount,
                recipient=recipient,
                inputs=[note.to_input(commitments) for note in input_notes],
                outputs=outputs,
                output_payload_hashes=payload_hashes,
            ),
            input_notes=input_notes,
            change_note=change_note,
            output_payloads=payloads,
            output_payload_hashes=payload_hashes,
        )


class ShieldedNoteProver:
    def __init__(self, bundle_json: str):
        self.bundle_json = bundle_json
        self.bundle = json.loads(bundle_json)
        self._bundle_handle = load_shielded_note_prover_bundle(bundle_json)

    @classmethod
    def build_insecure_dev_bundle(cls) -> "ShieldedNoteProver":
        return cls(build_insecure_dev_shielded_note_bundle_json())

    @classmethod
    def build_random_bundle(
        cls,
        *,
        contract_name: str,
        vk_id_prefix: str,
    ) -> "ShieldedNoteProver":
        return cls(
            build_random_shielded_note_bundle_json(
                contract_name,
                vk_id_prefix,
            )
        )

    def registry_manifest(self) -> dict[str, Any]:
        return shielded_registry_manifest(self)

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


def shielded_registry_manifest(
    bundle: ShieldedNoteProver | dict[str, Any],
) -> dict[str, Any]:
    if isinstance(bundle, ShieldedNoteProver):
        payload = bundle.bundle
    elif isinstance(bundle, dict):
        payload = bundle
    else:
        raise TypeError("bundle must be a ShieldedNoteProver or dict")

    payload_json = json.dumps(payload, sort_keys=True)
    bundle_hash = _sha3_hex(payload_json)
    entries = []
    configure_actions = []
    for action in ("deposit", "transfer", "withdraw"):
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


def merkle_root(commitments: Sequence[str]) -> str:
    return shielded_note_root(list(commitments))


def tree_state(commitments: Sequence[str]) -> ShieldedTreeState:
    return ShieldedTreeState(
        **json.loads(shielded_note_tree_state_json(list(commitments)))
    )


def encrypt_note_message(
    message: ShieldedNoteMessage,
    *,
    viewing_public_key: str,
    viewers: Sequence[ShieldedViewer | ShieldedRecipient | str] = (),
) -> str:
    all_viewers: list[ShieldedViewer | ShieldedRecipient | str] = [
        ShieldedViewer(viewing_public_key=viewing_public_key)
    ]
    all_viewers.extend(viewers)
    return ShieldedNotePayload.encrypt(message, all_viewers).to_hex()


def decrypt_note_message(
    payload_hex: str,
    *,
    viewing_private_key: str,
    viewing_public_key: str | None = None,
) -> ShieldedNoteMessage:
    public_key = _resolve_viewing_public_key(
        viewing_private_key,
        viewing_public_key,
    )
    sealed_box = SealedBox(
        _x25519_private_key_from_ed25519(viewing_private_key)
    )

    payload = ShieldedNotePayload.from_hex(payload_hex)
    if payload is not None:
        for ciphertext in payload.ciphertexts:
            if ciphertext.viewing_public_key != public_key:
                continue
            plaintext = sealed_box.decrypt(
                _normalize_hex_bytes(ciphertext.ciphertext)
            )
            return ShieldedNoteMessage.from_json(plaintext.decode("utf-8"))
        raise ValueError("no ciphertext for the provided viewing key")

    plaintext = sealed_box.decrypt(_normalize_hex_bytes(payload_hex))
    return ShieldedNoteMessage.from_json(plaintext.decode("utf-8"))


def scan_notes(
    *, asset_id: str, commitments: Sequence[str], notes: Sequence[ShieldedNote]
) -> list[ShieldedDiscoveredNote]:
    commitment_list = list(commitments)
    indexed_commitments = {
        commitment: index for index, commitment in enumerate(commitment_list)
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
                merkle_path=shielded_note_auth_path(
                    commitment_list, leaf_index
                ),
            )
        )
    return discovered


def recover_viewable_notes(
    *,
    asset_id: str,
    commitments: Sequence[str],
    payloads: Sequence[str | None],
    viewing_private_key: str,
    viewing_public_key: str | None = None,
) -> list[ShieldedViewableNote]:
    public_key = _resolve_viewing_public_key(
        viewing_private_key,
        viewing_public_key,
    )
    commitment_list = list(commitments)
    payload_list = list(payloads)
    if len(commitment_list) != len(payload_list):
        raise ValueError("commitments and payloads must have the same length")

    discovered: list[ShieldedViewableNote] = []
    for leaf_index, (commitment, payload_hex) in enumerate(
        zip(commitment_list, payload_list, strict=True)
    ):
        if payload_hex in (None, ""):
            continue

        disclosure_label = None
        payload = ShieldedNotePayload.from_hex(payload_hex)
        if payload is not None:
            for ciphertext in payload.ciphertexts:
                if ciphertext.viewing_public_key == public_key:
                    disclosure_label = ciphertext.label
                    break

        try:
            message = decrypt_note_message(
                payload_hex,
                viewing_private_key=viewing_private_key,
                viewing_public_key=public_key,
            )
        except Exception:
            continue
        if message.asset_id != asset_id or message.commitment != commitment:
            continue
        discovered.append(
            ShieldedViewableNote(
                message=message,
                commitment=commitment,
                leaf_index=leaf_index,
                disclosure_label=disclosure_label,
            )
        )
    return discovered


def recover_encrypted_notes(
    *,
    asset_id: str,
    commitments: Sequence[str],
    payloads: Sequence[str | None],
    owner_secret: str,
    viewing_private_key: str,
    viewing_public_key: str | None = None,
) -> list[ShieldedDiscoveredNote]:
    discovered_viewable = recover_viewable_notes(
        asset_id=asset_id,
        commitments=commitments,
        payloads=payloads,
        viewing_private_key=viewing_private_key,
        viewing_public_key=viewing_public_key,
    )
    commitment_list = list(commitments)
    discovered: list[ShieldedDiscoveredNote] = []
    for viewable in discovered_viewable:
        try:
            note = viewable.to_owned_note(owner_secret)
        except ValueError:
            continue
        discovered.append(
            ShieldedDiscoveredNote(
                note=note,
                commitment=viewable.commitment,
                leaf_index=viewable.leaf_index,
                merkle_path=shielded_note_auth_path(
                    commitment_list, viewable.leaf_index
                ),
            )
        )
    return discovered


def _request_json(request: Any) -> str:
    return json.dumps(asdict(request), sort_keys=True)
