import json

from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519
from nacl.public import PublicKey, SealedBox
from xian_zk import (
    ShieldedKeyBundle,
    ShieldedNote,
    ShieldedNotePayload,
    ShieldedNoteRecord,
    ShieldedOutput,
    ShieldedViewer,
    ShieldedWallet,
    asset_id_for_contract,
    decrypt_note_message,
    note_records_from_transactions,
    output_payload_hash,
    payload_discovery_tags,
    payload_matches_viewing_key,
    payload_sync_hints,
    recover_encrypted_notes,
    recover_viewable_notes,
    shielded_registry_manifest,
)


def field(value: int) -> str:
    return f"0x{value:064x}"


def indexed_tx(
    function: str,
    kwargs: dict[str, object],
    *,
    tx_index: int,
    block_height: int = 1,
):
    return {
        "tx_hash": f"TX-{block_height}-{tx_index}",
        "block_height": block_height,
        "tx_index": tx_index,
        "success": True,
        "created_at": f"2026-01-01T00:00:{block_height:02d}+00:00",
        "payload": {
            "sender": "alice",
            "nonce": tx_index,
            "contract": "con_shielded_note_token",
            "function": function,
            "kwargs": kwargs,
        },
    }


def indexed_tx_strings(
    function: str,
    kwargs: dict[str, object],
    *,
    tx_index: int,
    block_height: int = 1,
):
    payload = {
        "sender": "alice",
        "nonce": tx_index,
        "contract": "con_shielded_note_token",
        "function": function,
        "kwargs": kwargs,
    }
    return {
        "tx_hash": f"TX-{block_height}-{tx_index}",
        "block_height": block_height,
        "tx_index": tx_index,
        "success": True,
        "created_at": f"2026-01-01T00:00:{block_height:02d}+00:00",
        "payload": json.dumps(payload, sort_keys=True),
        "envelope": json.dumps(
            {"payload": payload},
            sort_keys=True,
        ),
    }


class _FakeIndexedClient:
    def __init__(self, *, events, tags, receipts):
        self._events = list(events)
        self._tags = list(tags)
        self._receipts = dict(receipts)
        self.events_calls: list[tuple[str, str, int, int | None]] = []
        self.tag_calls: list[tuple[str, str, int, int | None]] = []
        self.tx_calls: list[str] = []

    def list_events(
        self,
        contract: str,
        event: str,
        *,
        limit: int = 100,
        after_id: int | None = None,
        offset: int = 0,
    ):
        self.events_calls.append((contract, event, limit, after_id))
        del offset
        rows = [
            row for row in self._events if after_id is None or row["id"] > after_id
        ]
        return rows[:limit]

    def list_shielded_output_tags(
        self,
        tag_value: str,
        *,
        kind: str = "sync_hint",
        limit: int = 100,
        after_id: int | None = None,
        offset: int = 0,
    ):
        self.tag_calls.append((tag_value, kind, limit, after_id))
        del offset
        rows = [
            row
            for row in self._tags
            if row["tag_value"] == tag_value
            and row["tag_kind"] == kind
            and (after_id is None or row["id"] > after_id)
        ]
        return rows[:limit]

    def get_tx(self, tx_hash: str):
        self.tx_calls.append(tx_hash)
        return self._receipts[tx_hash]


def test_recipient_address_and_note_payload_round_trip():
    asset_id = asset_id_for_contract("con_shielded_note_token")
    recipient_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(101),
        viewing_private_key="11" * 32,
    )

    output = ShieldedOutput.for_recipient(
        recipient_keys.recipient,
        amount=25,
        rho=field(1001),
        blind=field(2001),
    )
    payload = output.encrypt_for(
        asset_id=asset_id,
        viewing_public_key=recipient_keys.viewing_public_key,
        memo="invoice-7",
    )
    message = decrypt_note_message(
        payload,
        viewing_private_key=recipient_keys.viewing_private_key,
    )

    expected_note = ShieldedNote(
        owner_secret=recipient_keys.owner_secret,
        amount=25,
        rho=field(1001),
        blind=field(2001),
    )
    assert output.commitment(asset_id) == expected_note.commitment(asset_id)
    assert message.memo == "invoice-7"
    assert message.to_owned_note(recipient_keys.owner_secret) == expected_note


def test_note_payload_does_not_embed_viewing_public_key_in_cleartext():
    asset_id = asset_id_for_contract("con_shielded_note_token")
    recipient_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(120),
        viewing_private_key="12" * 32,
    )

    output = ShieldedOutput.for_recipient(
        recipient_keys.recipient,
        amount=9,
        rho=field(130),
        blind=field(140),
    )
    payload = output.encrypt_for(
        asset_id=asset_id,
        viewing_public_key=recipient_keys.viewing_public_key,
        memo="private-note",
    )

    decoded = bytes.fromhex(payload.removeprefix("0x")).decode("utf-8")
    parsed = ShieldedNotePayload.from_hex(payload)

    assert recipient_keys.viewing_public_key not in decoded
    assert '"viewing_public_key"' not in decoded
    assert '"discovery_tag"' in decoded
    assert '"sync_hint"' in decoded
    assert parsed is not None
    assert parsed.ciphertexts[0].viewing_public_key is None
    assert parsed.ciphertexts[0].discovery_tag is not None
    assert parsed.ciphertexts[0].sync_hint == recipient_keys.sync_hint


def test_payload_matcher_and_tags_work_for_owner_and_disclosed_viewer():
    asset_id = asset_id_for_contract("con_shielded_note_token")
    owner_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(201),
        viewing_private_key="21" * 32,
    )
    auditor_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(202),
        viewing_private_key="22" * 32,
    )
    stranger_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(203),
        viewing_private_key="23" * 32,
    )

    output = ShieldedOutput.for_recipient(
        owner_keys.recipient,
        amount=13,
        rho=field(204),
        blind=field(205),
    )
    payload = output.encrypt_for(
        asset_id=asset_id,
        viewing_public_key=owner_keys.viewing_public_key,
        viewers=[auditor_keys.viewer],
    )

    tags = payload_discovery_tags(payload)
    sync_hints = payload_sync_hints(payload)

    assert len(tags) == 2
    assert sync_hints == [owner_keys.sync_hint, auditor_keys.sync_hint]
    assert payload_matches_viewing_key(
        payload,
        viewing_private_key=owner_keys.viewing_private_key,
    )
    assert payload_matches_viewing_key(
        payload,
        viewing_private_key=auditor_keys.viewing_private_key,
    )
    assert not payload_matches_viewing_key(
        payload,
        viewing_private_key=stranger_keys.viewing_private_key,
    )


def test_legacy_payload_format_still_decrypts():
    asset_id = asset_id_for_contract("con_shielded_note_token")
    recipient_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(150),
        viewing_private_key="15" * 32,
    )

    output = ShieldedOutput.for_recipient(
        recipient_keys.recipient,
        amount=11,
        rho=field(160),
        blind=field(170),
    )
    message = output.to_message(asset_id, memo="legacy")
    sealed_box = SealedBox(
        PublicKey(
            crypto_sign_ed25519_pk_to_curve25519(
                bytes.fromhex(recipient_keys.viewing_public_key)
            )
        )
    )
    ciphertext = "0x" + sealed_box.encrypt(
        message.to_json().encode("utf-8")
    ).hex()
    legacy_payload = "0x" + json.dumps(
        {
            "version": 1,
            "ciphertexts": [
                {
                    "viewing_public_key": recipient_keys.viewing_public_key,
                    "ciphertext": ciphertext,
                    "label": None,
                }
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8").hex()

    decrypted = decrypt_note_message(
        legacy_payload,
        viewing_private_key=recipient_keys.viewing_private_key,
    )

    assert decrypted.memo == "legacy"
    assert decrypted.to_owned_note(recipient_keys.owner_secret) == ShieldedNote(
        owner_secret=recipient_keys.owner_secret,
        amount=11,
        rho=field(160),
        blind=field(170),
    )


def test_recover_encrypted_notes_discovers_owned_notes_from_payloads():
    asset_id = asset_id_for_contract("con_shielded_note_token")
    alice_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(202),
        viewing_private_key="22" * 32,
    )
    bob_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(303),
        viewing_private_key="33" * 32,
    )

    alice_note = ShieldedNote(
        owner_secret=alice_keys.owner_secret,
        amount=40,
        rho=field(1002),
        blind=field(2002),
    )
    bob_output = ShieldedOutput.for_recipient(
        bob_keys.recipient,
        amount=15,
        rho=field(1003),
        blind=field(2003),
    )

    commitments = [alice_note.commitment(asset_id), bob_output.commitment(asset_id)]
    payloads = [
        "",
        bob_output.encrypt_for(
            asset_id=asset_id,
            viewing_public_key=bob_keys.viewing_public_key,
        ),
    ]

    discovered = recover_encrypted_notes(
        asset_id=asset_id,
        commitments=commitments,
        payloads=payloads,
        owner_secret=bob_keys.owner_secret,
        viewing_private_key=bob_keys.viewing_private_key,
    )

    assert len(discovered) == 1
    assert discovered[0].leaf_index == 1
    assert discovered[0].commitment == commitments[1]
    assert discovered[0].note == ShieldedNote(
        owner_secret=bob_keys.owner_secret,
        amount=15,
        rho=field(1003),
        blind=field(2003),
    )


def test_disclosed_viewer_can_read_note_without_spend_authority():
    asset_id = asset_id_for_contract("con_shielded_note_token")
    owner_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(404),
        viewing_private_key="44" * 32,
    )
    auditor_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(505),
        viewing_private_key="55" * 32,
    )

    output = ShieldedOutput.for_recipient(
        owner_keys.recipient,
        amount=18,
        rho=field(1004),
        blind=field(2004),
    )
    payload = output.encrypt_for(
        asset_id=asset_id,
        viewing_public_key=owner_keys.viewing_public_key,
        viewers=[
            ShieldedViewer(
                viewing_public_key=auditor_keys.viewing_public_key,
                label="auditor",
            )
        ],
    )

    viewable = recover_viewable_notes(
        asset_id=asset_id,
        commitments=[output.commitment(asset_id)],
        payloads=[payload],
        viewing_private_key=auditor_keys.viewing_private_key,
    )

    assert len(viewable) == 1
    assert viewable[0].disclosure_label == "auditor"
    assert viewable[0].message.amount == 18
    assert viewable[0].message.owner_public == owner_keys.owner_public

    try:
        viewable[0].to_owned_note(auditor_keys.owner_secret)
        assert False, "auditor should not be able to derive a spendable note"
    except ValueError:
        pass


def test_wallet_sync_snapshot_and_spent_tracking_round_trip():
    asset_id = asset_id_for_contract("con_shielded_note_token")
    wallet = ShieldedWallet.from_parts(
        asset_id=asset_id,
        owner_secret=field(606),
        viewing_private_key="66" * 32,
    )
    other_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(707),
        viewing_private_key="77" * 32,
    )

    wallet_note = ShieldedNote(
        owner_secret=wallet.owner_secret,
        amount=40,
        rho=field(1005),
        blind=field(2005),
    )
    other_output = ShieldedOutput.for_recipient(
        other_keys.recipient,
        amount=12,
        rho=field(1006),
        blind=field(2006),
    )

    sync_result = wallet.sync_records(
        [
            ShieldedNoteRecord(
                index=0,
                commitment=wallet_note.commitment(asset_id),
                payload=wallet_note.to_output().encrypt_for(
                    asset_id=asset_id,
                    viewing_public_key=wallet.viewing_public_key,
                    memo="salary",
                ),
            ),
            ShieldedNoteRecord(
                index=1,
                commitment=other_output.commitment(asset_id),
                payload=other_output.encrypt_for(
                    asset_id=asset_id,
                    viewing_public_key=other_keys.viewing_public_key,
                ),
            ),
        ]
    )

    assert sync_result.scanned_record_count == 2
    assert len(sync_result.discovered_notes) == 1
    assert sync_result.discovered_notes[0].memo == "salary"
    assert wallet.available_balance() == 40
    assert wallet.commitments() == [
        wallet_note.commitment(asset_id),
        other_output.commitment(asset_id),
    ]

    restored = ShieldedWallet.from_json(wallet.to_json())
    assert restored.available_balance() == 40
    assert restored.current_root() == wallet.current_root()

    spent = restored.apply_spent_nullifiers([wallet_note.nullifier(asset_id)])
    assert spent == [wallet_note.commitment(asset_id)]
    assert restored.available_balance() == 0

    from_seed = ShieldedWallet.from_seed_json(wallet.export_seed_json())
    assert from_seed.asset_id == wallet.asset_id
    assert from_seed.owner_secret == wallet.owner_secret


def test_note_records_from_transactions_reconstructs_canonical_indexes():
    asset_id = asset_id_for_contract("con_shielded_note_token")
    alice_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(808),
        viewing_private_key="88" * 32,
    )
    bob_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(909),
        viewing_private_key="99" * 32,
    )

    alice_note_a = ShieldedNote(
        owner_secret=alice_keys.owner_secret,
        amount=30,
        rho=field(3001),
        blind=field(4001),
    )
    alice_note_b = ShieldedNote(
        owner_secret=alice_keys.owner_secret,
        amount=20,
        rho=field(3002),
        blind=field(4002),
    )
    bob_output = ShieldedOutput.for_recipient(
        bob_keys.recipient,
        amount=15,
        rho=field(3003),
        blind=field(4003),
    )

    deposit_payloads = [
        alice_note_a.to_output().encrypt_for(
            asset_id=asset_id,
            viewing_public_key=alice_keys.viewing_public_key,
        ),
        alice_note_b.to_output().encrypt_for(
            asset_id=asset_id,
            viewing_public_key=alice_keys.viewing_public_key,
        ),
    ]
    transfer_payload = bob_output.encrypt_for(
        asset_id=asset_id,
        viewing_public_key=bob_keys.viewing_public_key,
    )

    records = note_records_from_transactions(
        [
            indexed_tx(
                "transfer_shielded",
                {
                    "output_commitments": [bob_output.commitment(asset_id)],
                    "output_payloads": [transfer_payload],
                },
                tx_index=0,
                block_height=2,
            ),
            indexed_tx(
                "deposit_shielded",
                {
                    "output_commitments": [
                        alice_note_a.commitment(asset_id),
                        alice_note_b.commitment(asset_id),
                    ],
                    "output_payloads": deposit_payloads,
                },
                tx_index=0,
                block_height=1,
            ),
        ]
    )

    assert [record.index for record in records] == [0, 1, 2]
    assert [record.commitment for record in records] == [
        alice_note_a.commitment(asset_id),
        alice_note_b.commitment(asset_id),
        bob_output.commitment(asset_id),
    ]
    assert records[0].payload_hash == output_payload_hash(deposit_payloads[0])
    assert len(records[0].payload_tags) == 1
    assert records[2].payload_hash == output_payload_hash(transfer_payload)
    assert len(records[2].payload_tags) == 1


def test_note_records_from_transactions_accepts_stringified_indexed_payloads():
    asset_id = asset_id_for_contract("con_shielded_note_token")
    alice_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(1201),
        viewing_private_key="11" * 32,
    )
    alice_note = ShieldedNote(
        owner_secret=alice_keys.owner_secret,
        amount=17,
        rho=field(1301),
        blind=field(1401),
    )
    payload = alice_note.to_output().encrypt_for(
        asset_id=asset_id,
        viewing_public_key=alice_keys.viewing_public_key,
    )

    records = note_records_from_transactions(
        [
            indexed_tx_strings(
                "deposit_shielded",
                {
                    "output_commitments": [alice_note.commitment(asset_id)],
                    "output_payloads": [payload],
                },
                block_height=7,
                tx_index=0,
            )
        ]
    )

    assert len(records) == 1
    assert records[0].commitment == alice_note.commitment(asset_id)
    assert records[0].payload == payload
    assert records[0].payload_hash == output_payload_hash(payload)
    assert len(records[0].payload_tags) == 1


def test_wallet_sync_transactions_discovers_owned_notes_from_indexed_history():
    asset_id = asset_id_for_contract("con_shielded_note_token")
    wallet = ShieldedWallet.from_parts(
        asset_id=asset_id,
        owner_secret=field(1001),
        viewing_private_key="aa" * 32,
    )
    other_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(1002),
        viewing_private_key="bb" * 32,
    )

    wallet_note = ShieldedNote(
        owner_secret=wallet.owner_secret,
        amount=28,
        rho=field(5001),
        blind=field(6001),
    )
    other_output = ShieldedOutput.for_recipient(
        other_keys.recipient,
        amount=13,
        rho=field(5002),
        blind=field(6002),
    )

    sync_result = wallet.sync_transactions(
        [
            indexed_tx(
                "deposit_shielded",
                {
                    "output_commitments": [
                        wallet_note.commitment(asset_id),
                        other_output.commitment(asset_id),
                    ],
                    "output_payloads": [
                        wallet_note.to_output().encrypt_for(
                            asset_id=asset_id,
                            viewing_public_key=wallet.viewing_public_key,
                            memo="bonus",
                        ),
                        other_output.encrypt_for(
                            asset_id=asset_id,
                            viewing_public_key=other_keys.viewing_public_key,
                        ),
                    ],
                },
                tx_index=0,
                block_height=1,
            )
        ]
    )

    assert sync_result.scanned_record_count == 2
    assert sync_result.candidate_record_count == 1
    assert len(sync_result.discovered_notes) == 1
    assert sync_result.discovered_notes[0].memo == "bonus"
    assert wallet.available_balance() == 28


def test_wallet_candidate_records_prefilters_non_matching_payloads():
    asset_id = asset_id_for_contract("con_shielded_note_token")
    wallet = ShieldedWallet.from_parts(
        asset_id=asset_id,
        owner_secret=field(1101),
        viewing_private_key="ab" * 32,
    )
    other_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(1102),
        viewing_private_key="bc" * 32,
    )

    wallet_note = ShieldedNote(
        owner_secret=wallet.owner_secret,
        amount=9,
        rho=field(1103),
        blind=field(1104),
    )
    other_note = ShieldedNote(
        owner_secret=other_keys.owner_secret,
        amount=5,
        rho=field(1105),
        blind=field(1106),
    )

    records = [
        ShieldedNoteRecord(
            index=0,
            commitment=wallet_note.commitment(asset_id),
            payload=wallet_note.to_output().encrypt_for(
                asset_id=asset_id,
                viewing_public_key=wallet.viewing_public_key,
            ),
        ),
        ShieldedNoteRecord(
            index=1,
            commitment=other_note.commitment(asset_id),
            payload=other_note.to_output().encrypt_for(
                asset_id=asset_id,
                viewing_public_key=other_keys.viewing_public_key,
            ),
        ),
    ]

    candidates = wallet.candidate_records(records)

    assert [record.commitment for record in candidates] == [
        wallet_note.commitment(asset_id)
    ]


def test_wallet_can_sync_from_indexed_events_and_sync_hints():
    asset_id = asset_id_for_contract("con_shielded_note_token")
    wallet = ShieldedWallet.from_parts(
        asset_id=asset_id,
        owner_secret=field(1201),
        viewing_private_key="cd" * 32,
    )
    other_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(1202),
        viewing_private_key="de" * 32,
    )

    wallet_note = ShieldedNote(
        owner_secret=wallet.owner_secret,
        amount=17,
        rho=field(1203),
        blind=field(1204),
    )
    other_note = ShieldedNote(
        owner_secret=other_keys.owner_secret,
        amount=6,
        rho=field(1205),
        blind=field(1206),
    )

    wallet_payload = wallet_note.to_output().encrypt_for(
        asset_id=asset_id,
        viewing_public_key=wallet.viewing_public_key,
        memo="indexed-sync",
    )
    other_payload = other_note.to_output().encrypt_for(
        asset_id=asset_id,
        viewing_public_key=other_keys.viewing_public_key,
    )

    client = _FakeIndexedClient(
        events=[
            {
                "id": 11,
                "contract": "con_private",
                "event": "ShieldedOutputsCommitted",
                "data_indexed": {
                    "new_root": field(1301),
                },
                "data": {
                    "action": "transfer",
                    "note_index_start": 0,
                    "output_count": 2,
                    "commitments_blob": "|".join(
                        [
                            wallet_note.commitment(asset_id),
                            other_note.commitment(asset_id),
                        ]
                    ),
                    "payload_hashes_blob": "|".join(
                        [
                            output_payload_hash(wallet_payload),
                            output_payload_hash(other_payload),
                        ]
                    ),
                },
                "created_at": "2026-01-01T00:00:01Z",
            },
        ],
        tags=[
            {
                "id": 21,
                "tx_hash": "TX-INDEXED-1",
                "block_height": 2,
                "tx_index": 0,
                "output_index": 0,
                "note_index": 0,
                "commitment": wallet_note.commitment(asset_id),
                "tag_kind": "sync_hint",
                "tag_value": wallet.indexed_sync_hint,
            }
        ],
        receipts={
            "TX-INDEXED-1": type(
                "Receipt",
                (),
                {
                    "transaction": {
                        "payload": {
                            "sender": "alice",
                            "nonce": 1,
                            "contract": "con_private",
                            "function": "transfer_shielded",
                            "kwargs": {
                                "output_commitments": [
                                    wallet_note.commitment(asset_id),
                                    other_note.commitment(asset_id),
                                ],
                                "output_payloads": [
                                    wallet_payload,
                                    other_payload,
                                ],
                            },
                        }
                    }
                },
            )()
        },
    )

    sync_result = wallet.sync_indexed_client(client, contract="con_private")

    assert sync_result.scanned_record_count == 2
    assert sync_result.candidate_record_count == 1
    assert len(sync_result.discovered_notes) == 1
    assert sync_result.discovered_notes[0].memo == "indexed-sync"
    assert wallet.available_balance() == 17
    assert wallet.last_output_event_id == 11
    assert wallet.last_tag_id == 21
    assert client.tx_calls == ["TX-INDEXED-1"]


def test_wallet_can_build_transfer_and_exact_withdraw_plans():
    asset_id = asset_id_for_contract("con_shielded_note_token")
    alice_wallet = ShieldedWallet.from_parts(
        asset_id=asset_id,
        owner_secret=field(808),
        viewing_private_key="88" * 32,
    )
    bob_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(909),
        viewing_private_key="99" * 32,
    )

    alice_note_1 = ShieldedNote(
        owner_secret=alice_wallet.owner_secret,
        amount=40,
        rho=field(1007),
        blind=field(2007),
    )
    alice_note_2 = ShieldedNote(
        owner_secret=alice_wallet.owner_secret,
        amount=30,
        rho=field(1008),
        blind=field(2008),
    )

    alice_wallet.sync_records(
        [
            {
                "index": 0,
                "commitment": alice_note_1.commitment(asset_id),
                "payload": alice_note_1.to_output().encrypt_for(
                    asset_id=asset_id,
                    viewing_public_key=alice_wallet.viewing_public_key,
                ),
            },
            {
                "index": 1,
                "commitment": alice_note_2.commitment(asset_id),
                "payload": alice_note_2.to_output().encrypt_for(
                    asset_id=asset_id,
                    viewing_public_key=alice_wallet.viewing_public_key,
                ),
            },
        ]
    )

    transfer_plan = alice_wallet.build_transfer(
        recipient=bob_keys.recipient,
        amount=50,
        recipient_memo="invoice-12",
        change_memo="change",
    )

    assert transfer_plan.request.old_root == alice_wallet.current_root()
    assert len(transfer_plan.request.inputs) == 2
    assert len(transfer_plan.request.outputs) == 2
    assert len(transfer_plan.output_payloads) == 2
    assert transfer_plan.request.output_payload_hashes == [
        output_payload_hash(payload)
        for payload in transfer_plan.output_payloads
    ]
    assert transfer_plan.output_payload_hashes == (
        transfer_plan.request.output_payload_hashes
    )
    assert transfer_plan.change_note is not None
    assert transfer_plan.change_note.amount == 20
    assert transfer_plan.recipient_output.amount == 50

    withdraw_plan = alice_wallet.build_withdraw(amount=70, recipient="alice")
    assert withdraw_plan.request.old_root == alice_wallet.current_root()
    assert len(withdraw_plan.request.inputs) == 2
    assert withdraw_plan.request.outputs == []
    assert withdraw_plan.output_payloads == []
    assert withdraw_plan.request.output_payload_hashes == []
    assert withdraw_plan.change_note is None


def test_registry_manifest_maps_bundle_to_registry_entries():
    manifest = shielded_registry_manifest(
        {
            "contract_name": "con_private_usd",
            "circuit_family": "shielded_note_v3",
            "tree_depth": 20,
            "leaf_capacity": 1_048_576,
            "max_inputs": 4,
            "max_outputs": 4,
            "warning": "single-party setup",
            "setup_mode": "single-party",
            "setup_ceremony": "",
            "deposit": {
                "vk_id": "private-usd-deposit",
                "vk_hex": "0x01",
                "circuit_name": "shielded_note_deposit_v3",
                "version": "3",
            },
            "transfer": {
                "vk_id": "private-usd-transfer",
                "vk_hex": "0x02",
                "circuit_name": "shielded_note_transfer_v3",
                "version": "3",
            },
            "withdraw": {
                "vk_id": "private-usd-withdraw",
                "vk_hex": "0x03",
                "circuit_name": "shielded_note_withdraw_v3",
                "version": "3",
            },
        }
    )

    assert manifest["contract_name"] == "con_private_usd"
    assert manifest["circuit_family"] == "shielded_note_v3"
    assert manifest["setup_mode"] == "single-party"
    assert manifest["bundle_hash"].startswith("0x")
    assert manifest["registry_entries"][0]["vk_id"] == "private-usd-deposit"
    assert manifest["registry_entries"][0]["statement_version"] == "3"
    assert manifest["registry_entries"][2]["vk_hex"] == "0x03"
    assert manifest["configure_actions"] == [
        {"action": "deposit", "vk_id": "private-usd-deposit"},
        {"action": "transfer", "vk_id": "private-usd-transfer"},
        {"action": "withdraw", "vk_id": "private-usd-withdraw"},
    ]
