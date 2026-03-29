from xian_zk import (
    ShieldedKeyBundle,
    ShieldedNote,
    ShieldedNoteRecord,
    ShieldedOutput,
    ShieldedViewer,
    ShieldedWallet,
    decrypt_note_message,
    asset_id_for_contract,
    recover_encrypted_notes,
    recover_viewable_notes,
    shielded_registry_manifest,
)


def field(value: int) -> str:
    return f"0x{value:064x}"


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
    assert from_seed.viewing_public_key == wallet.viewing_public_key


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
    assert transfer_plan.change_note is not None
    assert transfer_plan.change_note.amount == 20
    assert transfer_plan.recipient_output.amount == 50

    withdraw_plan = alice_wallet.build_withdraw(amount=70, recipient="alice")
    assert withdraw_plan.request.old_root == alice_wallet.current_root()
    assert len(withdraw_plan.request.inputs) == 2
    assert withdraw_plan.request.outputs == []
    assert withdraw_plan.output_payloads == []
    assert withdraw_plan.change_note is None


def test_registry_manifest_maps_bundle_to_registry_entries():
    manifest = shielded_registry_manifest(
        {
            "contract_name": "con_private_usd",
            "circuit_family": "shielded_note_v2",
            "tree_depth": 20,
            "leaf_capacity": 1_048_576,
            "max_inputs": 4,
            "max_outputs": 4,
            "warning": "single-party setup",
            "deposit": {
                "vk_id": "private-usd-deposit",
                "vk_hex": "0x01",
                "circuit_name": "shielded_note_deposit_v2",
                "version": "2",
            },
            "transfer": {
                "vk_id": "private-usd-transfer",
                "vk_hex": "0x02",
                "circuit_name": "shielded_note_transfer_v2",
                "version": "2",
            },
            "withdraw": {
                "vk_id": "private-usd-withdraw",
                "vk_hex": "0x03",
                "circuit_name": "shielded_note_withdraw_v2",
                "version": "2",
            },
        }
    )

    assert manifest["contract_name"] == "con_private_usd"
    assert manifest["registry_entries"][0]["vk_id"] == "private-usd-deposit"
    assert manifest["registry_entries"][2]["vk_hex"] == "0x03"
    assert manifest["configure_actions"] == [
        {"action": "deposit", "vk_id": "private-usd-deposit"},
        {"action": "transfer", "vk_id": "private-usd-transfer"},
        {"action": "withdraw", "vk_id": "private-usd-withdraw"},
    ]
