from xian_zk import (
    ShieldedKeyBundle,
    ShieldedNote,
    ShieldedRelayTransferProver,
    ShieldedRelayTransferWallet,
    output_payload_hash,
    relay_transfer_binding,
    shielded_relay_registry_manifest,
)


def field(value: int) -> str:
    return f"0x{value:064x}"


def test_relay_wallet_builds_sender_hidden_transfer_plan():
    wallet = ShieldedRelayTransferWallet.from_parts(
        asset_id=field(111),
        owner_secret=field(222),
        viewing_private_key="11" * 32,
    )
    recipient = ShieldedKeyBundle.from_parts(
        owner_secret=field(333),
        viewing_private_key="22" * 32,
    )
    funding_note = ShieldedNote(
        owner_secret=wallet.owner_secret,
        amount=12,
        rho=field(444),
        blind=field(555),
    )
    wallet.sync_records(
        [
            {
                "index": 0,
                "commitment": funding_note.commitment(wallet.asset_id),
                "payload": funding_note.to_output().encrypt_for(
                    asset_id=wallet.asset_id,
                    viewing_public_key=wallet.viewing_public_key,
                ),
            }
        ]
    )

    plan = wallet.build_relay_transfer(
        recipient=recipient.recipient,
        amount=9,
        relayer="relayer",
        chain_id="xian-local-1",
        fee=2,
        expires_at="2026-01-01 12:30:00",
        recipient_memo="invoice-9",
        change_memo="change",
    )

    assert len(plan.request.inputs) == 1
    assert len(plan.request.outputs) == 2
    assert plan.change_note is not None
    assert plan.change_note.amount == 1
    assert plan.output_payload_hashes == [
        output_payload_hash(payload) for payload in plan.output_payloads
    ]
    assert plan.request.output_payload_hashes == plan.output_payload_hashes
    assert plan.relay_binding == relay_transfer_binding(
        input_nullifiers=[funding_note.nullifier(wallet.asset_id)],
        relayer="relayer",
        chain_id="xian-local-1",
        fee=2,
        expires_at="2026-01-01 12:30:00",
    )


def test_relay_transfer_prover_produces_bound_proof():
    wallet = ShieldedRelayTransferWallet.from_parts(
        asset_id=field(777),
        owner_secret=field(888),
        viewing_private_key="33" * 32,
    )
    recipient = ShieldedKeyBundle.from_parts(
        owner_secret=field(999),
        viewing_private_key="44" * 32,
    )
    funding_note = ShieldedNote(
        owner_secret=wallet.owner_secret,
        amount=15,
        rho=field(1001),
        blind=field(1002),
    )
    wallet.sync_records(
        [
            {
                "index": 0,
                "commitment": funding_note.commitment(wallet.asset_id),
                "payload": funding_note.to_output().encrypt_for(
                    asset_id=wallet.asset_id,
                    viewing_public_key=wallet.viewing_public_key,
                ),
            }
        ]
    )
    plan = wallet.build_relay_transfer(
        recipient=recipient.recipient,
        amount=10,
        relayer="relayer",
        chain_id="xian-local-1",
        fee=3,
        expires_at="2026-01-01 12:45:00",
    )
    prover = ShieldedRelayTransferProver.build_insecure_dev_bundle()

    proof = prover.prove_relay_transfer(plan.request)

    assert proof.relay_binding == plan.relay_binding
    assert proof.execution_tag == plan.execution_tag
    assert proof.relayer_fee == 3
    assert proof.output_payload_hashes == plan.output_payload_hashes
    assert len(proof.input_nullifiers) == 1
    assert len(proof.output_commitments) == 2


def test_relay_registry_manifest_rebinds_command_vk_for_note_token():
    manifest = shielded_relay_registry_manifest(
        {
            "contract_name": "con_shielded_commands",
            "circuit_family": "shielded_command_v4",
            "tree_depth": 20,
            "leaf_capacity": 1_048_576,
            "max_inputs": 4,
            "max_outputs": 4,
            "warning": "single-party setup",
            "setup_mode": "single-party",
            "setup_ceremony": "",
            "deposit": {
                "vk_id": "shielded-command-deposit-v4",
                "vk_hex": "0x01",
                "circuit_name": "shielded_command_deposit_v4",
                "version": "4",
            },
            "command": {
                "vk_id": "shielded-command-execute-v4",
                "vk_hex": "0x02",
                "circuit_name": "shielded_command_execute_v4",
                "version": "4",
            },
            "withdraw": {
                "vk_id": "shielded-command-withdraw-v4",
                "vk_hex": "0x03",
                "circuit_name": "shielded_command_withdraw_v4",
                "version": "4",
            },
        },
        artifact_contract_name="con_shielded_note_token",
    )

    assert manifest["contract_name"] == "con_shielded_note_token"
    assert manifest["registry_entries"][0]["action"] == "relay_transfer"
    assert manifest["registry_entries"][0]["vk_id"] == "shielded-command-execute-v4"
    assert manifest["configure_actions"] == [
        {
            "action": "relay_transfer",
            "vk_id": "shielded-command-execute-v4",
        }
    ]
