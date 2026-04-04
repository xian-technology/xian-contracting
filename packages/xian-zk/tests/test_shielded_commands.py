from xian_zk import (
    ShieldedCommandWallet,
    ShieldedNote,
    command_binding,
    output_payload_hash,
    shielded_command_registry_manifest,
)


def field(value: int) -> str:
    return f"0x{value:064x}"


def test_command_wallet_builds_bound_command_plan():
    wallet = ShieldedCommandWallet.from_parts(
        asset_id=field(111),
        owner_secret=field(222),
        viewing_private_key="11" * 32,
    )
    funding_note = ShieldedNote(
        owner_secret=wallet.owner_secret,
        amount=12,
        rho=field(333),
        blind=field(444),
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

    plan = wallet.build_command(
        target_contract="con_profile_adapter",
        relayer="relayer",
        chain_id="xian-local-1",
        fee=5,
        public_amount=3,
        payload={"display_name": "Anon Alice"},
        expires_at="2026-01-01 12:30:00",
        change_memo="change",
    )

    assert len(plan.request.inputs) == 1
    assert len(plan.request.outputs) == 1
    assert plan.change_note is not None
    assert plan.change_note.amount == 4
    assert plan.request.public_amount == 3
    assert plan.public_amount == 3
    assert plan.output_payload_hashes == [
        output_payload_hash(payload) for payload in plan.output_payloads
    ]
    assert plan.request.output_payload_hashes == plan.output_payload_hashes
    assert plan.command_binding == command_binding(
        input_nullifiers=[funding_note.nullifier(wallet.asset_id)],
        target_contract="con_profile_adapter",
        payload={"display_name": "Anon Alice"},
        relayer="relayer",
        chain_id="xian-local-1",
        fee=5,
        public_amount=3,
        expires_at="2026-01-01 12:30:00",
    )


def test_command_registry_manifest_includes_registry_metadata():
    manifest = shielded_command_registry_manifest(
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
        }
    )

    assert manifest["circuit_family"] == "shielded_command_v4"
    assert manifest["setup_mode"] == "single-party"
    assert manifest["registry_entries"][1]["action"] == "command"
    assert manifest["registry_entries"][1]["statement_version"] == "4"
    assert manifest["registry_entries"][1]["bundle_hash"].startswith("0x")
