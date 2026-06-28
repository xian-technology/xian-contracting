from xian_zk import (
    ShieldedCommandWallet,
    ShieldedNote,
    ShieldedSchedulerAuthProver,
    ShieldedSchedulerAuthRequest,
    command_binding,
    output_payload_hash,
    scheduler_owner_commitment,
    scheduler_update_public_inputs,
    shielded_command_registry_manifest,
    shielded_scheduler_auth_registry_manifest,
    verify_groth16_bn254,
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
            "circuit_family": "shielded_command_v5",
            "tree_depth": 20,
            "leaf_capacity": 1_048_576,
            "max_inputs": 4,
            "max_outputs": 4,
            "warning": "single-party setup",
            "setup_mode": "single-party",
            "setup_ceremony": "",
            "deposit": {
                "vk_id": "shielded-command-deposit-v5",
                "vk_hex": "0x01",
                "circuit_name": "shielded_command_deposit_v5",
                "version": "5",
            },
            "command": {
                "vk_id": "shielded-command-execute-v5",
                "vk_hex": "0x02",
                "circuit_name": "shielded_command_execute_v5",
                "version": "5",
            },
            "withdraw": {
                "vk_id": "shielded-command-withdraw-v5",
                "vk_hex": "0x03",
                "circuit_name": "shielded_command_withdraw_v5",
                "version": "5",
            },
        }
    )

    assert manifest["circuit_family"] == "shielded_command_v5"
    assert manifest["setup_mode"] == "single-party"
    assert manifest["registry_entries"][1]["action"] == "command"
    assert manifest["registry_entries"][1]["statement_version"] == "5"
    assert manifest["registry_entries"][1]["bundle_hash"].startswith("0x")


def test_scheduler_auth_proof_binds_owner_and_update_digest():
    prover = ShieldedSchedulerAuthProver.build_insecure_dev_bundle()
    proof = prover.prove_update(
        ShieldedSchedulerAuthRequest(
            owner_secret=field(5150),
            update_digest=field(6160),
        )
    )

    assert proof.owner_commitment == scheduler_owner_commitment(field(5150))
    assert proof.public_inputs == scheduler_update_public_inputs(
        owner_commitment=proof.owner_commitment,
        update_digest=proof.update_digest,
        update_nullifier=proof.update_nullifier,
    )
    assert verify_groth16_bn254(
        prover.bundle["action"]["vk_hex"],
        proof.proof_hex,
        proof.public_inputs,
    )

    tampered = list(proof.public_inputs)
    tampered[1] = field(6161)
    assert not verify_groth16_bn254(
        prover.bundle["action"]["vk_hex"],
        proof.proof_hex,
        tampered,
    )


def test_scheduler_auth_registry_manifest_includes_registry_metadata():
    manifest = shielded_scheduler_auth_registry_manifest(
        {
            "contract_name": "con_shielded_scheduler_adapter",
            "circuit_family": "shielded_scheduler_owner_v1",
            "warning": "single-party setup",
            "setup_mode": "single-party",
            "setup_ceremony": "",
            "action": {
                "vk_id": "shielded-scheduler-owner-v1",
                "vk_hex": "0x01",
                "circuit_name": "shielded_scheduler_owner_v1",
                "version": "1",
            },
        }
    )

    assert manifest["circuit_family"] == "shielded_scheduler_owner_v1"
    assert manifest["registry_entries"][0]["action"] == "authorize_update"
    assert manifest["registry_entries"][0]["tree_depth"] == 0
    assert manifest["registry_entries"][0]["statement_version"] == "1"
    assert manifest["registry_entries"][0]["bundle_hash"].startswith("0x")
