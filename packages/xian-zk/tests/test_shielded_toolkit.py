import json
from functools import lru_cache
from pathlib import Path

import pytest

from xian_zk import (
    ShieldedDepositRequest,
    ShieldedKeyBundle,
    ShieldedNote,
    ShieldedNoteProver,
    ShieldedOutput,
    ShieldedTransferRequest,
    ShieldedWithdrawRequest,
    asset_id_for_contract,
    merkle_root,
    scan_notes,
    tree_state,
    verify_groth16_bn254,
    zero_root,
)


SHIELDED_FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "shielded_note_flow.json"
)

pytestmark = pytest.mark.slow


def load_shielded_fixture():
    return json.loads(SHIELDED_FIXTURE_PATH.read_text())


def field(value: int) -> str:
    return f"0x{value:064x}"


@lru_cache(maxsize=1)
def load_dev_prover() -> ShieldedNoteProver:
    return ShieldedNoteProver.build_insecure_dev_bundle()


def test_insecure_dev_bundle_matches_existing_shielded_fixture_keys():
    fixture = load_shielded_fixture()
    prover = load_dev_prover()
    by_id = {vk["vk_id"]: vk["vk_hex"] for vk in fixture["verifying_keys"]}

    assert prover.bundle["deposit"]["vk_hex"] == by_id["shielded-deposit-v2"]
    assert prover.bundle["transfer"]["vk_hex"] == by_id["shielded-transfer-v2"]
    assert prover.bundle["withdraw"]["vk_hex"] == by_id["shielded-withdraw-v2"]


def test_prover_can_generate_and_verify_shielded_note_flow():
    prover = load_dev_prover()
    asset_id = asset_id_for_contract("con_shielded_note_token")

    alice_note_1 = ShieldedNote(
        owner_secret=field(101),
        amount=40,
        rho=field(1001),
        blind=field(2001),
    )
    alice_note_2 = ShieldedNote(
        owner_secret=field(101),
        amount=30,
        rho=field(1002),
        blind=field(2002),
    )
    bob_keys = ShieldedKeyBundle.from_parts(
        owner_secret=field(202),
        viewing_private_key="22" * 32,
    )
    bob_note_1 = ShieldedNote(
        owner_secret=bob_keys.owner_secret,
        amount=25,
        rho=field(1003),
        blind=field(2003),
    )
    alice_note_3 = ShieldedNote(
        owner_secret=field(101),
        amount=45,
        rho=field(1004),
        blind=field(2004),
    )
    alice_note_4 = ShieldedNote(
        owner_secret=field(101),
        amount=25,
        rho=field(1005),
        blind=field(2005),
    )

    deposit_request = ShieldedDepositRequest(
        asset_id=asset_id,
        old_root=zero_root(),
        append_state=tree_state([]),
        amount=70,
        outputs=[alice_note_1.to_output(), alice_note_2.to_output()],
    )
    deposit = prover.prove_deposit(deposit_request)
    assert deposit.old_root == zero_root()
    assert merkle_root(deposit.output_commitments) == deposit.expected_new_root
    assert verify_groth16_bn254(
        prover.bundle["deposit"]["vk_hex"],
        deposit.proof_hex,
        deposit.public_inputs,
    )

    discovered_inputs = scan_notes(
        asset_id=asset_id,
        commitments=deposit.output_commitments,
        notes=[alice_note_1, alice_note_2],
    )
    assert [note.leaf_index for note in discovered_inputs] == [0, 1]

    transfer_request = ShieldedTransferRequest(
        asset_id=asset_id,
        old_root=deposit.expected_new_root,
        append_state=tree_state(deposit.output_commitments),
        inputs=[match.to_input() for match in discovered_inputs],
        outputs=[
            ShieldedOutput.for_recipient(
                bob_keys.recipient,
                amount=bob_note_1.amount,
                rho=bob_note_1.rho,
                blind=bob_note_1.blind,
            ),
            alice_note_3.to_output(),
        ],
    )
    transfer = prover.prove_transfer(transfer_request)
    transfer_commitments = deposit.output_commitments + transfer.output_commitments
    assert transfer.old_root == deposit.expected_new_root
    assert merkle_root(transfer_commitments) == transfer.expected_new_root
    assert verify_groth16_bn254(
        prover.bundle["transfer"]["vk_hex"],
        transfer.proof_hex,
        transfer.public_inputs,
    )

    discovered_withdraw = scan_notes(
        asset_id=asset_id,
        commitments=transfer_commitments,
        notes=[alice_note_3],
    )
    assert [note.leaf_index for note in discovered_withdraw] == [3]

    withdraw_request = ShieldedWithdrawRequest(
        asset_id=asset_id,
        old_root=transfer.expected_new_root,
        append_state=tree_state(transfer_commitments),
        amount=20,
        recipient="bob",
        inputs=[discovered_withdraw[0].to_input()],
        outputs=[alice_note_4.to_output()],
    )
    withdraw = prover.prove_withdraw(withdraw_request)
    withdraw_commitments = transfer_commitments + withdraw.output_commitments
    assert withdraw.old_root == transfer.expected_new_root
    assert merkle_root(withdraw_commitments) == withdraw.expected_new_root
    assert verify_groth16_bn254(
        prover.bundle["withdraw"]["vk_hex"],
        withdraw.proof_hex,
        withdraw.public_inputs,
    )


def test_prover_can_generate_exact_withdraw_without_outputs():
    prover = load_dev_prover()
    asset_id = asset_id_for_contract("con_shielded_note_token")

    alice_note_1 = ShieldedNote(
        owner_secret=field(303),
        amount=40,
        rho=field(3001),
        blind=field(4001),
    )
    alice_note_2 = ShieldedNote(
        owner_secret=field(303),
        amount=30,
        rho=field(3002),
        blind=field(4002),
    )

    deposit = prover.prove_deposit(
        ShieldedDepositRequest(
            asset_id=asset_id,
            old_root=zero_root(),
            append_state=tree_state([]),
            amount=70,
            outputs=[alice_note_1.to_output(), alice_note_2.to_output()],
        )
    )
    discovered = scan_notes(
        asset_id=asset_id,
        commitments=deposit.output_commitments,
        notes=[alice_note_1, alice_note_2],
    )

    withdraw = prover.prove_withdraw(
        ShieldedWithdrawRequest(
            asset_id=asset_id,
            old_root=deposit.expected_new_root,
            append_state=tree_state(deposit.output_commitments),
            amount=70,
            recipient="alice",
            inputs=[note.to_input() for note in discovered],
            outputs=[],
        )
    )

    assert withdraw.output_commitments == []
    assert withdraw.expected_new_root == deposit.expected_new_root
    assert verify_groth16_bn254(
        prover.bundle["withdraw"]["vk_hex"],
        withdraw.proof_hex,
        withdraw.public_inputs,
    )
