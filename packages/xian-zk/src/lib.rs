mod core;
mod shielded_notes;

pub use crate::core::{
    build_demo_vector, verify_groth16_bn254, DemoVector, VerifierError,
    EXPECTED_FIELD_ELEMENT_BYTES,
};
pub use crate::shielded_notes::{
    build_insecure_dev_shielded_command_bundle, build_insecure_dev_shielded_note_bundle,
    build_random_shielded_command_bundle, build_random_shielded_note_bundle,
    build_shielded_command_fixture, build_shielded_note_fixture,
    prove_shielded_command_deposit, prove_shielded_command_execute,
    prove_shielded_command_withdraw, prove_shielded_deposit, prove_shielded_transfer,
    prove_shielded_withdraw, shielded_command_binding_hex,
    shielded_command_execution_tag_hex, shielded_command_nullifier_digest_hex,
    shielded_note_asset_id_hex,
    shielded_note_auth_path_hex, shielded_note_commitment_hex,
    shielded_note_nullifier_hex, shielded_note_output_commitment_hex,
    shielded_note_owner_public_hex, shielded_note_recipient_digest_hex,
    shielded_output_payload_hash_hex,
    shielded_note_root_hex, shielded_note_tree_state, shielded_note_zero_root_hex,
    ShieldedActionFixture, ShieldedCircuitBundle, ShieldedCommandActionFixture,
    ShieldedCommandFixture, ShieldedCommandProofResult, ShieldedCommandProverBundle,
    ShieldedCommandRequest, ShieldedDepositRequest, ShieldedFixture, ShieldedInputRequest,
    ShieldedOutputRequest, ShieldedProofResult, ShieldedProverBundle,
    ShieldedTransferRequest, ShieldedTreeState, ShieldedVkFixture, ShieldedWithdrawRequest,
    SHIELDED_NOTE_MAX_INPUTS, SHIELDED_NOTE_MAX_OUTPUTS, SHIELDED_NOTE_TREE_DEPTH,
    SHIELDED_NOTE_TREE_LEAF_COUNT,
};

#[cfg(feature = "python-extension")]
mod python_bindings;
