mod core;
mod shielded_notes;

pub use crate::core::{
    build_demo_vector,
    verify_groth16_bn254,
    DemoVector,
    VerifierError,
    EXPECTED_FIELD_ELEMENT_BYTES,
};
pub use crate::shielded_notes::{
    build_shielded_note_fixture,
    ShieldedActionFixture,
    ShieldedFixture,
    ShieldedVkFixture,
    SHIELDED_NOTE_MAX_INPUTS,
    SHIELDED_NOTE_MAX_OUTPUTS,
    SHIELDED_NOTE_TREE_DEPTH,
    SHIELDED_NOTE_TREE_LEAF_COUNT,
};

#[cfg(feature = "python-extension")]
mod python_bindings;
