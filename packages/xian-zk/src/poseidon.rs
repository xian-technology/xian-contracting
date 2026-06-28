//! Poseidon hash over the BN254 scalar field.
//!
//! This module is the **single source of truth** for the algebraic hash used by
//! the shielded-note and shielded-command circuits. Both the native helpers and
//! the R1CS gadget are built from one frozen [`PoseidonConfig`], so the
//! in-circuit and out-of-circuit hashes are guaranteed to agree (enforced by the
//! parity tests in `shielded_notes`).
//!
//! ## Construction
//!
//! A sponge over the Poseidon permutation with:
//! - field: BN254 scalar field `Fr`
//! - width `t = rate + capacity = 3` (rate `2`, capacity `1`)
//! - S-box `x^5` (`gcd(5, p-1) = 1`, so it is a permutation)
//! - `8` full rounds + `57` partial rounds
//!
//! targeting 128-bit security. Round constants and the MDS matrix are generated
//! deterministically by the standard Grain-LFSR procedure
//! ([`find_poseidon_ark_and_mds`]) and frozen by the known-answer tests below.
//!
//! Unlike the previous MiMC construction, this sponge has a non-zero **capacity**
//! and a one-way compression, so it is collision-resistant and binding. Each
//! call also **domain-separates** its input by absorbing a fixed tag first, so
//! digests from different contexts (and of different arities) can never collide.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{
    find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::sync::OnceLock;

/// Number of full rounds in the Poseidon permutation.
const POSEIDON_FULL_ROUNDS: usize = 8;
/// Number of partial rounds in the Poseidon permutation.
const POSEIDON_PARTIAL_ROUNDS: usize = 57;
/// S-box exponent. A permutation on `Fr` because `gcd(5, p-1) = 1`.
const POSEIDON_ALPHA: u64 = 5;
/// Sponge rate (field elements absorbed/squeezed per permutation).
const POSEIDON_RATE: usize = 2;
/// Sponge capacity (the security-providing portion of the state).
const POSEIDON_CAPACITY: usize = 1;
/// Bit length of the BN254 scalar field modulus, used by the Grain LFSR.
const BN254_FR_MODULUS_BITS: u64 = 254;
/// Number of candidate MDS matrices to skip during Grain-LFSR generation.
const POSEIDON_SKIP_MATRICES: u64 = 0;

/// Domain-separation tags. Each logical hash use absorbs a distinct tag as its
/// first input so that a digest produced in one context can never be reinterpreted
/// in another, and so the input arity is bound. Values are fixed forever; never
/// reuse or renumber a tag.
pub mod domain {
    /// `owner_public = H([owner_secret])`
    pub const OWNER_PUBLIC: u64 = 1;
    /// `note_commitment = H([asset_id, owner_public, amount, rho, blind])`
    pub const NOTE_COMMITMENT: u64 = 2;
    /// `nullifier = H([asset_id, owner_secret, rho])`
    pub const NULLIFIER: u64 = 3;
    /// `merkle_parent = H([left, right])`
    pub const MERKLE: u64 = 4;
    /// `command_nullifier_digest = H(input_nullifiers)`
    pub const COMMAND_NULLIFIER_DIGEST: u64 = 5;
    /// `command_binding = H(binding_fields)`
    pub const COMMAND_BINDING: u64 = 6;
    /// `command_execution_tag = H([nullifier_digest, command_binding])`
    pub const COMMAND_EXECUTION_TAG: u64 = 7;
    /// `scheduler_owner_commitment = H([owner_secret])`
    pub const SCHEDULER_OWNER_COMMITMENT: u64 = 8;
    /// `scheduler_update_nullifier = H([owner_secret, update_digest])`
    pub const SCHEDULER_UPDATE_NULLIFIER: u64 = 9;
}

/// Returns the process-wide frozen Poseidon configuration, generating it once.
fn config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(build_config)
}

/// Builds the frozen Poseidon configuration from the documented parameters.
fn build_config() -> PoseidonConfig<Fr> {
    // `find_poseidon_ark_and_mds` returns `(ark, mds)`; note that
    // `PoseidonConfig::new` takes `mds` *before* `ark`.
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        BN254_FR_MODULUS_BITS,
        POSEIDON_RATE,
        POSEIDON_FULL_ROUNDS as u64,
        POSEIDON_PARTIAL_ROUNDS as u64,
        POSEIDON_SKIP_MATRICES,
    );
    PoseidonConfig::new(
        POSEIDON_FULL_ROUNDS,
        POSEIDON_PARTIAL_ROUNDS,
        POSEIDON_ALPHA,
        mds,
        ark,
        POSEIDON_RATE,
        POSEIDON_CAPACITY,
    )
}

/// Builds the absorb sequence for a domain-separated hash: `[tag, values...]`.
fn absorb_input(domain: u64, values: &[Fr]) -> Vec<Fr> {
    let mut input = Vec::with_capacity(values.len() + 1);
    input.push(Fr::from(domain));
    input.extend_from_slice(values);
    input
}

/// Native domain-separated Poseidon hash of `values` under `domain`.
///
/// This is the canonical hash. The R1CS gadget [`poseidon_hash_var`] is proven
/// equal to it for every arity used by the shielded circuits.
pub fn poseidon_hash(domain: u64, values: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(config());
    sponge.absorb(&absorb_input(domain, values));
    sponge.squeeze_native_field_elements(1)[0]
}

/// In-circuit counterpart of [`poseidon_hash`], using the same frozen config.
pub fn poseidon_hash_var(
    cs: ConstraintSystemRef<Fr>,
    domain: u64,
    values: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, config());
    let mut input = Vec::with_capacity(values.len() + 1);
    input.push(FpVar::constant(Fr::from(domain)));
    input.extend_from_slice(values);
    sponge.absorb(&input)?;
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{BigInteger, PrimeField};
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    fn hex(value: Fr) -> String {
        let mut bytes = value.into_bigint().to_bytes_be();
        if bytes.len() < 32 {
            let mut padded = vec![0_u8; 32 - bytes.len()];
            padded.append(&mut bytes);
            bytes = padded;
        }
        format!("0x{}", hex::encode(bytes))
    }

    #[test]
    fn config_dimensions_are_frozen() {
        let cfg = config();
        assert_eq!(cfg.full_rounds, POSEIDON_FULL_ROUNDS);
        assert_eq!(cfg.partial_rounds, POSEIDON_PARTIAL_ROUNDS);
        assert_eq!(cfg.alpha, POSEIDON_ALPHA);
        assert_eq!(cfg.rate, POSEIDON_RATE);
        assert_eq!(cfg.capacity, POSEIDON_CAPACITY);
        assert_eq!(
            cfg.ark.len(),
            POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS
        );
        assert_eq!(cfg.mds.len(), POSEIDON_RATE + POSEIDON_CAPACITY);
        for row in &cfg.mds {
            assert_eq!(row.len(), POSEIDON_RATE + POSEIDON_CAPACITY);
        }
    }

    /// Native ⇄ gadget parity at the arities used by the shielded circuits.
    #[test]
    fn native_matches_gadget() {
        for arity in [1usize, 2, 3, 5, 8, 10] {
            let values: Vec<Fr> = (0..arity).map(|i| Fr::from((i as u64) + 11)).collect();
            let native = poseidon_hash(domain::NOTE_COMMITMENT, &values);

            let cs = ConstraintSystem::<Fr>::new_ref();
            let value_vars: Vec<FpVar<Fr>> = values
                .iter()
                .map(|v| FpVar::new_witness(cs.clone(), || Ok(*v)).unwrap())
                .collect();
            let gadget =
                poseidon_hash_var(cs.clone(), domain::NOTE_COMMITMENT, &value_vars).unwrap();
            assert!(cs.is_satisfied().unwrap());
            assert_eq!(gadget.value().unwrap(), native, "arity {arity}");
        }
    }

    /// Domain separation: same payload under different tags yields different digests.
    #[test]
    fn domain_tags_separate() {
        let values = [Fr::from(1u64), Fr::from(2u64)];
        assert_ne!(
            poseidon_hash(domain::NOTE_COMMITMENT, &values),
            poseidon_hash(domain::NULLIFIER, &values)
        );
        assert_ne!(
            poseidon_hash(domain::MERKLE, &values),
            poseidon_hash(domain::COMMAND_BINDING, &values)
        );
    }

    /// Frozen known-answer vectors. If these change, the parameters drifted.
    #[test]
    fn known_answer_vectors() {
        assert_eq!(
            hex(poseidon_hash(domain::OWNER_PUBLIC, &[Fr::from(1u64)])),
            KAT_OWNER_PUBLIC
        );
        assert_eq!(
            hex(poseidon_hash(
                domain::NOTE_COMMITMENT,
                &[
                    Fr::from(1u64),
                    Fr::from(2u64),
                    Fr::from(3u64),
                    Fr::from(4u64),
                    Fr::from(5u64),
                ]
            )),
            KAT_NOTE_COMMITMENT
        );
        assert_eq!(
            hex(poseidon_hash(
                domain::MERKLE,
                &[Fr::from(7u64), Fr::from(9u64)]
            )),
            KAT_MERKLE
        );
    }

    // Frozen Poseidon-BN254 known-answer vectors for the parameters above.
    const KAT_OWNER_PUBLIC: &str =
        "0x18befe7d64b6459c48322dbd5aeb949cadeea6ceb1a7ec3c17623c6654d36e39";
    const KAT_NOTE_COMMITMENT: &str =
        "0x1abdfd037bf86214811a19a556793b21a6e6024cdb394c7050882c46af3415a7";
    const KAT_MERKLE: &str = "0x183a75ea1bb4563d3e397f0d502da3fd4eb8397f6a17d02e1f55831cccb279b3";
}
