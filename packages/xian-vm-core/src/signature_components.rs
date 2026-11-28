//! Signature primitives shared by the account admission binding and VM host.
use libcrux_ml_dsa::ml_dsa_65::{verify, MLDSA65Signature, MLDSA65VerificationKey};

/// Pure ML-DSA-65 with the empty FIPS 204 context.
pub(crate) fn ml_dsa_65(
    key: &MLDSA65VerificationKey,
    message: &[u8],
    sig: &MLDSA65Signature,
) -> bool {
    verify(key, message, b"", sig).is_ok()
}

/// The node supplies public keys from a validated account record, and the
/// framed transcript. Both components authenticate exactly that message.
#[cfg(feature = "python-extension")]
pub(crate) fn account(ed: &[u8], pq: &[u8], message: &[u8], proofs: &[u8]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Some((ed_sig, pq_sig)) = proofs.split_at_checked(64) else {
        return false;
    };
    let (Ok(ed), Ok(ed_sig), Ok(pq), Ok(pq_sig)) = (
        ed.try_into(),
        Signature::try_from(ed_sig),
        pq.try_into(),
        pq_sig.try_into(),
    ) else {
        return false;
    };
    let Ok(ed) = VerifyingKey::from_bytes(ed) else {
        return false;
    };
    ed.verify_strict(message, &ed_sig).is_ok()
        && ml_dsa_65(
            &MLDSA65VerificationKey::new(pq),
            message,
            &MLDSA65Signature::new(pq_sig),
        )
}
