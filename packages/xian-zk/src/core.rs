use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use num_bigint::BigUint;
use serde::Serialize;
use std::error::Error;
use std::fmt::{Display, Formatter};

pub const EXPECTED_FIELD_ELEMENT_BYTES: usize = 32;
const FIELD_MODULUS_DECIMAL: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierError {
    Encoding(String),
    Verification(String),
}

impl Display for VerifierError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encoding(message) | Self::Verification(message) => formatter.write_str(message),
        }
    }
}

impl Error for VerifierError {}

#[derive(Clone)]
struct SquareCircuit {
    x: Option<Fr>,
    y: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y = cs.new_input_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;
        cs.enforce_constraint(lc!() + x, lc!() + x, lc!() + y)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DemoVector {
    pub vk_hex: String,
    pub proof_hex: String,
    pub public_inputs: Vec<String>,
}

pub struct PreparedGroth16Bn254Key {
    prepared_vk: PreparedVerifyingKey<Bn254>,
}

fn encoding_error(message: impl Into<String>) -> VerifierError {
    VerifierError::Encoding(message.into())
}

fn verification_error(message: impl Into<String>) -> VerifierError {
    VerifierError::Verification(message.into())
}

fn strip_0x(value: &str) -> Result<&str, VerifierError> {
    value
        .strip_prefix("0x")
        .ok_or_else(|| encoding_error("hex inputs must be 0x-prefixed"))
}

fn decode_hex_payload(value: &str) -> Result<Vec<u8>, VerifierError> {
    let raw = strip_0x(value)?;
    hex::decode(raw).map_err(|error| encoding_error(format!("invalid hex: {error}")))
}

fn left_pad_to_32(mut bytes: Vec<u8>) -> Result<Vec<u8>, VerifierError> {
    if bytes.len() > EXPECTED_FIELD_ELEMENT_BYTES {
        return Err(encoding_error("field elements must be exactly 32 bytes"));
    }
    if bytes.len() < EXPECTED_FIELD_ELEMENT_BYTES {
        let mut padded = vec![0_u8; EXPECTED_FIELD_ELEMENT_BYTES - bytes.len()];
        padded.append(&mut bytes);
        return Ok(padded);
    }
    Ok(bytes)
}

fn parse_public_input(hex_value: &str) -> Result<Fr, VerifierError> {
    let bytes = decode_hex_payload(hex_value)?;
    if bytes.len() != EXPECTED_FIELD_ELEMENT_BYTES {
        return Err(encoding_error("public inputs must be exactly 32 bytes"));
    }
    let value = BigUint::from_bytes_be(&bytes);
    let modulus = BigUint::parse_bytes(FIELD_MODULUS_DECIMAL.as_bytes(), 10).unwrap();
    if value >= modulus {
        return Err(encoding_error(
            "public input is not a canonical BN254 field element",
        ));
    }

    let field = Fr::from_be_bytes_mod_order(&bytes);
    let canonical = left_pad_to_32(field.into_bigint().to_bytes_be())
        .map_err(|_| encoding_error("failed to canonicalize public input"))?;
    if canonical != bytes {
        return Err(encoding_error(
            "public input is not a canonical BN254 field element",
        ));
    }

    Ok(field)
}

fn decode_verifying_key(vk_hex: &str) -> Result<VerifyingKey<Bn254>, VerifierError> {
    let bytes = decode_hex_payload(vk_hex)?;
    VerifyingKey::<Bn254>::deserialize_compressed(&mut &bytes[..])
        .map_err(|error| encoding_error(format!("invalid verifying key bytes: {error}")))
}

fn decode_proof(proof_hex: &str) -> Result<Proof<Bn254>, VerifierError> {
    let bytes = decode_hex_payload(proof_hex)?;
    Proof::<Bn254>::deserialize_compressed(&mut &bytes[..])
        .map_err(|error| encoding_error(format!("invalid proof bytes: {error}")))
}

fn parse_public_inputs(values: &[String]) -> Result<Vec<Fr>, VerifierError> {
    values
        .iter()
        .map(|value| parse_public_input(value))
        .collect()
}

pub fn prepare_groth16_bn254_vk(vk_hex: &str) -> Result<PreparedGroth16Bn254Key, VerifierError> {
    let vk = decode_verifying_key(vk_hex)?;
    Ok(PreparedGroth16Bn254Key {
        prepared_vk: prepare_verifying_key(&vk),
    })
}

pub fn verify_groth16_bn254(
    vk_hex: &str,
    proof_hex: &str,
    public_inputs: &[String],
) -> Result<bool, VerifierError> {
    let prepared = prepare_groth16_bn254_vk(vk_hex)?;
    verify_groth16_bn254_prepared(&prepared, proof_hex, public_inputs)
}

pub fn verify_groth16_bn254_prepared(
    prepared: &PreparedGroth16Bn254Key,
    proof_hex: &str,
    public_inputs: &[String],
) -> Result<bool, VerifierError> {
    let proof = decode_proof(proof_hex)?;
    let inputs = parse_public_inputs(public_inputs)?;
    Groth16::<Bn254>::verify_with_processed_vk(&prepared.prepared_vk, &inputs, &proof)
        .map_err(|error| verification_error(format!("verification failed: {error}")))
}

fn hex_encode(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn serialize_compressed_hex<T: CanonicalSerialize>(value: &T) -> Result<String, Box<dyn Error>> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes)?;
    Ok(hex_encode(&bytes))
}

fn fr_to_hex(value: Fr) -> String {
    let bytes = left_pad_to_32(value.into_bigint().to_bytes_be())
        .expect("field element serialization should fit 32 bytes");
    hex_encode(&bytes)
}

pub fn build_demo_vector() -> Result<DemoVector, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(42);
    let x = Fr::rand(&mut rng);
    let y = x * x;
    let setup_circuit = SquareCircuit { x: None, y: None };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng)?;
    let proof = Groth16::<Bn254>::prove(
        &pk,
        SquareCircuit {
            x: Some(x),
            y: Some(y),
        },
        &mut rng,
    )?;

    Ok(DemoVector {
        vk_hex: serialize_compressed_hex(&vk)?,
        proof_hex: serialize_compressed_hex(&proof)?,
        public_inputs: vec![fr_to_hex(y)],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_vector_verifies_successfully() {
        let vector = build_demo_vector().expect("demo vector should build");
        let result = verify_groth16_bn254(&vector.vk_hex, &vector.proof_hex, &vector.public_inputs)
            .expect("verification should not error");
        assert!(result);
    }

    #[test]
    fn tampered_public_input_fails_verification() {
        let mut vector = build_demo_vector().expect("demo vector should build");
        vector.public_inputs[0] =
            "0x0000000000000000000000000000000000000000000000000000000000000001".to_string();
        let result = verify_groth16_bn254(&vector.vk_hex, &vector.proof_hex, &vector.public_inputs)
            .expect("verification should not error");
        assert!(!result);
    }

    #[test]
    fn prepared_key_verification_reuses_prepared_vk() {
        let vector = build_demo_vector().expect("demo vector should build");
        let prepared = prepare_groth16_bn254_vk(&vector.vk_hex).expect("prepared key should build");
        let result =
            verify_groth16_bn254_prepared(&prepared, &vector.proof_hex, &vector.public_inputs)
                .expect("verification should not error");
        assert!(result);
    }

    #[test]
    fn zero_x_prefixed_public_input_over_field_modulus_is_rejected() {
        let over_modulus = format!("0x{}", "ff".repeat(32));
        let error = parse_public_input(&over_modulus).expect_err("input should be rejected");
        assert!(error.to_string().contains("canonical BN254 field element"));
    }
}
