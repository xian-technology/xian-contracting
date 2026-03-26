use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::error::Error;

pub const SHIELDED_NOTE_TREE_DEPTH: usize = 5;
pub const SHIELDED_NOTE_TREE_LEAF_COUNT: usize = 1 << SHIELDED_NOTE_TREE_DEPTH;
pub const SHIELDED_NOTE_MAX_INPUTS: usize = 4;
pub const SHIELDED_NOTE_MAX_OUTPUTS: usize = 4;
pub const SHIELDED_NOTE_AMOUNT_BITS: usize = 64;
const MIMC_ROUNDS: usize = 91;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ShieldedVkFixture {
    pub vk_id: String,
    pub circuit_name: String,
    pub version: String,
    pub vk_hex: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ShieldedActionFixture {
    pub proof_hex: String,
    pub old_root: String,
    pub expected_new_root: String,
    pub public_inputs: Vec<String>,
    pub input_count: usize,
    pub output_count: usize,
    pub amount: Option<u64>,
    pub recipient: Option<String>,
    pub input_nullifiers: Vec<String>,
    pub output_commitments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ShieldedFixture {
    pub contract_name: String,
    pub asset_id: String,
    pub zero_root: String,
    pub tree_depth: usize,
    pub leaf_capacity: usize,
    pub max_inputs: usize,
    pub max_outputs: usize,
    pub verifying_keys: Vec<ShieldedVkFixture>,
    pub deposit: ShieldedActionFixture,
    pub transfer: ShieldedActionFixture,
    pub withdraw: ShieldedActionFixture,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedCircuitBundle {
    pub vk_id: String,
    pub circuit_name: String,
    pub version: String,
    pub vk_hex: String,
    pub pk_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedProverBundle {
    pub circuit_family: String,
    pub warning: String,
    pub contract_name: String,
    pub tree_depth: usize,
    pub leaf_capacity: usize,
    pub max_inputs: usize,
    pub max_outputs: usize,
    pub deposit: ShieldedCircuitBundle,
    pub transfer: ShieldedCircuitBundle,
    pub withdraw: ShieldedCircuitBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedOutputRequest {
    pub owner_secret: String,
    pub amount: u64,
    pub rho: String,
    pub blind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedInputRequest {
    pub owner_secret: String,
    pub amount: u64,
    pub rho: String,
    pub blind: String,
    pub leaf_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedDepositRequest {
    pub asset_id: String,
    pub old_commitments: Vec<String>,
    pub amount: u64,
    pub outputs: Vec<ShieldedOutputRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedTransferRequest {
    pub asset_id: String,
    pub old_commitments: Vec<String>,
    pub inputs: Vec<ShieldedInputRequest>,
    pub outputs: Vec<ShieldedOutputRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedWithdrawRequest {
    pub asset_id: String,
    pub old_commitments: Vec<String>,
    pub amount: u64,
    pub recipient: String,
    pub inputs: Vec<ShieldedInputRequest>,
    pub outputs: Vec<ShieldedOutputRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedProofResult {
    pub proof_hex: String,
    pub old_root: String,
    pub expected_new_root: String,
    pub public_inputs: Vec<String>,
    pub input_nullifiers: Vec<String>,
    pub output_commitments: Vec<String>,
}

#[derive(Clone)]
struct NoteWitness {
    owner_secret: Fr,
    amount: u64,
    rho: Fr,
    blind: Fr,
}

#[derive(Clone)]
struct InputWitness {
    enabled: bool,
    note: NoteWitness,
    leaf_index: usize,
}

#[derive(Clone)]
struct OutputWitness {
    enabled: bool,
    note: NoteWitness,
}

#[derive(Clone)]
struct DepositCircuit {
    asset_id: Fr,
    old_root: Fr,
    amount: u64,
    output_count: usize,
    output_commitments: Vec<Fr>,
    old_leaves: Vec<Fr>,
    outputs: Vec<OutputWitness>,
}

#[derive(Clone)]
struct TransferCircuit {
    asset_id: Fr,
    old_root: Fr,
    input_count: usize,
    output_count: usize,
    input_nullifiers: Vec<Fr>,
    output_commitments: Vec<Fr>,
    old_leaves: Vec<Fr>,
    inputs: Vec<InputWitness>,
    outputs: Vec<OutputWitness>,
}

#[derive(Clone)]
struct WithdrawCircuit {
    asset_id: Fr,
    old_root: Fr,
    amount: u64,
    recipient_digest: Fr,
    input_count: usize,
    output_count: usize,
    input_nullifiers: Vec<Fr>,
    output_commitments: Vec<Fr>,
    old_leaves: Vec<Fr>,
    inputs: Vec<InputWitness>,
    outputs: Vec<OutputWitness>,
}

fn mimc_round_constant(round: usize) -> Fr {
    let digest = Sha3_256::digest(format!("xian-mimc-bn254-{round}").as_bytes());
    Fr::from_be_bytes_mod_order(&digest)
}

fn field_hex(value: Fr) -> String {
    let mut bytes = value.into_bigint().to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0_u8; 32 - bytes.len()];
        padded.append(&mut bytes);
        bytes = padded;
    }
    format!("0x{}", hex::encode(bytes))
}

fn parse_field_hex(value: &str) -> Result<Fr, Box<dyn Error>> {
    let raw = value
        .strip_prefix("0x")
        .ok_or("field values must be 0x-prefixed")?;
    let bytes = hex::decode(raw)?;
    if bytes.len() != 32 {
        return Err("field values must be 32 bytes".into());
    }
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

fn hash_to_field(label: &str) -> Fr {
    let digest = Sha3_256::digest(label.as_bytes());
    Fr::from_be_bytes_mod_order(&digest)
}

fn asset_id_for_contract(contract_name: &str) -> Fr {
    hash_to_field(contract_name)
}

fn recipient_digest(recipient: &str) -> Fr {
    hash_to_field(recipient)
}

fn mimc_permute_native(mut state: Fr) -> Fr {
    for round in 0..MIMC_ROUNDS {
        state += mimc_round_constant(round);
        let square = state.square();
        let fourth = square.square();
        let sixth = fourth * square;
        state = sixth * state;
    }
    state
}

fn mimc_hash_many_native(values: &[Fr]) -> Fr {
    let mut state = Fr::zero();
    for value in values {
        state = mimc_permute_native(state + value);
    }
    state
}

fn owner_public(owner_secret: Fr) -> Fr {
    mimc_hash_many_native(&[owner_secret])
}

fn note_commitment(asset_id: Fr, note: &NoteWitness) -> Fr {
    mimc_hash_many_native(&[
        asset_id,
        owner_public(note.owner_secret),
        Fr::from(note.amount),
        note.rho,
        note.blind,
    ])
}

fn note_nullifier(asset_id: Fr, note: &NoteWitness) -> Fr {
    mimc_hash_many_native(&[asset_id, note.owner_secret, note.rho])
}

fn merkle_parent(left: Fr, right: Fr) -> Fr {
    mimc_hash_many_native(&[left, right])
}

fn merkle_root(leaves: &[Fr]) -> Fr {
    assert_eq!(leaves.len(), SHIELDED_NOTE_TREE_LEAF_COUNT);
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(merkle_parent(pair[0], pair[1]));
        }
        level = next;
    }
    level[0]
}

fn leaves_from_commitments(commitments: &[String]) -> Result<Vec<Fr>, Box<dyn Error>> {
    if commitments.len() > SHIELDED_NOTE_TREE_LEAF_COUNT {
        return Err("too many commitments for fixed tree".into());
    }

    let mut leaves = Vec::with_capacity(SHIELDED_NOTE_TREE_LEAF_COUNT);
    for commitment in commitments {
        let field = parse_field_hex(commitment)?;
        if field.is_zero() {
            return Err("stored commitments must be non-zero".into());
        }
        leaves.push(field);
    }
    while leaves.len() < SHIELDED_NOTE_TREE_LEAF_COUNT {
        leaves.push(Fr::zero());
    }
    Ok(leaves)
}

fn note_from_output_request(output: &ShieldedOutputRequest) -> Result<NoteWitness, Box<dyn Error>> {
    Ok(NoteWitness {
        owner_secret: parse_field_hex(&output.owner_secret)?,
        amount: output.amount,
        rho: parse_field_hex(&output.rho)?,
        blind: parse_field_hex(&output.blind)?,
    })
}

fn note_from_input_request(input: &ShieldedInputRequest) -> Result<NoteWitness, Box<dyn Error>> {
    Ok(NoteWitness {
        owner_secret: parse_field_hex(&input.owner_secret)?,
        amount: input.amount,
        rho: parse_field_hex(&input.rho)?,
        blind: parse_field_hex(&input.blind)?,
    })
}

fn append_commitments(mut leaves: Vec<Fr>, commitments: &[Fr]) -> Vec<Fr> {
    let start = leaves
        .iter()
        .position(|leaf| leaf.is_zero())
        .unwrap_or(leaves.len());
    assert!(
        start + commitments.len() <= SHIELDED_NOTE_TREE_LEAF_COUNT,
        "too many commitments for fixed tree",
    );
    for (offset, commitment) in commitments.iter().enumerate() {
        leaves[start + offset] = *commitment;
    }
    leaves
}

fn zero_root() -> Fr {
    merkle_root(&vec![Fr::zero(); SHIELDED_NOTE_TREE_LEAF_COUNT])
}

pub fn shielded_note_zero_root_hex() -> String {
    field_hex(zero_root())
}

pub fn shielded_note_asset_id_hex(contract_name: &str) -> String {
    field_hex(asset_id_for_contract(contract_name))
}

pub fn shielded_note_recipient_digest_hex(recipient: &str) -> String {
    field_hex(recipient_digest(recipient))
}

pub fn shielded_note_commitment_hex(
    asset_id_hex: &str,
    owner_secret_hex: &str,
    amount: u64,
    rho_hex: &str,
    blind_hex: &str,
) -> Result<String, Box<dyn Error>> {
    let note = NoteWitness {
        owner_secret: parse_field_hex(owner_secret_hex)?,
        amount,
        rho: parse_field_hex(rho_hex)?,
        blind: parse_field_hex(blind_hex)?,
    };
    Ok(field_hex(note_commitment(
        parse_field_hex(asset_id_hex)?,
        &note,
    )))
}

pub fn shielded_note_nullifier_hex(
    asset_id_hex: &str,
    owner_secret_hex: &str,
    rho_hex: &str,
) -> Result<String, Box<dyn Error>> {
    let note = NoteWitness {
        owner_secret: parse_field_hex(owner_secret_hex)?,
        amount: 0,
        rho: parse_field_hex(rho_hex)?,
        blind: Fr::zero(),
    };
    Ok(field_hex(note_nullifier(
        parse_field_hex(asset_id_hex)?,
        &note,
    )))
}

pub fn shielded_note_root_hex(commitments: &[String]) -> Result<String, Box<dyn Error>> {
    Ok(field_hex(merkle_root(&leaves_from_commitments(
        commitments,
    )?)))
}

fn serialize_hex<T: CanonicalSerialize>(value: &T) -> Result<String, Box<dyn Error>> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes)?;
    Ok(format!("0x{}", hex::encode(bytes)))
}

fn deserialize_hex<T: CanonicalDeserialize>(value: &str) -> Result<T, Box<dyn Error>> {
    let raw = value
        .strip_prefix("0x")
        .ok_or("hex values must be 0x-prefixed")?;
    let bytes = hex::decode(raw)?;
    Ok(T::deserialize_compressed(&mut &bytes[..])?)
}

fn bool_to_fp(value: &Boolean<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    value.select(
        &FpVar::constant(Fr::from(1_u64)),
        &FpVar::constant(Fr::zero()),
    )
}

fn amount_bits_to_var(
    cs: ConstraintSystemRef<Fr>,
    amount: u64,
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut acc = FpVar::constant(Fr::zero());
    let mut coefficient = Fr::from(1_u64);

    for bit_index in 0..SHIELDED_NOTE_AMOUNT_BITS {
        let bit = ((amount >> bit_index) & 1) == 1;
        let bit_var = Boolean::new_witness(cs.clone(), || Ok(bit))?;
        let bit_fp = bool_to_fp(&bit_var)?;
        acc += bit_fp * coefficient;
        coefficient += coefficient;
    }

    Ok(acc)
}

fn mimc_permute_var(mut state: FpVar<Fr>) -> FpVar<Fr> {
    for round in 0..MIMC_ROUNDS {
        state += mimc_round_constant(round);
        let square = state.square().expect("square should succeed");
        let fourth = square.square().expect("square should succeed");
        let sixth = fourth * square;
        state = sixth * state;
    }
    state
}

fn mimc_hash_many_var(values: &[FpVar<Fr>]) -> FpVar<Fr> {
    let mut state = FpVar::constant(Fr::zero());
    for value in values {
        state = mimc_permute_var(state + value);
    }
    state
}

fn owner_public_var(owner_secret: &FpVar<Fr>) -> FpVar<Fr> {
    mimc_hash_many_var(std::slice::from_ref(owner_secret))
}

fn note_commitment_var(
    asset_id: &FpVar<Fr>,
    owner_secret: &FpVar<Fr>,
    amount: &FpVar<Fr>,
    rho: &FpVar<Fr>,
    blind: &FpVar<Fr>,
) -> FpVar<Fr> {
    let owner_public = owner_public_var(owner_secret);
    mimc_hash_many_var(&[
        asset_id.clone(),
        owner_public,
        amount.clone(),
        rho.clone(),
        blind.clone(),
    ])
}

fn note_nullifier_var(
    asset_id: &FpVar<Fr>,
    owner_secret: &FpVar<Fr>,
    rho: &FpVar<Fr>,
) -> FpVar<Fr> {
    mimc_hash_many_var(&[asset_id.clone(), owner_secret.clone(), rho.clone()])
}

fn merkle_parent_var(left: &FpVar<Fr>, right: &FpVar<Fr>) -> FpVar<Fr> {
    mimc_hash_many_var(&[left.clone(), right.clone()])
}

fn merkle_root_var(leaves: &[FpVar<Fr>]) -> FpVar<Fr> {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(merkle_parent_var(&pair[0], &pair[1]));
        }
        level = next;
    }
    level.remove(0)
}

fn select_leaf(
    cs: ConstraintSystemRef<Fr>,
    leaves: &[FpVar<Fr>],
    enabled: &Boolean<Fr>,
    index: usize,
) -> Result<FpVar<Fr>, SynthesisError> {
    let enabled_fp = bool_to_fp(enabled)?;
    let mut selector_sum = FpVar::constant(Fr::zero());
    let mut selected = FpVar::constant(Fr::zero());

    for (leaf_index, leaf) in leaves.iter().enumerate() {
        let is_selected =
            Boolean::new_witness(cs.clone(), || Ok(enabled.value()? && leaf_index == index))?;
        let selector_fp = bool_to_fp(&is_selected)?;
        selector_sum += selector_fp.clone();
        selected += leaf.clone() * selector_fp;
    }

    selector_sum.enforce_equal(&enabled_fp)?;
    Ok(selected)
}

fn public_inputs_var(
    cs: ConstraintSystemRef<Fr>,
    values: &[Fr],
) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    values
        .iter()
        .map(|value| FpVar::<Fr>::new_input(cs.clone(), || Ok(*value)))
        .collect()
}

fn witness_leaves_var(
    cs: ConstraintSystemRef<Fr>,
    leaves: &[Fr],
) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    leaves
        .iter()
        .map(|value| FpVar::<Fr>::new_witness(cs.clone(), || Ok(*value)))
        .collect()
}

impl DepositCircuit {
    fn blank() -> Self {
        Self {
            asset_id: Fr::zero(),
            old_root: zero_root(),
            amount: 0,
            output_count: 0,
            output_commitments: vec![Fr::zero(); SHIELDED_NOTE_MAX_OUTPUTS],
            old_leaves: vec![Fr::zero(); SHIELDED_NOTE_TREE_LEAF_COUNT],
            outputs: (0..SHIELDED_NOTE_MAX_OUTPUTS)
                .map(|_| OutputWitness {
                    enabled: false,
                    note: NoteWitness {
                        owner_secret: Fr::zero(),
                        amount: 0,
                        rho: Fr::zero(),
                        blind: Fr::zero(),
                    },
                })
                .collect(),
        }
    }

    fn public_inputs(&self) -> Vec<Fr> {
        let mut values = vec![
            self.asset_id,
            self.old_root,
            Fr::from(self.amount),
            Fr::from(self.output_count as u64),
        ];
        values.extend(self.output_commitments.iter().copied());
        values
    }
}

impl ConstraintSynthesizer<Fr> for DepositCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let public = public_inputs_var(cs.clone(), &self.public_inputs())?;
        let asset_id = &public[0];
        let old_root = &public[1];
        let amount = &public[2];
        let output_count = &public[3];
        let public_commitments = &public[4..];

        let old_leaves = witness_leaves_var(cs.clone(), &self.old_leaves)?;
        merkle_root_var(&old_leaves).enforce_equal(old_root)?;

        let mut enabled_sum = FpVar::constant(Fr::zero());
        let mut output_sum = FpVar::constant(Fr::zero());

        for (index, output) in self.outputs.iter().enumerate() {
            let enabled = Boolean::new_witness(cs.clone(), || Ok(output.enabled))?;
            let enabled_fp = bool_to_fp(&enabled)?;
            enabled_sum += enabled_fp.clone();

            let owner_secret =
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.note.owner_secret))?;
            let rho = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.note.rho))?;
            let blind = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.note.blind))?;
            let note_amount = amount_bits_to_var(cs.clone(), output.note.amount)?;
            let commitment =
                note_commitment_var(asset_id, &owner_secret, &note_amount, &rho, &blind);

            public_commitments[index].enforce_equal(&(commitment * enabled_fp.clone()))?;
            output_sum += note_amount * enabled_fp;
        }

        enabled_sum.enforce_equal(output_count)?;
        output_sum.enforce_equal(amount)?;
        Ok(())
    }
}

impl TransferCircuit {
    fn blank() -> Self {
        Self {
            asset_id: Fr::zero(),
            old_root: zero_root(),
            input_count: 0,
            output_count: 0,
            input_nullifiers: vec![Fr::zero(); SHIELDED_NOTE_MAX_INPUTS],
            output_commitments: vec![Fr::zero(); SHIELDED_NOTE_MAX_OUTPUTS],
            old_leaves: vec![Fr::zero(); SHIELDED_NOTE_TREE_LEAF_COUNT],
            inputs: (0..SHIELDED_NOTE_MAX_INPUTS)
                .map(|_| InputWitness {
                    enabled: false,
                    note: NoteWitness {
                        owner_secret: Fr::zero(),
                        amount: 0,
                        rho: Fr::zero(),
                        blind: Fr::zero(),
                    },
                    leaf_index: 0,
                })
                .collect(),
            outputs: (0..SHIELDED_NOTE_MAX_OUTPUTS)
                .map(|_| OutputWitness {
                    enabled: false,
                    note: NoteWitness {
                        owner_secret: Fr::zero(),
                        amount: 0,
                        rho: Fr::zero(),
                        blind: Fr::zero(),
                    },
                })
                .collect(),
        }
    }

    fn public_inputs(&self) -> Vec<Fr> {
        let mut values = vec![
            self.asset_id,
            self.old_root,
            Fr::from(self.input_count as u64),
            Fr::from(self.output_count as u64),
        ];
        values.extend(self.input_nullifiers.iter().copied());
        values.extend(self.output_commitments.iter().copied());
        values
    }
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let public = public_inputs_var(cs.clone(), &self.public_inputs())?;
        let asset_id = &public[0];
        let old_root = &public[1];
        let input_count = &public[2];
        let output_count = &public[3];
        let public_nullifiers = &public[4..4 + SHIELDED_NOTE_MAX_INPUTS];
        let public_commitments = &public[4 + SHIELDED_NOTE_MAX_INPUTS
            ..4 + SHIELDED_NOTE_MAX_INPUTS + SHIELDED_NOTE_MAX_OUTPUTS];

        let old_leaves = witness_leaves_var(cs.clone(), &self.old_leaves)?;
        merkle_root_var(&old_leaves).enforce_equal(old_root)?;

        let mut input_enabled_sum = FpVar::constant(Fr::zero());
        let mut output_enabled_sum = FpVar::constant(Fr::zero());
        let mut input_sum = FpVar::constant(Fr::zero());
        let mut output_sum = FpVar::constant(Fr::zero());

        for (index, input) in self.inputs.iter().enumerate() {
            let enabled = Boolean::new_witness(cs.clone(), || Ok(input.enabled))?;
            let enabled_fp = bool_to_fp(&enabled)?;
            input_enabled_sum += enabled_fp.clone();

            let owner_secret =
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(input.note.owner_secret))?;
            let rho = FpVar::<Fr>::new_witness(cs.clone(), || Ok(input.note.rho))?;
            let blind = FpVar::<Fr>::new_witness(cs.clone(), || Ok(input.note.blind))?;
            let note_amount = amount_bits_to_var(cs.clone(), input.note.amount)?;
            let commitment =
                note_commitment_var(asset_id, &owner_secret, &note_amount, &rho, &blind);
            let selected_leaf = select_leaf(cs.clone(), &old_leaves, &enabled, input.leaf_index)?;
            selected_leaf.enforce_equal(&(commitment.clone() * enabled_fp.clone()))?;

            let nullifier = note_nullifier_var(asset_id, &owner_secret, &rho) * enabled_fp.clone();
            public_nullifiers[index].enforce_equal(&nullifier)?;
            input_sum += note_amount * enabled_fp;
        }

        for (index, output) in self.outputs.iter().enumerate() {
            let enabled = Boolean::new_witness(cs.clone(), || Ok(output.enabled))?;
            let enabled_fp = bool_to_fp(&enabled)?;
            output_enabled_sum += enabled_fp.clone();

            let owner_secret =
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.note.owner_secret))?;
            let rho = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.note.rho))?;
            let blind = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.note.blind))?;
            let note_amount = amount_bits_to_var(cs.clone(), output.note.amount)?;
            let commitment =
                note_commitment_var(asset_id, &owner_secret, &note_amount, &rho, &blind);
            public_commitments[index].enforce_equal(&(commitment * enabled_fp.clone()))?;
            output_sum += note_amount * enabled_fp;
        }

        input_enabled_sum.enforce_equal(input_count)?;
        output_enabled_sum.enforce_equal(output_count)?;
        input_sum.enforce_equal(&output_sum)?;
        Ok(())
    }
}

impl WithdrawCircuit {
    fn blank() -> Self {
        Self {
            asset_id: Fr::zero(),
            old_root: zero_root(),
            amount: 0,
            recipient_digest: Fr::zero(),
            input_count: 0,
            output_count: 0,
            input_nullifiers: vec![Fr::zero(); SHIELDED_NOTE_MAX_INPUTS],
            output_commitments: vec![Fr::zero(); SHIELDED_NOTE_MAX_OUTPUTS],
            old_leaves: vec![Fr::zero(); SHIELDED_NOTE_TREE_LEAF_COUNT],
            inputs: (0..SHIELDED_NOTE_MAX_INPUTS)
                .map(|_| InputWitness {
                    enabled: false,
                    note: NoteWitness {
                        owner_secret: Fr::zero(),
                        amount: 0,
                        rho: Fr::zero(),
                        blind: Fr::zero(),
                    },
                    leaf_index: 0,
                })
                .collect(),
            outputs: (0..SHIELDED_NOTE_MAX_OUTPUTS)
                .map(|_| OutputWitness {
                    enabled: false,
                    note: NoteWitness {
                        owner_secret: Fr::zero(),
                        amount: 0,
                        rho: Fr::zero(),
                        blind: Fr::zero(),
                    },
                })
                .collect(),
        }
    }

    fn public_inputs(&self) -> Vec<Fr> {
        let mut values = vec![
            self.asset_id,
            self.old_root,
            Fr::from(self.amount),
            self.recipient_digest,
            Fr::from(self.input_count as u64),
            Fr::from(self.output_count as u64),
        ];
        values.extend(self.input_nullifiers.iter().copied());
        values.extend(self.output_commitments.iter().copied());
        values
    }
}

impl ConstraintSynthesizer<Fr> for WithdrawCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let public = public_inputs_var(cs.clone(), &self.public_inputs())?;
        let asset_id = &public[0];
        let old_root = &public[1];
        let amount = &public[2];
        let _recipient_digest = &public[3];
        let input_count = &public[4];
        let output_count = &public[5];
        let public_nullifiers = &public[6..6 + SHIELDED_NOTE_MAX_INPUTS];
        let public_commitments = &public[6 + SHIELDED_NOTE_MAX_INPUTS
            ..6 + SHIELDED_NOTE_MAX_INPUTS + SHIELDED_NOTE_MAX_OUTPUTS];

        let old_leaves = witness_leaves_var(cs.clone(), &self.old_leaves)?;
        merkle_root_var(&old_leaves).enforce_equal(old_root)?;

        let mut input_enabled_sum = FpVar::constant(Fr::zero());
        let mut output_enabled_sum = FpVar::constant(Fr::zero());
        let mut input_sum = FpVar::constant(Fr::zero());
        let mut output_sum = FpVar::constant(Fr::zero());

        for (index, input) in self.inputs.iter().enumerate() {
            let enabled = Boolean::new_witness(cs.clone(), || Ok(input.enabled))?;
            let enabled_fp = bool_to_fp(&enabled)?;
            input_enabled_sum += enabled_fp.clone();

            let owner_secret =
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(input.note.owner_secret))?;
            let rho = FpVar::<Fr>::new_witness(cs.clone(), || Ok(input.note.rho))?;
            let blind = FpVar::<Fr>::new_witness(cs.clone(), || Ok(input.note.blind))?;
            let note_amount = amount_bits_to_var(cs.clone(), input.note.amount)?;
            let commitment =
                note_commitment_var(asset_id, &owner_secret, &note_amount, &rho, &blind);
            let selected_leaf = select_leaf(cs.clone(), &old_leaves, &enabled, input.leaf_index)?;
            selected_leaf.enforce_equal(&(commitment.clone() * enabled_fp.clone()))?;

            let nullifier = note_nullifier_var(asset_id, &owner_secret, &rho) * enabled_fp.clone();
            public_nullifiers[index].enforce_equal(&nullifier)?;
            input_sum += note_amount * enabled_fp;
        }

        for (index, output) in self.outputs.iter().enumerate() {
            let enabled = Boolean::new_witness(cs.clone(), || Ok(output.enabled))?;
            let enabled_fp = bool_to_fp(&enabled)?;
            output_enabled_sum += enabled_fp.clone();

            let owner_secret =
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.note.owner_secret))?;
            let rho = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.note.rho))?;
            let blind = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.note.blind))?;
            let note_amount = amount_bits_to_var(cs.clone(), output.note.amount)?;
            let commitment =
                note_commitment_var(asset_id, &owner_secret, &note_amount, &rho, &blind);
            public_commitments[index].enforce_equal(&(commitment * enabled_fp.clone()))?;
            output_sum += note_amount * enabled_fp;
        }

        input_enabled_sum.enforce_equal(input_count)?;
        output_enabled_sum.enforce_equal(output_count)?;
        input_sum.enforce_equal(&(output_sum + amount.clone()))?;
        Ok(())
    }
}

fn prove_circuit<C: ConstraintSynthesizer<Fr> + Clone>(
    rng: &mut StdRng,
    blank: C,
    proving: C,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>, Proof<Bn254>), Box<dyn Error>> {
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(blank, rng)?;
    let proof = Groth16::<Bn254>::prove(&pk, proving, rng)?;
    Ok((pk, vk, proof))
}

pub fn build_shielded_note_fixture() -> Result<ShieldedFixture, Box<dyn Error>> {
    let contract_name = "con_shielded_note_token";
    let asset_id = asset_id_for_contract(contract_name);
    let zero_root = zero_root();

    let alice_secret = hash_to_field("shielded-note:alice");
    let bob_secret = hash_to_field("shielded-note:bob");

    let note_a1 = NoteWitness {
        owner_secret: alice_secret,
        amount: 40,
        rho: hash_to_field("shielded-note:a1:rho"),
        blind: hash_to_field("shielded-note:a1:blind"),
    };
    let note_a2 = NoteWitness {
        owner_secret: alice_secret,
        amount: 30,
        rho: hash_to_field("shielded-note:a2:rho"),
        blind: hash_to_field("shielded-note:a2:blind"),
    };
    let note_b1 = NoteWitness {
        owner_secret: bob_secret,
        amount: 25,
        rho: hash_to_field("shielded-note:b1:rho"),
        blind: hash_to_field("shielded-note:b1:blind"),
    };
    let note_a3 = NoteWitness {
        owner_secret: alice_secret,
        amount: 45,
        rho: hash_to_field("shielded-note:a3:rho"),
        blind: hash_to_field("shielded-note:a3:blind"),
    };
    let note_a4 = NoteWitness {
        owner_secret: alice_secret,
        amount: 25,
        rho: hash_to_field("shielded-note:a4:rho"),
        blind: hash_to_field("shielded-note:a4:blind"),
    };

    let commitment_a1 = note_commitment(asset_id, &note_a1);
    let commitment_a2 = note_commitment(asset_id, &note_a2);
    let commitment_b1 = note_commitment(asset_id, &note_b1);
    let commitment_a3 = note_commitment(asset_id, &note_a3);
    let commitment_a4 = note_commitment(asset_id, &note_a4);

    let nullifier_a1 = note_nullifier(asset_id, &note_a1);
    let nullifier_a2 = note_nullifier(asset_id, &note_a2);
    let nullifier_a3 = note_nullifier(asset_id, &note_a3);

    let leaves0 = vec![Fr::zero(); SHIELDED_NOTE_TREE_LEAF_COUNT];
    let root0 = merkle_root(&leaves0);
    let leaves1 = append_commitments(leaves0.clone(), &[commitment_a1, commitment_a2]);
    let root1 = merkle_root(&leaves1);
    let leaves2 = append_commitments(leaves1.clone(), &[commitment_b1, commitment_a3]);
    let root2 = merkle_root(&leaves2);
    let leaves3 = append_commitments(leaves2.clone(), &[commitment_a4]);
    let root3 = merkle_root(&leaves3);

    let deposit_circuit = DepositCircuit {
        asset_id,
        old_root: root0,
        amount: 70,
        output_count: 2,
        output_commitments: vec![commitment_a1, commitment_a2, Fr::zero(), Fr::zero()],
        old_leaves: leaves0.clone(),
        outputs: vec![
            OutputWitness {
                enabled: true,
                note: note_a1.clone(),
            },
            OutputWitness {
                enabled: true,
                note: note_a2.clone(),
            },
            OutputWitness {
                enabled: false,
                note: NoteWitness {
                    owner_secret: Fr::zero(),
                    amount: 0,
                    rho: Fr::zero(),
                    blind: Fr::zero(),
                },
            },
            OutputWitness {
                enabled: false,
                note: NoteWitness {
                    owner_secret: Fr::zero(),
                    amount: 0,
                    rho: Fr::zero(),
                    blind: Fr::zero(),
                },
            },
        ],
    };

    let transfer_circuit = TransferCircuit {
        asset_id,
        old_root: root1,
        input_count: 2,
        output_count: 2,
        input_nullifiers: vec![nullifier_a1, nullifier_a2, Fr::zero(), Fr::zero()],
        output_commitments: vec![commitment_b1, commitment_a3, Fr::zero(), Fr::zero()],
        old_leaves: leaves1.clone(),
        inputs: vec![
            InputWitness {
                enabled: true,
                note: note_a1.clone(),
                leaf_index: 0,
            },
            InputWitness {
                enabled: true,
                note: note_a2.clone(),
                leaf_index: 1,
            },
            InputWitness {
                enabled: false,
                note: NoteWitness {
                    owner_secret: Fr::zero(),
                    amount: 0,
                    rho: Fr::zero(),
                    blind: Fr::zero(),
                },
                leaf_index: 0,
            },
            InputWitness {
                enabled: false,
                note: NoteWitness {
                    owner_secret: Fr::zero(),
                    amount: 0,
                    rho: Fr::zero(),
                    blind: Fr::zero(),
                },
                leaf_index: 0,
            },
        ],
        outputs: vec![
            OutputWitness {
                enabled: true,
                note: note_b1.clone(),
            },
            OutputWitness {
                enabled: true,
                note: note_a3.clone(),
            },
            OutputWitness {
                enabled: false,
                note: NoteWitness {
                    owner_secret: Fr::zero(),
                    amount: 0,
                    rho: Fr::zero(),
                    blind: Fr::zero(),
                },
            },
            OutputWitness {
                enabled: false,
                note: NoteWitness {
                    owner_secret: Fr::zero(),
                    amount: 0,
                    rho: Fr::zero(),
                    blind: Fr::zero(),
                },
            },
        ],
    };

    let withdraw_circuit = WithdrawCircuit {
        asset_id,
        old_root: root2,
        amount: 20,
        recipient_digest: recipient_digest("bob"),
        input_count: 1,
        output_count: 1,
        input_nullifiers: vec![nullifier_a3, Fr::zero(), Fr::zero(), Fr::zero()],
        output_commitments: vec![commitment_a4, Fr::zero(), Fr::zero(), Fr::zero()],
        old_leaves: leaves2.clone(),
        inputs: vec![
            InputWitness {
                enabled: true,
                note: note_a3.clone(),
                leaf_index: 3,
            },
            InputWitness {
                enabled: false,
                note: NoteWitness {
                    owner_secret: Fr::zero(),
                    amount: 0,
                    rho: Fr::zero(),
                    blind: Fr::zero(),
                },
                leaf_index: 0,
            },
            InputWitness {
                enabled: false,
                note: NoteWitness {
                    owner_secret: Fr::zero(),
                    amount: 0,
                    rho: Fr::zero(),
                    blind: Fr::zero(),
                },
                leaf_index: 0,
            },
            InputWitness {
                enabled: false,
                note: NoteWitness {
                    owner_secret: Fr::zero(),
                    amount: 0,
                    rho: Fr::zero(),
                    blind: Fr::zero(),
                },
                leaf_index: 0,
            },
        ],
        outputs: vec![
            OutputWitness {
                enabled: true,
                note: note_a4.clone(),
            },
            OutputWitness {
                enabled: false,
                note: NoteWitness {
                    owner_secret: Fr::zero(),
                    amount: 0,
                    rho: Fr::zero(),
                    blind: Fr::zero(),
                },
            },
            OutputWitness {
                enabled: false,
                note: NoteWitness {
                    owner_secret: Fr::zero(),
                    amount: 0,
                    rho: Fr::zero(),
                    blind: Fr::zero(),
                },
            },
            OutputWitness {
                enabled: false,
                note: NoteWitness {
                    owner_secret: Fr::zero(),
                    amount: 0,
                    rho: Fr::zero(),
                    blind: Fr::zero(),
                },
            },
        ],
    };

    let mut rng = StdRng::seed_from_u64(20260326);
    let (_deposit_pk, deposit_vk, deposit_proof) =
        prove_circuit(&mut rng, DepositCircuit::blank(), deposit_circuit.clone())?;
    let (_transfer_pk, transfer_vk, transfer_proof) =
        prove_circuit(&mut rng, TransferCircuit::blank(), transfer_circuit.clone())?;
    let (_withdraw_pk, withdraw_vk, withdraw_proof) =
        prove_circuit(&mut rng, WithdrawCircuit::blank(), withdraw_circuit.clone())?;

    Ok(ShieldedFixture {
        contract_name: contract_name.to_string(),
        asset_id: field_hex(asset_id),
        zero_root: field_hex(zero_root),
        tree_depth: SHIELDED_NOTE_TREE_DEPTH,
        leaf_capacity: SHIELDED_NOTE_TREE_LEAF_COUNT,
        max_inputs: SHIELDED_NOTE_MAX_INPUTS,
        max_outputs: SHIELDED_NOTE_MAX_OUTPUTS,
        verifying_keys: vec![
            ShieldedVkFixture {
                vk_id: "shielded-deposit-v1".to_string(),
                circuit_name: "shielded_note_deposit_v1".to_string(),
                version: "1".to_string(),
                vk_hex: serialize_hex(&deposit_vk)?,
            },
            ShieldedVkFixture {
                vk_id: "shielded-transfer-v1".to_string(),
                circuit_name: "shielded_note_transfer_v1".to_string(),
                version: "1".to_string(),
                vk_hex: serialize_hex(&transfer_vk)?,
            },
            ShieldedVkFixture {
                vk_id: "shielded-withdraw-v1".to_string(),
                circuit_name: "shielded_note_withdraw_v1".to_string(),
                version: "1".to_string(),
                vk_hex: serialize_hex(&withdraw_vk)?,
            },
        ],
        deposit: ShieldedActionFixture {
            proof_hex: serialize_hex(&deposit_proof)?,
            old_root: field_hex(root0),
            expected_new_root: field_hex(root1),
            public_inputs: deposit_circuit
                .public_inputs()
                .into_iter()
                .map(field_hex)
                .collect(),
            input_count: 0,
            output_count: 2,
            amount: Some(70),
            recipient: None,
            input_nullifiers: vec![],
            output_commitments: vec![field_hex(commitment_a1), field_hex(commitment_a2)],
        },
        transfer: ShieldedActionFixture {
            proof_hex: serialize_hex(&transfer_proof)?,
            old_root: field_hex(root1),
            expected_new_root: field_hex(root2),
            public_inputs: transfer_circuit
                .public_inputs()
                .into_iter()
                .map(field_hex)
                .collect(),
            input_count: 2,
            output_count: 2,
            amount: None,
            recipient: None,
            input_nullifiers: vec![field_hex(nullifier_a1), field_hex(nullifier_a2)],
            output_commitments: vec![field_hex(commitment_b1), field_hex(commitment_a3)],
        },
        withdraw: ShieldedActionFixture {
            proof_hex: serialize_hex(&withdraw_proof)?,
            old_root: field_hex(root2),
            expected_new_root: field_hex(root3),
            public_inputs: withdraw_circuit
                .public_inputs()
                .into_iter()
                .map(field_hex)
                .collect(),
            input_count: 1,
            output_count: 1,
            amount: Some(20),
            recipient: Some("bob".to_string()),
            input_nullifiers: vec![field_hex(nullifier_a3)],
            output_commitments: vec![field_hex(commitment_a4)],
        },
    })
}

pub fn build_insecure_dev_shielded_note_bundle() -> Result<ShieldedProverBundle, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(20260326);
    let (_deposit_pk, deposit_vk, _deposit_proof) =
        prove_circuit(&mut rng, DepositCircuit::blank(), DepositCircuit::blank())?;
    let (_transfer_pk, transfer_vk, _transfer_proof) =
        prove_circuit(&mut rng, TransferCircuit::blank(), TransferCircuit::blank())?;
    let (_withdraw_pk, withdraw_vk, _withdraw_proof) =
        prove_circuit(&mut rng, WithdrawCircuit::blank(), WithdrawCircuit::blank())?;

    let mut rng = StdRng::seed_from_u64(20260326);
    let (deposit_pk, _deposit_vk, _) =
        prove_circuit(&mut rng, DepositCircuit::blank(), DepositCircuit::blank())?;
    let (transfer_pk, _transfer_vk, _) =
        prove_circuit(&mut rng, TransferCircuit::blank(), TransferCircuit::blank())?;
    let (withdraw_pk, _withdraw_vk, _) =
        prove_circuit(&mut rng, WithdrawCircuit::blank(), WithdrawCircuit::blank())?;

    Ok(ShieldedProverBundle {
        circuit_family: "shielded_note_v1".to_string(),
        warning: "INSECURE DEV BUNDLE: deterministic setup seed exposes toxic waste and must never be used on a real network.".to_string(),
        contract_name: "con_shielded_note_token".to_string(),
        tree_depth: SHIELDED_NOTE_TREE_DEPTH,
        leaf_capacity: SHIELDED_NOTE_TREE_LEAF_COUNT,
        max_inputs: SHIELDED_NOTE_MAX_INPUTS,
        max_outputs: SHIELDED_NOTE_MAX_OUTPUTS,
        deposit: ShieldedCircuitBundle {
            vk_id: "shielded-deposit-v1".to_string(),
            circuit_name: "shielded_note_deposit_v1".to_string(),
            version: "1".to_string(),
            vk_hex: serialize_hex(&deposit_vk)?,
            pk_hex: serialize_hex(&deposit_pk)?,
        },
        transfer: ShieldedCircuitBundle {
            vk_id: "shielded-transfer-v1".to_string(),
            circuit_name: "shielded_note_transfer_v1".to_string(),
            version: "1".to_string(),
            vk_hex: serialize_hex(&transfer_vk)?,
            pk_hex: serialize_hex(&transfer_pk)?,
        },
        withdraw: ShieldedCircuitBundle {
            vk_id: "shielded-withdraw-v1".to_string(),
            circuit_name: "shielded_note_withdraw_v1".to_string(),
            version: "1".to_string(),
            vk_hex: serialize_hex(&withdraw_vk)?,
            pk_hex: serialize_hex(&withdraw_pk)?,
        },
    })
}

fn prove_with_pk<C: ConstraintSynthesizer<Fr>>(
    proving_key_hex: &str,
    circuit: C,
) -> Result<Proof<Bn254>, Box<dyn Error>> {
    let proving_key: ProvingKey<Bn254> = deserialize_hex(proving_key_hex)?;
    let mut rng = OsRng;
    Ok(Groth16::<Bn254>::prove(&proving_key, circuit, &mut rng)?)
}

fn blank_output_witness() -> OutputWitness {
    OutputWitness {
        enabled: false,
        note: NoteWitness {
            owner_secret: Fr::zero(),
            amount: 0,
            rho: Fr::zero(),
            blind: Fr::zero(),
        },
    }
}

fn blank_input_witness() -> InputWitness {
    InputWitness {
        enabled: false,
        note: NoteWitness {
            owner_secret: Fr::zero(),
            amount: 0,
            rho: Fr::zero(),
            blind: Fr::zero(),
        },
        leaf_index: 0,
    }
}

pub fn prove_shielded_deposit(
    bundle: &ShieldedProverBundle,
    request: &ShieldedDepositRequest,
) -> Result<ShieldedProofResult, Box<dyn Error>> {
    let asset_id = parse_field_hex(&request.asset_id)?;
    let old_leaves = leaves_from_commitments(&request.old_commitments)?;
    let old_root = merkle_root(&old_leaves);
    let mut output_witnesses = Vec::new();
    let mut output_commitments = Vec::new();
    for output in &request.outputs {
        let note = note_from_output_request(output)?;
        output_commitments.push(note_commitment(asset_id, &note));
        output_witnesses.push(OutputWitness {
            enabled: true,
            note,
        });
    }
    while output_witnesses.len() < SHIELDED_NOTE_MAX_OUTPUTS {
        output_witnesses.push(blank_output_witness());
    }
    let new_leaves = append_commitments(old_leaves.clone(), &output_commitments);
    let expected_new_root = merkle_root(&new_leaves);
    let circuit = DepositCircuit {
        asset_id,
        old_root,
        amount: request.amount,
        output_count: request.outputs.len(),
        output_commitments: {
            let mut values = output_commitments.clone();
            while values.len() < SHIELDED_NOTE_MAX_OUTPUTS {
                values.push(Fr::zero());
            }
            values
        },
        old_leaves,
        outputs: output_witnesses,
    };
    let proof = prove_with_pk(&bundle.deposit.pk_hex, circuit.clone())?;
    Ok(ShieldedProofResult {
        proof_hex: serialize_hex(&proof)?,
        old_root: field_hex(old_root),
        expected_new_root: field_hex(expected_new_root),
        public_inputs: circuit.public_inputs().into_iter().map(field_hex).collect(),
        input_nullifiers: vec![],
        output_commitments: output_commitments.into_iter().map(field_hex).collect(),
    })
}

pub fn prove_shielded_transfer(
    bundle: &ShieldedProverBundle,
    request: &ShieldedTransferRequest,
) -> Result<ShieldedProofResult, Box<dyn Error>> {
    let asset_id = parse_field_hex(&request.asset_id)?;
    let old_leaves = leaves_from_commitments(&request.old_commitments)?;
    let old_root = merkle_root(&old_leaves);

    if request.inputs.is_empty() || request.inputs.len() > SHIELDED_NOTE_MAX_INPUTS {
        return Err("invalid input count".into());
    }
    if request.outputs.is_empty() || request.outputs.len() > SHIELDED_NOTE_MAX_OUTPUTS {
        return Err("invalid output count".into());
    }

    let mut input_witnesses = Vec::new();
    let mut input_nullifiers = Vec::new();
    for input in &request.inputs {
        let note = note_from_input_request(input)?;
        input_nullifiers.push(note_nullifier(asset_id, &note));
        input_witnesses.push(InputWitness {
            enabled: true,
            note,
            leaf_index: input.leaf_index,
        });
    }
    while input_witnesses.len() < SHIELDED_NOTE_MAX_INPUTS {
        input_witnesses.push(blank_input_witness());
    }

    let mut output_witnesses = Vec::new();
    let mut output_commitments = Vec::new();
    for output in &request.outputs {
        let note = note_from_output_request(output)?;
        output_commitments.push(note_commitment(asset_id, &note));
        output_witnesses.push(OutputWitness {
            enabled: true,
            note,
        });
    }
    while output_witnesses.len() < SHIELDED_NOTE_MAX_OUTPUTS {
        output_witnesses.push(blank_output_witness());
    }

    let new_leaves = append_commitments(old_leaves.clone(), &output_commitments);
    let expected_new_root = merkle_root(&new_leaves);
    let circuit = TransferCircuit {
        asset_id,
        old_root,
        input_count: request.inputs.len(),
        output_count: request.outputs.len(),
        input_nullifiers: {
            let mut values = input_nullifiers.clone();
            while values.len() < SHIELDED_NOTE_MAX_INPUTS {
                values.push(Fr::zero());
            }
            values
        },
        output_commitments: {
            let mut values = output_commitments.clone();
            while values.len() < SHIELDED_NOTE_MAX_OUTPUTS {
                values.push(Fr::zero());
            }
            values
        },
        old_leaves,
        inputs: input_witnesses,
        outputs: output_witnesses,
    };
    let proof = prove_with_pk(&bundle.transfer.pk_hex, circuit.clone())?;
    Ok(ShieldedProofResult {
        proof_hex: serialize_hex(&proof)?,
        old_root: field_hex(old_root),
        expected_new_root: field_hex(expected_new_root),
        public_inputs: circuit.public_inputs().into_iter().map(field_hex).collect(),
        input_nullifiers: input_nullifiers.into_iter().map(field_hex).collect(),
        output_commitments: output_commitments.into_iter().map(field_hex).collect(),
    })
}

pub fn prove_shielded_withdraw(
    bundle: &ShieldedProverBundle,
    request: &ShieldedWithdrawRequest,
) -> Result<ShieldedProofResult, Box<dyn Error>> {
    let asset_id = parse_field_hex(&request.asset_id)?;
    let old_leaves = leaves_from_commitments(&request.old_commitments)?;
    let old_root = merkle_root(&old_leaves);

    if request.inputs.is_empty() || request.inputs.len() > SHIELDED_NOTE_MAX_INPUTS {
        return Err("invalid input count".into());
    }
    if request.outputs.is_empty() || request.outputs.len() > SHIELDED_NOTE_MAX_OUTPUTS {
        return Err("invalid output count".into());
    }

    let mut input_witnesses = Vec::new();
    let mut input_nullifiers = Vec::new();
    for input in &request.inputs {
        let note = note_from_input_request(input)?;
        input_nullifiers.push(note_nullifier(asset_id, &note));
        input_witnesses.push(InputWitness {
            enabled: true,
            note,
            leaf_index: input.leaf_index,
        });
    }
    while input_witnesses.len() < SHIELDED_NOTE_MAX_INPUTS {
        input_witnesses.push(blank_input_witness());
    }

    let mut output_witnesses = Vec::new();
    let mut output_commitments = Vec::new();
    for output in &request.outputs {
        let note = note_from_output_request(output)?;
        output_commitments.push(note_commitment(asset_id, &note));
        output_witnesses.push(OutputWitness {
            enabled: true,
            note,
        });
    }
    while output_witnesses.len() < SHIELDED_NOTE_MAX_OUTPUTS {
        output_witnesses.push(blank_output_witness());
    }

    let new_leaves = append_commitments(old_leaves.clone(), &output_commitments);
    let expected_new_root = merkle_root(&new_leaves);
    let circuit = WithdrawCircuit {
        asset_id,
        old_root,
        amount: request.amount,
        recipient_digest: recipient_digest(&request.recipient),
        input_count: request.inputs.len(),
        output_count: request.outputs.len(),
        input_nullifiers: {
            let mut values = input_nullifiers.clone();
            while values.len() < SHIELDED_NOTE_MAX_INPUTS {
                values.push(Fr::zero());
            }
            values
        },
        output_commitments: {
            let mut values = output_commitments.clone();
            while values.len() < SHIELDED_NOTE_MAX_OUTPUTS {
                values.push(Fr::zero());
            }
            values
        },
        old_leaves,
        inputs: input_witnesses,
        outputs: output_witnesses,
    };
    let proof = prove_with_pk(&bundle.withdraw.pk_hex, circuit.clone())?;
    Ok(ShieldedProofResult {
        proof_hex: serialize_hex(&proof)?,
        old_root: field_hex(old_root),
        expected_new_root: field_hex(expected_new_root),
        public_inputs: circuit.public_inputs().into_iter().map(field_hex).collect(),
        input_nullifiers: input_nullifiers.into_iter().map(field_hex).collect(),
        output_commitments: output_commitments.into_iter().map(field_hex).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::verify_groth16_bn254;

    #[test]
    fn shielded_fixture_vectors_verify() {
        let fixture = build_shielded_note_fixture().expect("fixture should build");

        let deposit_vk = &fixture.verifying_keys[0].vk_hex;
        let transfer_vk = &fixture.verifying_keys[1].vk_hex;
        let withdraw_vk = &fixture.verifying_keys[2].vk_hex;

        assert!(verify_groth16_bn254(
            deposit_vk,
            &fixture.deposit.proof_hex,
            &fixture.deposit.public_inputs,
        )
        .expect("deposit verify should succeed"));
        assert!(verify_groth16_bn254(
            transfer_vk,
            &fixture.transfer.proof_hex,
            &fixture.transfer.public_inputs,
        )
        .expect("transfer verify should succeed"));
        assert!(verify_groth16_bn254(
            withdraw_vk,
            &fixture.withdraw.proof_hex,
            &fixture.withdraw.public_inputs,
        )
        .expect("withdraw verify should succeed"));
    }
}
