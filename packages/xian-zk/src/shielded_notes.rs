use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::error::Error;

pub const SHIELDED_NOTE_TREE_DEPTH: usize = 20;
pub const SHIELDED_NOTE_TREE_LEAF_COUNT: usize = 1 << SHIELDED_NOTE_TREE_DEPTH;
pub const SHIELDED_NOTE_MAX_INPUTS: usize = 4;
pub const SHIELDED_NOTE_MAX_OUTPUTS: usize = 4;
pub const SHIELDED_NOTE_AMOUNT_BITS: usize = 64;
const MIMC_ROUNDS: usize = 91;
const SHIELDED_NOTE_CIRCUIT_FAMILY: &str = "shielded_note_v3";
const SHIELDED_NOTE_DEPOSIT_CIRCUIT_NAME: &str = "shielded_note_deposit_v3";
const SHIELDED_NOTE_TRANSFER_CIRCUIT_NAME: &str = "shielded_note_transfer_v3";
const SHIELDED_NOTE_WITHDRAW_CIRCUIT_NAME: &str = "shielded_note_withdraw_v3";
const SHIELDED_NOTE_CIRCUIT_VERSION: &str = "3";
const SHIELDED_COMMAND_CIRCUIT_FAMILY: &str = "shielded_command_v4";
const SHIELDED_COMMAND_DEPOSIT_CIRCUIT_NAME: &str = "shielded_command_deposit_v4";
const SHIELDED_COMMAND_EXECUTE_CIRCUIT_NAME: &str = "shielded_command_execute_v4";
const SHIELDED_COMMAND_WITHDRAW_CIRCUIT_NAME: &str = "shielded_command_withdraw_v4";
const SHIELDED_COMMAND_CIRCUIT_VERSION: &str = "4";

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
    pub output_payload_hashes: Vec<String>,
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
    pub setup_mode: String,
    pub setup_ceremony: String,
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
pub struct ShieldedCommandProverBundle {
    pub circuit_family: String,
    pub warning: String,
    pub setup_mode: String,
    pub setup_ceremony: String,
    pub contract_name: String,
    pub tree_depth: usize,
    pub leaf_capacity: usize,
    pub max_inputs: usize,
    pub max_outputs: usize,
    pub deposit: ShieldedCircuitBundle,
    pub command: ShieldedCircuitBundle,
    pub withdraw: ShieldedCircuitBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedOutputRequest {
    pub owner_public: String,
    pub amount: u64,
    pub rho: String,
    pub blind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedTreeState {
    pub root: String,
    pub note_count: usize,
    pub filled_subtrees: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedInputRequest {
    pub owner_secret: String,
    pub amount: u64,
    pub rho: String,
    pub blind: String,
    pub leaf_index: usize,
    pub merkle_path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedDepositRequest {
    pub asset_id: String,
    pub old_root: String,
    pub append_state: ShieldedTreeState,
    pub amount: u64,
    pub outputs: Vec<ShieldedOutputRequest>,
    #[serde(default)]
    pub output_payload_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedTransferRequest {
    pub asset_id: String,
    pub old_root: String,
    pub append_state: ShieldedTreeState,
    pub inputs: Vec<ShieldedInputRequest>,
    pub outputs: Vec<ShieldedOutputRequest>,
    #[serde(default)]
    pub output_payload_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedWithdrawRequest {
    pub asset_id: String,
    pub old_root: String,
    pub append_state: ShieldedTreeState,
    pub amount: u64,
    pub recipient: String,
    pub inputs: Vec<ShieldedInputRequest>,
    pub outputs: Vec<ShieldedOutputRequest>,
    #[serde(default)]
    pub output_payload_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedProofResult {
    pub proof_hex: String,
    pub old_root: String,
    pub expected_new_root: String,
    pub public_inputs: Vec<String>,
    pub input_nullifiers: Vec<String>,
    pub output_commitments: Vec<String>,
    pub output_payload_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedCommandRequest {
    pub asset_id: String,
    pub old_root: String,
    pub append_state: ShieldedTreeState,
    pub fee: u64,
    pub public_amount: u64,
    pub inputs: Vec<ShieldedInputRequest>,
    pub outputs: Vec<ShieldedOutputRequest>,
    pub command_binding: String,
    #[serde(default)]
    pub output_payload_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShieldedCommandProofResult {
    pub proof_hex: String,
    pub old_root: String,
    pub expected_new_root: String,
    pub public_inputs: Vec<String>,
    pub command_binding: String,
    pub execution_tag: String,
    pub public_amount: u64,
    pub input_nullifiers: Vec<String>,
    pub output_commitments: Vec<String>,
    pub output_payload_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ShieldedCommandActionFixture {
    pub proof_hex: String,
    pub old_root: String,
    pub expected_new_root: String,
    pub public_inputs: Vec<String>,
    pub fee: u64,
    pub public_amount: u64,
    pub command_binding: String,
    pub execution_tag: String,
    pub input_count: usize,
    pub input_nullifiers: Vec<String>,
    pub output_count: usize,
    pub output_commitments: Vec<String>,
    pub output_payload_hashes: Vec<String>,
    pub target_contract: String,
    pub payload: serde_json::Value,
    pub relayer: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ShieldedCommandFixture {
    pub contract_name: String,
    pub asset_id: String,
    pub zero_root: String,
    pub tree_depth: usize,
    pub leaf_capacity: usize,
    pub max_inputs: usize,
    pub max_outputs: usize,
    pub verifying_keys: Vec<ShieldedVkFixture>,
    pub deposit: ShieldedActionFixture,
    pub command: ShieldedCommandActionFixture,
    pub withdraw: ShieldedActionFixture,
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
    merkle_path: Vec<Fr>,
    path_directions: Vec<bool>,
}

#[derive(Clone)]
struct OutputWitness {
    enabled: bool,
    owner_public: Fr,
    amount: u64,
    rho: Fr,
    blind: Fr,
}

#[derive(Clone)]
struct DepositCircuit {
    asset_id: Fr,
    old_root: Fr,
    amount: u64,
    output_count: usize,
    output_commitments: Vec<Fr>,
    output_payload_hashes: Vec<Fr>,
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
    output_payload_hashes: Vec<Fr>,
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
    output_payload_hashes: Vec<Fr>,
    inputs: Vec<InputWitness>,
    outputs: Vec<OutputWitness>,
}

#[derive(Clone)]
struct CommandCircuit {
    asset_id: Fr,
    old_root: Fr,
    command_binding: Fr,
    execution_tag: Fr,
    fee: u64,
    public_amount: u64,
    input_count: usize,
    input_nullifiers: Vec<Fr>,
    output_count: usize,
    output_commitments: Vec<Fr>,
    output_payload_hashes: Vec<Fr>,
    inputs: Vec<InputWitness>,
    outputs: Vec<OutputWitness>,
}

#[derive(Clone)]
struct FrontierState {
    root: Fr,
    note_count: usize,
    filled_subtrees: Vec<Fr>,
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

fn contract_sha3_to_field(value: &str) -> Fr {
    let digest = match hex::decode(value) {
        Ok(raw) => Sha3_256::digest(&raw),
        Err(_) => Sha3_256::digest(value.as_bytes()),
    };
    Fr::from_be_bytes_mod_order(&digest)
}

fn asset_id_for_contract(contract_name: &str) -> Fr {
    hash_to_field(contract_name)
}

fn recipient_digest(recipient: &str) -> Fr {
    contract_sha3_to_field(recipient)
}

fn output_payload_hash(payload_hex: &str) -> Fr {
    if payload_hex.is_empty() {
        return Fr::zero();
    }
    contract_sha3_to_field(payload_hex)
}

fn encode_command_payload_part(prefix: &str, value: &str) -> String {
    format!("{prefix}:{}:{value}", value.len())
}

fn canonicalize_command_payload(
    value: &serde_json::Value,
) -> Result<String, Box<dyn Error>> {
    match value {
        serde_json::Value::Null => Ok("n".to_string()),
        serde_json::Value::Bool(flag) => Ok(if *flag { "b:1" } else { "b:0" }.to_string()),
        serde_json::Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                Ok(format!("i:{value}"))
            } else if let Some(value) = number.as_u64() {
                Ok(format!("i:{value}"))
            } else {
                Err("command payload numbers must be integers".into())
            }
        }
        serde_json::Value::String(text) => Ok(encode_command_payload_part("s", text)),
        serde_json::Value::Array(items) => {
            let mut body = String::new();
            for item in items {
                body.push_str(&encode_command_payload_part(
                    "e",
                    &canonicalize_command_payload(item)?,
                ));
            }
            Ok(format!("l:{}:{body}", items.len()))
        }
        serde_json::Value::Object(entries) => {
            let mut keys: Vec<&String> = entries.keys().collect();
            keys.sort();
            let mut body = String::new();
            for key in keys {
                body.push_str(&encode_command_payload_part("k", key));
                body.push_str(&encode_command_payload_part(
                    "v",
                    &canonicalize_command_payload(
                        entries.get(key).expect("sorted key must exist"),
                    )?,
                ));
            }
            Ok(format!("d:{}:{body}", entries.len()))
        }
    }
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

fn output_commitment(asset_id: Fr, owner_public: Fr, amount: u64, rho: Fr, blind: Fr) -> Fr {
    mimc_hash_many_native(&[asset_id, owner_public, Fr::from(amount), rho, blind])
}

fn note_commitment(asset_id: Fr, note: &NoteWitness) -> Fr {
    output_commitment(
        asset_id,
        owner_public(note.owner_secret),
        note.amount,
        note.rho,
        note.blind,
    )
}

fn note_nullifier(asset_id: Fr, note: &NoteWitness) -> Fr {
    mimc_hash_many_native(&[asset_id, note.owner_secret, note.rho])
}

fn command_nullifier_digest(input_nullifiers: &[Fr]) -> Fr {
    mimc_hash_many_native(input_nullifiers)
}

fn command_binding(
    nullifier_digest: Fr,
    target_digest: Fr,
    payload_digest: Fr,
    relayer_digest: Fr,
    expiry_digest: Fr,
    chain_digest: Fr,
    entrypoint_digest: Fr,
    version_digest: Fr,
    fee: u64,
    public_amount: u64,
) -> Fr {
    mimc_hash_many_native(&[
        nullifier_digest,
        target_digest,
        payload_digest,
        relayer_digest,
        expiry_digest,
        chain_digest,
        entrypoint_digest,
        version_digest,
        Fr::from(fee),
        Fr::from(public_amount),
    ])
}

fn command_execution_tag(nullifier_digest: Fr, command_binding: Fr) -> Fr {
    mimc_hash_many_native(&[nullifier_digest, command_binding])
}

fn merkle_parent(left: Fr, right: Fr) -> Fr {
    mimc_hash_many_native(&[left, right])
}

fn zero_hashes() -> Vec<Fr> {
    let mut values = Vec::with_capacity(SHIELDED_NOTE_TREE_DEPTH + 1);
    let mut current = Fr::zero();
    values.push(current);
    for _ in 0..SHIELDED_NOTE_TREE_DEPTH {
        current = merkle_parent(current, current);
        values.push(current);
    }
    values
}

fn zero_root() -> Fr {
    zero_hashes()[SHIELDED_NOTE_TREE_DEPTH]
}

fn frontier_state_to_public(state: &FrontierState) -> ShieldedTreeState {
    ShieldedTreeState {
        root: field_hex(state.root),
        note_count: state.note_count,
        filled_subtrees: state
            .filled_subtrees
            .iter()
            .copied()
            .map(field_hex)
            .collect(),
    }
}

fn leaf_fields_from_commitments(commitments: &[String]) -> Result<Vec<Fr>, Box<dyn Error>> {
    if commitments.len() > SHIELDED_NOTE_TREE_LEAF_COUNT {
        return Err("too many commitments for shielded tree".into());
    }

    let mut leaves = Vec::with_capacity(commitments.len());
    for commitment in commitments {
        let field = parse_field_hex(commitment)?;
        if field.is_zero() {
            return Err("stored commitments must be non-zero".into());
        }
        leaves.push(field);
    }
    Ok(leaves)
}

fn root_from_frontier(note_count: usize, filled_subtrees: &[Fr]) -> Result<Fr, Box<dyn Error>> {
    if note_count > SHIELDED_NOTE_TREE_LEAF_COUNT {
        return Err("note_count exceeds shielded tree capacity".into());
    }
    if filled_subtrees.len() != SHIELDED_NOTE_TREE_DEPTH {
        return Err("filled_subtrees length does not match tree depth".into());
    }

    let zeroes = zero_hashes();
    let mut current = Fr::zero();
    let mut index = note_count;

    for level in 0..SHIELDED_NOTE_TREE_DEPTH {
        current = if index & 1 == 1 {
            merkle_parent(filled_subtrees[level], current)
        } else {
            merkle_parent(current, zeroes[level])
        };
        index >>= 1;
    }

    Ok(current)
}

fn empty_frontier_state() -> FrontierState {
    FrontierState {
        root: zero_root(),
        note_count: 0,
        filled_subtrees: vec![Fr::zero(); SHIELDED_NOTE_TREE_DEPTH],
    }
}

fn append_commitment_to_state(
    state: &mut FrontierState,
    commitment: Fr,
) -> Result<(), Box<dyn Error>> {
    if commitment.is_zero() {
        return Err("output commitments must be non-zero".into());
    }
    if state.note_count >= SHIELDED_NOTE_TREE_LEAF_COUNT {
        return Err("shielded tree is full".into());
    }

    let zeroes = zero_hashes();
    let mut current_hash = commitment;
    let mut index = state.note_count;

    for level in 0..SHIELDED_NOTE_TREE_DEPTH {
        if index & 1 == 0 {
            state.filled_subtrees[level] = current_hash;
            current_hash = merkle_parent(current_hash, zeroes[level]);
        } else {
            current_hash = merkle_parent(state.filled_subtrees[level], current_hash);
        }
        index >>= 1;
    }

    state.note_count += 1;
    state.root = current_hash;
    Ok(())
}

fn append_commitments_to_state(
    state: &FrontierState,
    commitments: &[Fr],
) -> Result<FrontierState, Box<dyn Error>> {
    let mut next = state.clone();
    for commitment in commitments {
        append_commitment_to_state(&mut next, *commitment)?;
    }
    Ok(next)
}

fn tree_state_from_commitments(commitments: &[String]) -> Result<FrontierState, Box<dyn Error>> {
    let leaves = leaf_fields_from_commitments(commitments)?;
    let mut state = empty_frontier_state();
    for leaf in leaves {
        append_commitment_to_state(&mut state, leaf)?;
    }
    Ok(state)
}

fn parse_tree_state(state: &ShieldedTreeState) -> Result<FrontierState, Box<dyn Error>> {
    if state.filled_subtrees.len() != SHIELDED_NOTE_TREE_DEPTH {
        return Err("filled_subtrees length does not match tree depth".into());
    }

    let parsed_root = parse_field_hex(&state.root)?;
    let mut filled_subtrees = Vec::with_capacity(SHIELDED_NOTE_TREE_DEPTH);
    for value in &state.filled_subtrees {
        filled_subtrees.push(parse_field_hex(value)?);
    }

    let derived_root = root_from_frontier(state.note_count, &filled_subtrees)?;
    if derived_root != parsed_root {
        return Err("append_state root does not match filled_subtrees".into());
    }

    Ok(FrontierState {
        root: parsed_root,
        note_count: state.note_count,
        filled_subtrees,
    })
}

fn auth_path_from_leaves(leaves: &[Fr], leaf_index: usize) -> Result<Vec<Fr>, Box<dyn Error>> {
    if leaf_index >= leaves.len() {
        return Err("leaf_index is out of range".into());
    }

    let zeroes = zero_hashes();
    let mut level = leaves.to_vec();
    let mut index = leaf_index;
    let mut path = Vec::with_capacity(SHIELDED_NOTE_TREE_DEPTH);

    for depth in 0..SHIELDED_NOTE_TREE_DEPTH {
        let sibling = if index & 1 == 0 {
            if index + 1 < level.len() {
                level[index + 1]
            } else {
                zeroes[depth]
            }
        } else {
            level[index - 1]
        };
        path.push(sibling);

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair_start in (0..level.len()).step_by(2) {
            let left = level[pair_start];
            let right = if pair_start + 1 < level.len() {
                level[pair_start + 1]
            } else {
                zeroes[depth]
            };
            next.push(merkle_parent(left, right));
        }

        if next.is_empty() {
            next.push(zeroes[depth + 1]);
        }

        level = next;
        index >>= 1;
    }

    Ok(path)
}

fn output_witness_from_request(
    output: &ShieldedOutputRequest,
) -> Result<OutputWitness, Box<dyn Error>> {
    Ok(OutputWitness {
        enabled: true,
        owner_public: parse_field_hex(&output.owner_public)?,
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

pub fn shielded_note_zero_root_hex() -> String {
    field_hex(zero_root())
}

pub fn shielded_note_asset_id_hex(contract_name: &str) -> String {
    field_hex(asset_id_for_contract(contract_name))
}

pub fn shielded_note_recipient_digest_hex(recipient: &str) -> String {
    field_hex(recipient_digest(recipient))
}

pub fn shielded_output_payload_hash_hex(payload_hex: &str) -> String {
    field_hex(output_payload_hash(payload_hex))
}

pub fn shielded_note_owner_public_hex(owner_secret_hex: &str) -> Result<String, Box<dyn Error>> {
    Ok(field_hex(owner_public(parse_field_hex(owner_secret_hex)?)))
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

pub fn shielded_note_output_commitment_hex(
    asset_id_hex: &str,
    owner_public_hex: &str,
    amount: u64,
    rho_hex: &str,
    blind_hex: &str,
) -> Result<String, Box<dyn Error>> {
    Ok(field_hex(output_commitment(
        parse_field_hex(asset_id_hex)?,
        parse_field_hex(owner_public_hex)?,
        amount,
        parse_field_hex(rho_hex)?,
        parse_field_hex(blind_hex)?,
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
    Ok(field_hex(tree_state_from_commitments(commitments)?.root))
}

pub fn shielded_note_tree_state(
    commitments: &[String],
) -> Result<ShieldedTreeState, Box<dyn Error>> {
    Ok(frontier_state_to_public(&tree_state_from_commitments(
        commitments,
    )?))
}

pub fn shielded_note_auth_path_hex(
    commitments: &[String],
    leaf_index: usize,
) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(
        auth_path_from_leaves(&leaf_fields_from_commitments(commitments)?, leaf_index)?
            .into_iter()
            .map(field_hex)
            .collect(),
    )
}

pub fn shielded_command_nullifier_digest_hex(
    input_nullifier_hexes: &[String],
) -> Result<String, Box<dyn Error>> {
    if input_nullifier_hexes.is_empty() || input_nullifier_hexes.len() > SHIELDED_NOTE_MAX_INPUTS {
        return Err("invalid input nullifier count".into());
    }
    let parsed = input_nullifier_hexes
        .iter()
        .map(|value| parse_field_hex(value))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(field_hex(command_nullifier_digest(
        &pad_fields(parsed, SHIELDED_NOTE_MAX_INPUTS),
    )))
}

pub fn shielded_command_binding_hex(
    nullifier_digest_hex: &str,
    target_digest_hex: &str,
    payload_digest_hex: &str,
    relayer_digest_hex: &str,
    expiry_digest_hex: &str,
    chain_digest_hex: &str,
    entrypoint_digest_hex: &str,
    version_digest_hex: &str,
    fee: u64,
    public_amount: u64,
) -> Result<String, Box<dyn Error>> {
    Ok(field_hex(command_binding(
        parse_field_hex(nullifier_digest_hex)?,
        parse_field_hex(target_digest_hex)?,
        parse_field_hex(payload_digest_hex)?,
        parse_field_hex(relayer_digest_hex)?,
        parse_field_hex(expiry_digest_hex)?,
        parse_field_hex(chain_digest_hex)?,
        parse_field_hex(entrypoint_digest_hex)?,
        parse_field_hex(version_digest_hex)?,
        fee,
        public_amount,
    )))
}

pub fn shielded_command_execution_tag_hex(
    nullifier_digest_hex: &str,
    command_binding_hex_value: &str,
) -> Result<String, Box<dyn Error>> {
    Ok(field_hex(command_execution_tag(
        parse_field_hex(nullifier_digest_hex)?,
        parse_field_hex(command_binding_hex_value)?,
    )))
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

fn output_commitment_var(
    asset_id: &FpVar<Fr>,
    owner_public: &FpVar<Fr>,
    amount: &FpVar<Fr>,
    rho: &FpVar<Fr>,
    blind: &FpVar<Fr>,
) -> FpVar<Fr> {
    mimc_hash_many_var(&[
        asset_id.clone(),
        owner_public.clone(),
        amount.clone(),
        rho.clone(),
        blind.clone(),
    ])
}

fn note_commitment_var(
    asset_id: &FpVar<Fr>,
    owner_secret: &FpVar<Fr>,
    amount: &FpVar<Fr>,
    rho: &FpVar<Fr>,
    blind: &FpVar<Fr>,
) -> FpVar<Fr> {
    let owner_public = owner_public_var(owner_secret);
    output_commitment_var(asset_id, &owner_public, amount, rho, blind)
}

fn note_nullifier_var(
    asset_id: &FpVar<Fr>,
    owner_secret: &FpVar<Fr>,
    rho: &FpVar<Fr>,
) -> FpVar<Fr> {
    mimc_hash_many_var(&[asset_id.clone(), owner_secret.clone(), rho.clone()])
}

fn command_nullifier_digest_var(input_nullifiers: &[FpVar<Fr>]) -> FpVar<Fr> {
    mimc_hash_many_var(input_nullifiers)
}

fn command_execution_tag_var(
    nullifier_digest: &FpVar<Fr>,
    command_binding: &FpVar<Fr>,
) -> FpVar<Fr> {
    mimc_hash_many_var(&[nullifier_digest.clone(), command_binding.clone()])
}

fn merkle_parent_var(left: &FpVar<Fr>, right: &FpVar<Fr>) -> FpVar<Fr> {
    mimc_hash_many_var(&[left.clone(), right.clone()])
}

fn merkle_root_from_auth_path_var(
    cs: ConstraintSystemRef<Fr>,
    leaf: &FpVar<Fr>,
    auth_path: &[FpVar<Fr>],
    path_directions: &[bool],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut current = leaf.clone();
    for (level, sibling) in auth_path.iter().enumerate() {
        let is_right = Boolean::new_witness(cs.clone(), || Ok(path_directions[level]))?;
        let left = is_right.select(sibling, &current)?;
        let right = is_right.select(&current, sibling)?;
        current = merkle_parent_var(&left, &right);
    }
    Ok(current)
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

fn witness_path_var(
    cs: ConstraintSystemRef<Fr>,
    path: &[Fr],
) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    path.iter()
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
            output_payload_hashes: vec![Fr::zero(); SHIELDED_NOTE_MAX_OUTPUTS],
            outputs: (0..SHIELDED_NOTE_MAX_OUTPUTS)
                .map(|_| blank_output_witness())
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
        values.extend(self.output_payload_hashes.iter().copied());
        values
    }
}

impl ConstraintSynthesizer<Fr> for DepositCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let public = public_inputs_var(cs.clone(), &self.public_inputs())?;
        let asset_id = &public[0];
        let _old_root = &public[1];
        let amount = &public[2];
        let output_count = &public[3];
        let public_commitments = &public[4..];

        let mut enabled_sum = FpVar::constant(Fr::zero());
        let mut output_sum = FpVar::constant(Fr::zero());

        for (index, output) in self.outputs.iter().enumerate() {
            let enabled = Boolean::new_witness(cs.clone(), || Ok(output.enabled))?;
            let enabled_fp = bool_to_fp(&enabled)?;
            enabled_sum += enabled_fp.clone();

            let owner_public =
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.owner_public))?;
            let rho = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.rho))?;
            let blind = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.blind))?;
            let note_amount = amount_bits_to_var(cs.clone(), output.amount)?;
            let commitment =
                output_commitment_var(asset_id, &owner_public, &note_amount, &rho, &blind);

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
            output_payload_hashes: vec![Fr::zero(); SHIELDED_NOTE_MAX_OUTPUTS],
            inputs: (0..SHIELDED_NOTE_MAX_INPUTS)
                .map(|_| InputWitness {
                    enabled: false,
                    note: NoteWitness {
                        owner_secret: Fr::zero(),
                        amount: 0,
                        rho: Fr::zero(),
                        blind: Fr::zero(),
                    },
                    merkle_path: vec![Fr::zero(); SHIELDED_NOTE_TREE_DEPTH],
                    path_directions: vec![false; SHIELDED_NOTE_TREE_DEPTH],
                })
                .collect(),
            outputs: (0..SHIELDED_NOTE_MAX_OUTPUTS)
                .map(|_| blank_output_witness())
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
        values.extend(self.output_payload_hashes.iter().copied());
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
            let auth_path = witness_path_var(cs.clone(), &input.merkle_path)?;
            let membership_root = merkle_root_from_auth_path_var(
                cs.clone(),
                &commitment,
                &auth_path,
                &input.path_directions,
            )?;
            ((membership_root - old_root.clone()) * enabled_fp.clone())
                .enforce_equal(&FpVar::constant(Fr::zero()))?;

            let nullifier = note_nullifier_var(asset_id, &owner_secret, &rho) * enabled_fp.clone();
            public_nullifiers[index].enforce_equal(&nullifier)?;
            input_sum += note_amount * enabled_fp;
        }

        for (index, output) in self.outputs.iter().enumerate() {
            let enabled = Boolean::new_witness(cs.clone(), || Ok(output.enabled))?;
            let enabled_fp = bool_to_fp(&enabled)?;
            output_enabled_sum += enabled_fp.clone();

            let owner_public =
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.owner_public))?;
            let rho = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.rho))?;
            let blind = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.blind))?;
            let note_amount = amount_bits_to_var(cs.clone(), output.amount)?;
            let commitment =
                output_commitment_var(asset_id, &owner_public, &note_amount, &rho, &blind);
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
            output_payload_hashes: vec![Fr::zero(); SHIELDED_NOTE_MAX_OUTPUTS],
            inputs: (0..SHIELDED_NOTE_MAX_INPUTS)
                .map(|_| InputWitness {
                    enabled: false,
                    note: NoteWitness {
                        owner_secret: Fr::zero(),
                        amount: 0,
                        rho: Fr::zero(),
                        blind: Fr::zero(),
                    },
                    merkle_path: vec![Fr::zero(); SHIELDED_NOTE_TREE_DEPTH],
                    path_directions: vec![false; SHIELDED_NOTE_TREE_DEPTH],
                })
                .collect(),
            outputs: (0..SHIELDED_NOTE_MAX_OUTPUTS)
                .map(|_| blank_output_witness())
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
        values.extend(self.output_payload_hashes.iter().copied());
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
            let auth_path = witness_path_var(cs.clone(), &input.merkle_path)?;
            let membership_root = merkle_root_from_auth_path_var(
                cs.clone(),
                &commitment,
                &auth_path,
                &input.path_directions,
            )?;
            ((membership_root - old_root.clone()) * enabled_fp.clone())
                .enforce_equal(&FpVar::constant(Fr::zero()))?;

            let nullifier = note_nullifier_var(asset_id, &owner_secret, &rho) * enabled_fp.clone();
            public_nullifiers[index].enforce_equal(&nullifier)?;
            input_sum += note_amount * enabled_fp;
        }

        for (index, output) in self.outputs.iter().enumerate() {
            let enabled = Boolean::new_witness(cs.clone(), || Ok(output.enabled))?;
            let enabled_fp = bool_to_fp(&enabled)?;
            output_enabled_sum += enabled_fp.clone();

            let owner_public =
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.owner_public))?;
            let rho = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.rho))?;
            let blind = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.blind))?;
            let note_amount = amount_bits_to_var(cs.clone(), output.amount)?;
            let commitment =
                output_commitment_var(asset_id, &owner_public, &note_amount, &rho, &blind);
            public_commitments[index].enforce_equal(&(commitment * enabled_fp.clone()))?;
            output_sum += note_amount * enabled_fp;
        }

        input_enabled_sum.enforce_equal(input_count)?;
        output_enabled_sum.enforce_equal(output_count)?;
        input_sum.enforce_equal(&(output_sum + amount.clone()))?;
        Ok(())
    }
}

impl CommandCircuit {
    fn blank() -> Self {
        let input_nullifiers = vec![Fr::zero(); SHIELDED_NOTE_MAX_INPUTS];
        let nullifier_digest = command_nullifier_digest(&input_nullifiers);
        let command_binding = command_binding(
            nullifier_digest,
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            Fr::zero(),
            0,
            0,
        );
        Self {
            asset_id: Fr::zero(),
            old_root: zero_root(),
            command_binding,
            execution_tag: command_execution_tag(nullifier_digest, command_binding),
            fee: 0,
            public_amount: 0,
            input_count: 0,
            input_nullifiers,
            output_count: 0,
            output_commitments: vec![Fr::zero(); SHIELDED_NOTE_MAX_OUTPUTS],
            output_payload_hashes: vec![Fr::zero(); SHIELDED_NOTE_MAX_OUTPUTS],
            inputs: (0..SHIELDED_NOTE_MAX_INPUTS)
                .map(|_| blank_input_witness())
                .collect(),
            outputs: (0..SHIELDED_NOTE_MAX_OUTPUTS)
                .map(|_| blank_output_witness())
                .collect(),
        }
    }

    fn public_inputs(&self) -> Vec<Fr> {
        let mut values = vec![
            self.asset_id,
            self.old_root,
            self.command_binding,
            self.execution_tag,
            Fr::from(self.fee),
            Fr::from(self.public_amount),
            Fr::from(self.input_count as u64),
            Fr::from(self.output_count as u64),
        ];
        values.extend(self.input_nullifiers.iter().copied());
        values.extend(self.output_commitments.iter().copied());
        values.extend(self.output_payload_hashes.iter().copied());
        values
    }
}

impl ConstraintSynthesizer<Fr> for CommandCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let public = public_inputs_var(cs.clone(), &self.public_inputs())?;
        let asset_id = &public[0];
        let old_root = &public[1];
        let command_binding = &public[2];
        let public_execution_tag = &public[3];
        let fee = &public[4];
        let public_amount = &public[5];
        let input_count = &public[6];
        let output_count = &public[7];
        let public_nullifiers = &public[8..8 + SHIELDED_NOTE_MAX_INPUTS];
        let public_commitments = &public[8 + SHIELDED_NOTE_MAX_INPUTS
            ..8 + SHIELDED_NOTE_MAX_INPUTS + SHIELDED_NOTE_MAX_OUTPUTS];

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
            let auth_path = witness_path_var(cs.clone(), &input.merkle_path)?;
            let membership_root = merkle_root_from_auth_path_var(
                cs.clone(),
                &commitment,
                &auth_path,
                &input.path_directions,
            )?;
            ((membership_root - old_root.clone()) * enabled_fp.clone())
                .enforce_equal(&FpVar::constant(Fr::zero()))?;

            let nullifier = note_nullifier_var(asset_id, &owner_secret, &rho) * enabled_fp.clone();
            public_nullifiers[index].enforce_equal(&nullifier)?;
            input_sum += note_amount * enabled_fp;
        }

        let nullifier_digest = command_nullifier_digest_var(public_nullifiers);
        let execution_tag = command_execution_tag_var(&nullifier_digest, command_binding);
        public_execution_tag.enforce_equal(&execution_tag)?;

        for (index, output) in self.outputs.iter().enumerate() {
            let enabled = Boolean::new_witness(cs.clone(), || Ok(output.enabled))?;
            let enabled_fp = bool_to_fp(&enabled)?;
            output_enabled_sum += enabled_fp.clone();

            let owner_public =
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.owner_public))?;
            let rho = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.rho))?;
            let blind = FpVar::<Fr>::new_witness(cs.clone(), || Ok(output.blind))?;
            let note_amount = amount_bits_to_var(cs.clone(), output.amount)?;
            let commitment =
                output_commitment_var(asset_id, &owner_public, &note_amount, &rho, &blind);
            public_commitments[index].enforce_equal(&(commitment * enabled_fp.clone()))?;
            output_sum += note_amount * enabled_fp;
        }

        input_enabled_sum.enforce_equal(input_count)?;
        output_enabled_sum.enforce_equal(output_count)?;
        input_sum.enforce_equal(&(output_sum + fee.clone() + public_amount.clone()))?;
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
        owner_public: Fr::zero(),
        amount: 0,
        rho: Fr::zero(),
        blind: Fr::zero(),
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
        merkle_path: vec![Fr::zero(); SHIELDED_NOTE_TREE_DEPTH],
        path_directions: vec![false; SHIELDED_NOTE_TREE_DEPTH],
    }
}

fn pad_fields(mut values: Vec<Fr>, size: usize) -> Vec<Fr> {
    while values.len() < size {
        values.push(Fr::zero());
    }
    values
}

fn parse_merkle_path(path: &[String]) -> Result<Vec<Fr>, Box<dyn Error>> {
    if path.len() != SHIELDED_NOTE_TREE_DEPTH {
        return Err("merkle_path length does not match tree depth".into());
    }
    path.iter().map(|value| parse_field_hex(value)).collect()
}

fn path_directions_for_leaf_index(leaf_index: usize) -> Vec<bool> {
    let mut directions = Vec::with_capacity(SHIELDED_NOTE_TREE_DEPTH);
    for level in 0..SHIELDED_NOTE_TREE_DEPTH {
        directions.push(((leaf_index >> level) & 1) == 1);
    }
    directions
}

fn input_witness_from_request(
    input: &ShieldedInputRequest,
) -> Result<InputWitness, Box<dyn Error>> {
    if input.leaf_index >= SHIELDED_NOTE_TREE_LEAF_COUNT {
        return Err("leaf_index exceeds tree capacity".into());
    }
    Ok(InputWitness {
        enabled: true,
        note: note_from_input_request(input)?,
        merkle_path: parse_merkle_path(&input.merkle_path)?,
        path_directions: path_directions_for_leaf_index(input.leaf_index),
    })
}

fn build_output_witnesses(
    asset_id: Fr,
    outputs: &[ShieldedOutputRequest],
) -> Result<(Vec<OutputWitness>, Vec<Fr>), Box<dyn Error>> {
    let mut output_witnesses = Vec::new();
    let mut output_commitments = Vec::new();
    for output in outputs {
        let witness = output_witness_from_request(output)?;
        output_commitments.push(output_commitment(
            asset_id,
            witness.owner_public,
            witness.amount,
            witness.rho,
            witness.blind,
        ));
        output_witnesses.push(witness);
    }
    while output_witnesses.len() < SHIELDED_NOTE_MAX_OUTPUTS {
        output_witnesses.push(blank_output_witness());
    }
    Ok((output_witnesses, output_commitments))
}

fn parse_output_payload_hashes(
    payload_hashes: &[String],
    output_count: usize,
) -> Result<Vec<Fr>, Box<dyn Error>> {
    if payload_hashes.is_empty() {
        return Ok(vec![Fr::zero(); output_count]);
    }
    if payload_hashes.len() != output_count {
        return Err("output_payload_hashes length must match outputs".into());
    }
    payload_hashes
        .iter()
        .map(|value| parse_field_hex(value))
        .collect()
}

pub fn build_shielded_note_fixture() -> Result<ShieldedFixture, Box<dyn Error>> {
    let contract_name = "con_shielded_note_token";
    let asset_id = asset_id_for_contract(contract_name);
    let zero_state = empty_frontier_state();

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

    let commitments1 = vec![field_hex(commitment_a1), field_hex(commitment_a2)];
    let commitments2 = vec![
        field_hex(commitment_a1),
        field_hex(commitment_a2),
        field_hex(commitment_b1),
        field_hex(commitment_a3),
    ];
    let commitments3 = vec![
        field_hex(commitment_a1),
        field_hex(commitment_a2),
        field_hex(commitment_b1),
        field_hex(commitment_a3),
        field_hex(commitment_a4),
    ];

    let state1 = tree_state_from_commitments(&commitments1)?;
    let state2 = tree_state_from_commitments(&commitments2)?;
    let state3 = tree_state_from_commitments(&commitments3)?;
    let leaves1 = leaf_fields_from_commitments(&commitments1)?;
    let leaves2 = leaf_fields_from_commitments(&commitments2)?;

    let deposit_circuit = DepositCircuit {
        asset_id,
        old_root: zero_state.root,
        amount: 70,
        output_count: 2,
        output_commitments: pad_fields(
            vec![commitment_a1, commitment_a2],
            SHIELDED_NOTE_MAX_OUTPUTS,
        ),
        output_payload_hashes: vec![Fr::zero(); SHIELDED_NOTE_MAX_OUTPUTS],
        outputs: vec![
            OutputWitness {
                enabled: true,
                owner_public: owner_public(note_a1.owner_secret),
                amount: note_a1.amount,
                rho: note_a1.rho,
                blind: note_a1.blind,
            },
            OutputWitness {
                enabled: true,
                owner_public: owner_public(note_a2.owner_secret),
                amount: note_a2.amount,
                rho: note_a2.rho,
                blind: note_a2.blind,
            },
            blank_output_witness(),
            blank_output_witness(),
        ],
    };

    let transfer_circuit = TransferCircuit {
        asset_id,
        old_root: state1.root,
        input_count: 2,
        output_count: 2,
        input_nullifiers: pad_fields(vec![nullifier_a1, nullifier_a2], SHIELDED_NOTE_MAX_INPUTS),
        output_commitments: pad_fields(
            vec![commitment_b1, commitment_a3],
            SHIELDED_NOTE_MAX_OUTPUTS,
        ),
        output_payload_hashes: vec![Fr::zero(); SHIELDED_NOTE_MAX_OUTPUTS],
        inputs: vec![
            InputWitness {
                enabled: true,
                note: note_a1.clone(),
                merkle_path: auth_path_from_leaves(&leaves1, 0)?,
                path_directions: path_directions_for_leaf_index(0),
            },
            InputWitness {
                enabled: true,
                note: note_a2.clone(),
                merkle_path: auth_path_from_leaves(&leaves1, 1)?,
                path_directions: path_directions_for_leaf_index(1),
            },
            blank_input_witness(),
            blank_input_witness(),
        ],
        outputs: vec![
            OutputWitness {
                enabled: true,
                owner_public: owner_public(note_b1.owner_secret),
                amount: note_b1.amount,
                rho: note_b1.rho,
                blind: note_b1.blind,
            },
            OutputWitness {
                enabled: true,
                owner_public: owner_public(note_a3.owner_secret),
                amount: note_a3.amount,
                rho: note_a3.rho,
                blind: note_a3.blind,
            },
            blank_output_witness(),
            blank_output_witness(),
        ],
    };

    let withdraw_circuit = WithdrawCircuit {
        asset_id,
        old_root: state2.root,
        amount: 20,
        recipient_digest: recipient_digest("bob"),
        input_count: 1,
        output_count: 1,
        input_nullifiers: pad_fields(vec![nullifier_a3], SHIELDED_NOTE_MAX_INPUTS),
        output_commitments: pad_fields(vec![commitment_a4], SHIELDED_NOTE_MAX_OUTPUTS),
        output_payload_hashes: vec![Fr::zero(); SHIELDED_NOTE_MAX_OUTPUTS],
        inputs: vec![
            InputWitness {
                enabled: true,
                note: note_a3.clone(),
                merkle_path: auth_path_from_leaves(&leaves2, 3)?,
                path_directions: path_directions_for_leaf_index(3),
            },
            blank_input_witness(),
            blank_input_witness(),
            blank_input_witness(),
        ],
        outputs: vec![
            OutputWitness {
                enabled: true,
                owner_public: owner_public(note_a4.owner_secret),
                amount: note_a4.amount,
                rho: note_a4.rho,
                blind: note_a4.blind,
            },
            blank_output_witness(),
            blank_output_witness(),
            blank_output_witness(),
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
        zero_root: field_hex(zero_state.root),
        tree_depth: SHIELDED_NOTE_TREE_DEPTH,
        leaf_capacity: SHIELDED_NOTE_TREE_LEAF_COUNT,
        max_inputs: SHIELDED_NOTE_MAX_INPUTS,
        max_outputs: SHIELDED_NOTE_MAX_OUTPUTS,
        verifying_keys: vec![
            ShieldedVkFixture {
                vk_id: "shielded-deposit-v3".to_string(),
                circuit_name: "shielded_note_deposit_v3".to_string(),
                version: "3".to_string(),
                vk_hex: serialize_hex(&deposit_vk)?,
            },
            ShieldedVkFixture {
                vk_id: "shielded-transfer-v3".to_string(),
                circuit_name: "shielded_note_transfer_v3".to_string(),
                version: "3".to_string(),
                vk_hex: serialize_hex(&transfer_vk)?,
            },
            ShieldedVkFixture {
                vk_id: "shielded-withdraw-v3".to_string(),
                circuit_name: "shielded_note_withdraw_v3".to_string(),
                version: "3".to_string(),
                vk_hex: serialize_hex(&withdraw_vk)?,
            },
        ],
        deposit: ShieldedActionFixture {
            proof_hex: serialize_hex(&deposit_proof)?,
            old_root: field_hex(zero_state.root),
            expected_new_root: field_hex(state1.root),
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
            output_payload_hashes: vec![field_hex(Fr::zero()), field_hex(Fr::zero())],
        },
        transfer: ShieldedActionFixture {
            proof_hex: serialize_hex(&transfer_proof)?,
            old_root: field_hex(state1.root),
            expected_new_root: field_hex(state2.root),
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
            output_payload_hashes: vec![field_hex(Fr::zero()), field_hex(Fr::zero())],
        },
        withdraw: ShieldedActionFixture {
            proof_hex: serialize_hex(&withdraw_proof)?,
            old_root: field_hex(state2.root),
            expected_new_root: field_hex(state3.root),
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
            output_payload_hashes: vec![field_hex(Fr::zero())],
        },
    })
}

struct ShieldedBundleDescriptor<'a> {
    contract_name: &'a str,
    warning: &'a str,
    setup_mode: &'a str,
    setup_ceremony: &'a str,
    deposit_vk_id: &'a str,
    transfer_vk_id: &'a str,
    withdraw_vk_id: &'a str,
}

fn build_shielded_note_bundle_with_rng(
    rng: &mut StdRng,
    descriptor: &ShieldedBundleDescriptor<'_>,
) -> Result<ShieldedProverBundle, Box<dyn Error>> {
    let (deposit_pk, deposit_vk, _) =
        prove_circuit(rng, DepositCircuit::blank(), DepositCircuit::blank())?;
    let (transfer_pk, transfer_vk, _) =
        prove_circuit(rng, TransferCircuit::blank(), TransferCircuit::blank())?;
    let (withdraw_pk, withdraw_vk, _) =
        prove_circuit(rng, WithdrawCircuit::blank(), WithdrawCircuit::blank())?;

    Ok(ShieldedProverBundle {
        circuit_family: SHIELDED_NOTE_CIRCUIT_FAMILY.to_string(),
        warning: descriptor.warning.to_string(),
        setup_mode: descriptor.setup_mode.to_string(),
        setup_ceremony: descriptor.setup_ceremony.to_string(),
        contract_name: descriptor.contract_name.to_string(),
        tree_depth: SHIELDED_NOTE_TREE_DEPTH,
        leaf_capacity: SHIELDED_NOTE_TREE_LEAF_COUNT,
        max_inputs: SHIELDED_NOTE_MAX_INPUTS,
        max_outputs: SHIELDED_NOTE_MAX_OUTPUTS,
        deposit: ShieldedCircuitBundle {
            vk_id: descriptor.deposit_vk_id.to_string(),
            circuit_name: SHIELDED_NOTE_DEPOSIT_CIRCUIT_NAME.to_string(),
            version: SHIELDED_NOTE_CIRCUIT_VERSION.to_string(),
            vk_hex: serialize_hex(&deposit_vk)?,
            pk_hex: serialize_hex(&deposit_pk)?,
        },
        transfer: ShieldedCircuitBundle {
            vk_id: descriptor.transfer_vk_id.to_string(),
            circuit_name: SHIELDED_NOTE_TRANSFER_CIRCUIT_NAME.to_string(),
            version: SHIELDED_NOTE_CIRCUIT_VERSION.to_string(),
            vk_hex: serialize_hex(&transfer_vk)?,
            pk_hex: serialize_hex(&transfer_pk)?,
        },
        withdraw: ShieldedCircuitBundle {
            vk_id: descriptor.withdraw_vk_id.to_string(),
            circuit_name: SHIELDED_NOTE_WITHDRAW_CIRCUIT_NAME.to_string(),
            version: SHIELDED_NOTE_CIRCUIT_VERSION.to_string(),
            vk_hex: serialize_hex(&withdraw_vk)?,
            pk_hex: serialize_hex(&withdraw_pk)?,
        },
    })
}

pub fn build_random_shielded_note_bundle(
    contract_name: &str,
    vk_id_prefix: &str,
) -> Result<ShieldedProverBundle, Box<dyn Error>> {
    if contract_name.is_empty() {
        return Err("contract_name must be non-empty".into());
    }
    if vk_id_prefix.is_empty() {
        return Err("vk_id_prefix must be non-empty".into());
    }

    let deposit_vk_id = format!("{vk_id_prefix}-deposit");
    let transfer_vk_id = format!("{vk_id_prefix}-transfer");
    let withdraw_vk_id = format!("{vk_id_prefix}-withdraw");
    let descriptor = ShieldedBundleDescriptor {
        contract_name,
        warning: "SINGLE-PARTY RANDOM BUNDLE: generated from OS randomness for deployment use. This replaces the deterministic dev setup but is still not an MPC ceremony.",
        setup_mode: "single-party",
        setup_ceremony: "",
        deposit_vk_id: &deposit_vk_id,
        transfer_vk_id: &transfer_vk_id,
        withdraw_vk_id: &withdraw_vk_id,
    };

    let mut rng = StdRng::from_rng(OsRng)
        .map_err(|error| format!("failed to seed random setup rng: {error}"))?;
    build_shielded_note_bundle_with_rng(&mut rng, &descriptor)
}

pub fn build_insecure_dev_shielded_note_bundle() -> Result<ShieldedProverBundle, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(20260326);
    let descriptor = ShieldedBundleDescriptor {
        contract_name: "con_shielded_note_token",
        warning: "INSECURE DEV BUNDLE: deterministic setup seed exposes toxic waste and must never be used on a real network.",
        setup_mode: "insecure-dev",
        setup_ceremony: "",
        deposit_vk_id: "shielded-deposit-v3",
        transfer_vk_id: "shielded-transfer-v3",
        withdraw_vk_id: "shielded-withdraw-v3",
    };
    build_shielded_note_bundle_with_rng(&mut rng, &descriptor)
}

struct ShieldedCommandBundleDescriptor<'a> {
    contract_name: &'a str,
    warning: &'a str,
    setup_mode: &'a str,
    setup_ceremony: &'a str,
    deposit_vk_id: &'a str,
    command_vk_id: &'a str,
    withdraw_vk_id: &'a str,
}

fn build_shielded_command_bundle_with_rng(
    rng: &mut StdRng,
    descriptor: &ShieldedCommandBundleDescriptor<'_>,
) -> Result<ShieldedCommandProverBundle, Box<dyn Error>> {
    let note_descriptor = ShieldedBundleDescriptor {
        contract_name: descriptor.contract_name,
        warning: descriptor.warning,
        setup_mode: descriptor.setup_mode,
        setup_ceremony: descriptor.setup_ceremony,
        deposit_vk_id: descriptor.deposit_vk_id,
        transfer_vk_id: "shadow-transfer-unused",
        withdraw_vk_id: descriptor.withdraw_vk_id,
    };
    let note_bundle = build_shielded_note_bundle_with_rng(rng, &note_descriptor)?;
    let (command_pk, command_vk, _) =
        prove_circuit(rng, CommandCircuit::blank(), CommandCircuit::blank())?;

    Ok(ShieldedCommandProverBundle {
        circuit_family: SHIELDED_COMMAND_CIRCUIT_FAMILY.to_string(),
        warning: descriptor.warning.to_string(),
        setup_mode: descriptor.setup_mode.to_string(),
        setup_ceremony: descriptor.setup_ceremony.to_string(),
        contract_name: descriptor.contract_name.to_string(),
        tree_depth: SHIELDED_NOTE_TREE_DEPTH,
        leaf_capacity: SHIELDED_NOTE_TREE_LEAF_COUNT,
        max_inputs: SHIELDED_NOTE_MAX_INPUTS,
        max_outputs: SHIELDED_NOTE_MAX_OUTPUTS,
        deposit: ShieldedCircuitBundle {
            vk_id: descriptor.deposit_vk_id.to_string(),
            circuit_name: SHIELDED_COMMAND_DEPOSIT_CIRCUIT_NAME.to_string(),
            version: SHIELDED_COMMAND_CIRCUIT_VERSION.to_string(),
            vk_hex: note_bundle.deposit.vk_hex,
            pk_hex: note_bundle.deposit.pk_hex,
        },
        command: ShieldedCircuitBundle {
            vk_id: descriptor.command_vk_id.to_string(),
            circuit_name: SHIELDED_COMMAND_EXECUTE_CIRCUIT_NAME.to_string(),
            version: SHIELDED_COMMAND_CIRCUIT_VERSION.to_string(),
            vk_hex: serialize_hex(&command_vk)?,
            pk_hex: serialize_hex(&command_pk)?,
        },
        withdraw: ShieldedCircuitBundle {
            vk_id: descriptor.withdraw_vk_id.to_string(),
            circuit_name: SHIELDED_COMMAND_WITHDRAW_CIRCUIT_NAME.to_string(),
            version: SHIELDED_COMMAND_CIRCUIT_VERSION.to_string(),
            vk_hex: note_bundle.withdraw.vk_hex,
            pk_hex: note_bundle.withdraw.pk_hex,
        },
    })
}

pub fn build_random_shielded_command_bundle(
    contract_name: &str,
    vk_id_prefix: &str,
) -> Result<ShieldedCommandProverBundle, Box<dyn Error>> {
    if contract_name.is_empty() {
        return Err("contract_name must be non-empty".into());
    }
    if vk_id_prefix.is_empty() {
        return Err("vk_id_prefix must be non-empty".into());
    }

    let deposit_vk_id = format!("{vk_id_prefix}-deposit");
    let command_vk_id = format!("{vk_id_prefix}-command");
    let withdraw_vk_id = format!("{vk_id_prefix}-withdraw");
    let descriptor = ShieldedCommandBundleDescriptor {
        contract_name,
        warning: "SINGLE-PARTY RANDOM BUNDLE: generated from OS randomness for deployment use. This replaces the deterministic dev setup but is still not an MPC ceremony.",
        setup_mode: "single-party",
        setup_ceremony: "",
        deposit_vk_id: &deposit_vk_id,
        command_vk_id: &command_vk_id,
        withdraw_vk_id: &withdraw_vk_id,
    };

    let mut rng = StdRng::from_rng(OsRng)
        .map_err(|error| format!("failed to seed random setup rng: {error}"))?;
    build_shielded_command_bundle_with_rng(&mut rng, &descriptor)
}

pub fn build_insecure_dev_shielded_command_bundle(
) -> Result<ShieldedCommandProverBundle, Box<dyn Error>> {
    let mut rng = StdRng::seed_from_u64(20260403);
    let descriptor = ShieldedCommandBundleDescriptor {
        contract_name: "con_shielded_commands",
        warning: "INSECURE DEV BUNDLE: deterministic setup seed exposes toxic waste and must never be used on a real network.",
        setup_mode: "insecure-dev",
        setup_ceremony: "",
        deposit_vk_id: "shielded-command-deposit-v4",
        command_vk_id: "shielded-command-execute-v4",
        withdraw_vk_id: "shielded-command-withdraw-v4",
    };
    build_shielded_command_bundle_with_rng(&mut rng, &descriptor)
}

fn note_shadow_bundle_from_command(
    bundle: &ShieldedCommandProverBundle,
) -> ShieldedProverBundle {
    ShieldedProverBundle {
        circuit_family: SHIELDED_COMMAND_CIRCUIT_FAMILY.to_string(),
        warning: bundle.warning.clone(),
        setup_mode: bundle.setup_mode.clone(),
        setup_ceremony: bundle.setup_ceremony.clone(),
        contract_name: bundle.contract_name.clone(),
        tree_depth: bundle.tree_depth,
        leaf_capacity: bundle.leaf_capacity,
        max_inputs: bundle.max_inputs,
        max_outputs: bundle.max_outputs,
        deposit: bundle.deposit.clone(),
        transfer: bundle.deposit.clone(),
        withdraw: bundle.withdraw.clone(),
    }
}

pub fn prove_shielded_deposit(
    bundle: &ShieldedProverBundle,
    request: &ShieldedDepositRequest,
) -> Result<ShieldedProofResult, Box<dyn Error>> {
    if request.outputs.is_empty() || request.outputs.len() > SHIELDED_NOTE_MAX_OUTPUTS {
        return Err("invalid output count".into());
    }

    let asset_id = parse_field_hex(&request.asset_id)?;
    let old_root = parse_field_hex(&request.old_root)?;
    let append_state = parse_tree_state(&request.append_state)?;
    let (output_witnesses, output_commitments) =
        build_output_witnesses(asset_id, &request.outputs)?;
    let output_payload_hashes =
        parse_output_payload_hashes(&request.output_payload_hashes, request.outputs.len())?;
    let expected_new_root = append_commitments_to_state(&append_state, &output_commitments)?.root;
    let circuit = DepositCircuit {
        asset_id,
        old_root,
        amount: request.amount,
        output_count: request.outputs.len(),
        output_commitments: pad_fields(output_commitments.clone(), SHIELDED_NOTE_MAX_OUTPUTS),
        output_payload_hashes: pad_fields(
            output_payload_hashes.clone(),
            SHIELDED_NOTE_MAX_OUTPUTS,
        ),
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
        output_payload_hashes: output_payload_hashes
            .into_iter()
            .map(field_hex)
            .collect(),
    })
}

pub fn prove_shielded_transfer(
    bundle: &ShieldedProverBundle,
    request: &ShieldedTransferRequest,
) -> Result<ShieldedProofResult, Box<dyn Error>> {
    if request.inputs.is_empty() || request.inputs.len() > SHIELDED_NOTE_MAX_INPUTS {
        return Err("invalid input count".into());
    }
    if request.outputs.is_empty() || request.outputs.len() > SHIELDED_NOTE_MAX_OUTPUTS {
        return Err("invalid output count".into());
    }

    let asset_id = parse_field_hex(&request.asset_id)?;
    let old_root = parse_field_hex(&request.old_root)?;
    let append_state = parse_tree_state(&request.append_state)?;

    let mut input_witnesses = Vec::new();
    let mut input_nullifiers = Vec::new();
    for input in &request.inputs {
        let witness = input_witness_from_request(input)?;
        input_nullifiers.push(note_nullifier(asset_id, &witness.note));
        input_witnesses.push(witness);
    }
    while input_witnesses.len() < SHIELDED_NOTE_MAX_INPUTS {
        input_witnesses.push(blank_input_witness());
    }

    let (output_witnesses, output_commitments) =
        build_output_witnesses(asset_id, &request.outputs)?;
    let output_payload_hashes =
        parse_output_payload_hashes(&request.output_payload_hashes, request.outputs.len())?;
    let expected_new_root = append_commitments_to_state(&append_state, &output_commitments)?.root;
    let circuit = TransferCircuit {
        asset_id,
        old_root,
        input_count: request.inputs.len(),
        output_count: request.outputs.len(),
        input_nullifiers: pad_fields(input_nullifiers.clone(), SHIELDED_NOTE_MAX_INPUTS),
        output_commitments: pad_fields(output_commitments.clone(), SHIELDED_NOTE_MAX_OUTPUTS),
        output_payload_hashes: pad_fields(
            output_payload_hashes.clone(),
            SHIELDED_NOTE_MAX_OUTPUTS,
        ),
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
        output_payload_hashes: output_payload_hashes
            .into_iter()
            .map(field_hex)
            .collect(),
    })
}

pub fn prove_shielded_withdraw(
    bundle: &ShieldedProverBundle,
    request: &ShieldedWithdrawRequest,
) -> Result<ShieldedProofResult, Box<dyn Error>> {
    if request.inputs.is_empty() || request.inputs.len() > SHIELDED_NOTE_MAX_INPUTS {
        return Err("invalid input count".into());
    }
    if request.outputs.len() > SHIELDED_NOTE_MAX_OUTPUTS {
        return Err("invalid output count".into());
    }

    let asset_id = parse_field_hex(&request.asset_id)?;
    let old_root = parse_field_hex(&request.old_root)?;
    let append_state = parse_tree_state(&request.append_state)?;

    let mut input_witnesses = Vec::new();
    let mut input_nullifiers = Vec::new();
    for input in &request.inputs {
        let witness = input_witness_from_request(input)?;
        input_nullifiers.push(note_nullifier(asset_id, &witness.note));
        input_witnesses.push(witness);
    }
    while input_witnesses.len() < SHIELDED_NOTE_MAX_INPUTS {
        input_witnesses.push(blank_input_witness());
    }

    let (output_witnesses, output_commitments) =
        build_output_witnesses(asset_id, &request.outputs)?;
    let output_payload_hashes =
        parse_output_payload_hashes(&request.output_payload_hashes, request.outputs.len())?;
    let expected_new_root = append_commitments_to_state(&append_state, &output_commitments)?.root;
    let circuit = WithdrawCircuit {
        asset_id,
        old_root,
        amount: request.amount,
        recipient_digest: recipient_digest(&request.recipient),
        input_count: request.inputs.len(),
        output_count: request.outputs.len(),
        input_nullifiers: pad_fields(input_nullifiers.clone(), SHIELDED_NOTE_MAX_INPUTS),
        output_commitments: pad_fields(output_commitments.clone(), SHIELDED_NOTE_MAX_OUTPUTS),
        output_payload_hashes: pad_fields(
            output_payload_hashes.clone(),
            SHIELDED_NOTE_MAX_OUTPUTS,
        ),
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
        output_payload_hashes: output_payload_hashes
            .into_iter()
            .map(field_hex)
            .collect(),
    })
}

pub fn prove_shielded_command_deposit(
    bundle: &ShieldedCommandProverBundle,
    request: &ShieldedDepositRequest,
) -> Result<ShieldedProofResult, Box<dyn Error>> {
    prove_shielded_deposit(&note_shadow_bundle_from_command(bundle), request)
}

pub fn prove_shielded_command_execute(
    bundle: &ShieldedCommandProverBundle,
    request: &ShieldedCommandRequest,
) -> Result<ShieldedCommandProofResult, Box<dyn Error>> {
    if request.inputs.is_empty() || request.inputs.len() > SHIELDED_NOTE_MAX_INPUTS {
        return Err("invalid input count".into());
    }
    if request.outputs.len() > SHIELDED_NOTE_MAX_OUTPUTS {
        return Err("invalid output count".into());
    }

    let asset_id = parse_field_hex(&request.asset_id)?;
    let old_root = parse_field_hex(&request.old_root)?;
    let append_state = parse_tree_state(&request.append_state)?;
    let mut input_witnesses = Vec::new();
    let mut input_nullifiers = Vec::new();
    for input in &request.inputs {
        let witness = input_witness_from_request(input)?;
        input_nullifiers.push(note_nullifier(asset_id, &witness.note));
        input_witnesses.push(witness);
    }
    while input_witnesses.len() < SHIELDED_NOTE_MAX_INPUTS {
        input_witnesses.push(blank_input_witness());
    }

    let padded_input_nullifiers = pad_fields(input_nullifiers.clone(), SHIELDED_NOTE_MAX_INPUTS);
    let command_binding_value = parse_field_hex(&request.command_binding)?;
    let execution_tag = command_execution_tag(
        command_nullifier_digest(&padded_input_nullifiers),
        command_binding_value,
    );
    let (output_witnesses, output_commitments) =
        build_output_witnesses(asset_id, &request.outputs)?;
    let output_payload_hashes =
        parse_output_payload_hashes(&request.output_payload_hashes, request.outputs.len())?;
    let expected_new_root = append_commitments_to_state(&append_state, &output_commitments)?.root;
    let circuit = CommandCircuit {
        asset_id,
        old_root,
        command_binding: command_binding_value,
        execution_tag,
        fee: request.fee,
        public_amount: request.public_amount,
        input_count: request.inputs.len(),
        input_nullifiers: padded_input_nullifiers,
        output_count: request.outputs.len(),
        output_commitments: pad_fields(output_commitments.clone(), SHIELDED_NOTE_MAX_OUTPUTS),
        output_payload_hashes: pad_fields(
            output_payload_hashes.clone(),
            SHIELDED_NOTE_MAX_OUTPUTS,
        ),
        inputs: input_witnesses,
        outputs: output_witnesses,
    };
    let proof = prove_with_pk(&bundle.command.pk_hex, circuit.clone())?;
    Ok(ShieldedCommandProofResult {
        proof_hex: serialize_hex(&proof)?,
        old_root: field_hex(old_root),
        expected_new_root: field_hex(expected_new_root),
        public_inputs: circuit.public_inputs().into_iter().map(field_hex).collect(),
        command_binding: field_hex(command_binding_value),
        execution_tag: field_hex(execution_tag),
        public_amount: request.public_amount,
        input_nullifiers: input_nullifiers.into_iter().map(field_hex).collect(),
        output_commitments: output_commitments.into_iter().map(field_hex).collect(),
        output_payload_hashes: output_payload_hashes
            .into_iter()
            .map(field_hex)
            .collect(),
    })
}

pub fn prove_shielded_command_withdraw(
    bundle: &ShieldedCommandProverBundle,
    request: &ShieldedWithdrawRequest,
) -> Result<ShieldedProofResult, Box<dyn Error>> {
    prove_shielded_withdraw(&note_shadow_bundle_from_command(bundle), request)
}

pub fn build_shielded_command_fixture() -> Result<ShieldedCommandFixture, Box<dyn Error>> {
    let contract_name = "con_shielded_commands";
    let asset_id = asset_id_for_contract(contract_name);
    let zero_state = empty_frontier_state();

    let alice_secret = hash_to_field("shielded-command:alice");
    let note_a1 = NoteWitness {
        owner_secret: alice_secret,
        amount: 70,
        rho: hash_to_field("shielded-command:a1:rho"),
        blind: hash_to_field("shielded-command:a1:blind"),
    };
    let note_a2 = NoteWitness {
        owner_secret: alice_secret,
        amount: 50,
        rho: hash_to_field("shielded-command:a2:rho"),
        blind: hash_to_field("shielded-command:a2:blind"),
    };
    let note_a3 = NoteWitness {
        owner_secret: alice_secret,
        amount: 30,
        rho: hash_to_field("shielded-command:a3:rho"),
        blind: hash_to_field("shielded-command:a3:blind"),
    };

    let commitment_a1 = note_commitment(asset_id, &note_a1);
    let commitment_a2 = note_commitment(asset_id, &note_a2);
    let nullifier_a1 = note_nullifier(asset_id, &note_a1);
    let nullifier_a2 = note_nullifier(asset_id, &note_a2);

    let deposit_commitments = vec![field_hex(commitment_a1)];
    let command_commitments = vec![field_hex(commitment_a1), field_hex(commitment_a2)];
    let state1 = tree_state_from_commitments(&deposit_commitments)?;
    let state2 = tree_state_from_commitments(&command_commitments)?;
    let leaves1 = leaf_fields_from_commitments(&deposit_commitments)?;
    let leaves2 = leaf_fields_from_commitments(&command_commitments)?;

    let target_contract = "con_shielded_target";
    let payload = serde_json::json!({
        "increment": 4,
        "label": "hidden",
    });
    let relayer = "relayer";
    let chain_id = "xian-local-1";
    let expires_at = "2026-01-01 12:30:00";

    let target_digest = contract_sha3_to_field(target_contract);
    let payload_digest = contract_sha3_to_field(&canonicalize_command_payload(&payload)?);
    let relayer_digest = contract_sha3_to_field(relayer);
    let expiry_digest = contract_sha3_to_field(expires_at);
    let chain_digest = contract_sha3_to_field(chain_id);
    let entrypoint_digest = contract_sha3_to_field("interact");
    let version_digest = contract_sha3_to_field("shielded-command-v4");
    let padded_input_nullifiers =
        pad_fields(vec![nullifier_a1], SHIELDED_NOTE_MAX_INPUTS);
    let command_binding_value = command_binding(
        command_nullifier_digest(&padded_input_nullifiers),
        target_digest,
        payload_digest,
        relayer_digest,
        expiry_digest,
        chain_digest,
        entrypoint_digest,
        version_digest,
        7,
        13,
    );
    let execution_tag = command_execution_tag(
        command_nullifier_digest(&padded_input_nullifiers),
        command_binding_value,
    );

    let bundle = build_insecure_dev_shielded_command_bundle()?;

    let deposit = prove_shielded_command_deposit(
        &bundle,
        &ShieldedDepositRequest {
            asset_id: field_hex(asset_id),
            old_root: field_hex(zero_state.root),
            append_state: frontier_state_to_public(&zero_state),
            amount: 70,
            outputs: vec![ShieldedOutputRequest {
                owner_public: field_hex(owner_public(note_a1.owner_secret)),
                amount: note_a1.amount,
                rho: field_hex(note_a1.rho),
                blind: field_hex(note_a1.blind),
            }],
            output_payload_hashes: vec![field_hex(Fr::zero())],
        },
    )?;

    let command = prove_shielded_command_execute(
        &bundle,
        &ShieldedCommandRequest {
            asset_id: field_hex(asset_id),
            old_root: field_hex(state1.root),
            append_state: frontier_state_to_public(&state1),
            fee: 7,
            public_amount: 13,
            inputs: vec![ShieldedInputRequest {
                owner_secret: field_hex(note_a1.owner_secret),
                amount: note_a1.amount,
                rho: field_hex(note_a1.rho),
                blind: field_hex(note_a1.blind),
                leaf_index: 0,
                merkle_path: auth_path_from_leaves(&leaves1, 0)?
                    .into_iter()
                    .map(field_hex)
                    .collect(),
            }],
            outputs: vec![ShieldedOutputRequest {
                owner_public: field_hex(owner_public(note_a2.owner_secret)),
                amount: note_a2.amount,
                rho: field_hex(note_a2.rho),
                blind: field_hex(note_a2.blind),
            }],
            command_binding: field_hex(command_binding_value),
            output_payload_hashes: vec![field_hex(Fr::zero())],
        },
    )?;

    let withdraw = prove_shielded_command_withdraw(
        &bundle,
        &ShieldedWithdrawRequest {
            asset_id: field_hex(asset_id),
            old_root: field_hex(state2.root),
            append_state: frontier_state_to_public(&state2),
            amount: 20,
            recipient: "bob".to_string(),
            inputs: vec![ShieldedInputRequest {
                owner_secret: field_hex(note_a2.owner_secret),
                amount: note_a2.amount,
                rho: field_hex(note_a2.rho),
                blind: field_hex(note_a2.blind),
                leaf_index: 1,
                merkle_path: auth_path_from_leaves(&leaves2, 1)?
                    .into_iter()
                    .map(field_hex)
                    .collect(),
            }],
            outputs: vec![ShieldedOutputRequest {
                owner_public: field_hex(owner_public(note_a3.owner_secret)),
                amount: note_a3.amount,
                rho: field_hex(note_a3.rho),
                blind: field_hex(note_a3.blind),
            }],
            output_payload_hashes: vec![field_hex(Fr::zero())],
        },
    )?;

    Ok(ShieldedCommandFixture {
        contract_name: contract_name.to_string(),
        asset_id: field_hex(asset_id),
        zero_root: field_hex(zero_state.root),
        tree_depth: SHIELDED_NOTE_TREE_DEPTH,
        leaf_capacity: SHIELDED_NOTE_TREE_LEAF_COUNT,
        max_inputs: SHIELDED_NOTE_MAX_INPUTS,
        max_outputs: SHIELDED_NOTE_MAX_OUTPUTS,
        verifying_keys: vec![
            ShieldedVkFixture {
                vk_id: bundle.deposit.vk_id.clone(),
                circuit_name: bundle.deposit.circuit_name.clone(),
                version: bundle.deposit.version.clone(),
                vk_hex: bundle.deposit.vk_hex.clone(),
            },
            ShieldedVkFixture {
                vk_id: bundle.command.vk_id.clone(),
                circuit_name: bundle.command.circuit_name.clone(),
                version: bundle.command.version.clone(),
                vk_hex: bundle.command.vk_hex.clone(),
            },
            ShieldedVkFixture {
                vk_id: bundle.withdraw.vk_id.clone(),
                circuit_name: bundle.withdraw.circuit_name.clone(),
                version: bundle.withdraw.version.clone(),
                vk_hex: bundle.withdraw.vk_hex.clone(),
            },
        ],
        deposit: ShieldedActionFixture {
            proof_hex: deposit.proof_hex,
            old_root: deposit.old_root,
            expected_new_root: deposit.expected_new_root,
            public_inputs: deposit.public_inputs,
            input_count: 0,
            output_count: 1,
            amount: Some(70),
            recipient: None,
            input_nullifiers: vec![],
            output_commitments: deposit.output_commitments,
            output_payload_hashes: deposit.output_payload_hashes,
        },
        command: ShieldedCommandActionFixture {
            proof_hex: command.proof_hex,
            old_root: command.old_root,
            expected_new_root: command.expected_new_root,
            public_inputs: command.public_inputs,
            fee: 7,
            public_amount: 13,
            command_binding: field_hex(command_binding_value),
            execution_tag: field_hex(execution_tag),
            input_count: 1,
            input_nullifiers: vec![field_hex(nullifier_a1)],
            output_count: 1,
            output_commitments: command.output_commitments,
            output_payload_hashes: command.output_payload_hashes,
            target_contract: target_contract.to_string(),
            payload,
            relayer: relayer.to_string(),
            expires_at: expires_at.to_string(),
        },
        withdraw: ShieldedActionFixture {
            proof_hex: withdraw.proof_hex,
            old_root: withdraw.old_root,
            expected_new_root: withdraw.expected_new_root,
            public_inputs: withdraw.public_inputs,
            input_count: 1,
            output_count: 1,
            amount: Some(20),
            recipient: Some("bob".to_string()),
            input_nullifiers: vec![field_hex(nullifier_a2)],
            output_commitments: withdraw.output_commitments,
            output_payload_hashes: withdraw.output_payload_hashes,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::verify_groth16_bn254;

    #[test]
    fn recipient_digest_matches_contract_hashing_for_hex_like_values() {
        let recipient = "ab".repeat(32);
        let expected = {
            let decoded = hex::decode(&recipient).expect("hex recipient");
            let digest = Sha3_256::digest(&decoded);
            field_hex(Fr::from_be_bytes_mod_order(&digest))
        };

        assert_eq!(shielded_note_recipient_digest_hex(&recipient), expected);
    }

    #[test]
    fn random_bundle_requires_non_empty_names() {
        assert!(build_random_shielded_note_bundle("", "bundle-id").is_err());
        assert!(build_random_shielded_note_bundle("con_private_usd", "").is_err());
        assert!(build_random_shielded_command_bundle("", "bundle-id").is_err());
        assert!(build_random_shielded_command_bundle("con_private_usd", "").is_err());
    }

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

    #[test]
    fn shielded_command_fixture_vectors_verify() {
        let fixture = build_shielded_command_fixture().expect("fixture should build");

        let deposit_vk = &fixture.verifying_keys[0].vk_hex;
        let command_vk = &fixture.verifying_keys[1].vk_hex;
        let withdraw_vk = &fixture.verifying_keys[2].vk_hex;

        assert!(verify_groth16_bn254(
            deposit_vk,
            &fixture.deposit.proof_hex,
            &fixture.deposit.public_inputs,
        )
        .expect("deposit verify should succeed"));
        assert!(verify_groth16_bn254(
            command_vk,
            &fixture.command.proof_hex,
            &fixture.command.public_inputs,
        )
        .expect("command verify should succeed"));
        assert!(verify_groth16_bn254(
            withdraw_vk,
            &fixture.withdraw.proof_hex,
            &fixture.withdraw.public_inputs,
        )
        .expect("withdraw verify should succeed"));
    }
}
