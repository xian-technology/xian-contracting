//! The shielded-note helpers of the zk bridge: each checks its arguments as
//! the Python function does, then calls the `xian-zk` helper the Python
//! binding calls. A helper's own refusal reaches the VM as the binding's
//! `ValueError`.
use super::checks::{
    absent_payload, assertion, field_list, field_values, hex, native_u64, non_empty_text,
    non_negative, py, value_error, Py, MAX_PAYLOAD_HEX_CHARS, MAX_PUBLIC_INPUTS,
};
use super::Served;
use crate::{VmExecutionError, VmValue};
use num_bigint::BigInt;
use num_traits::Signed;
use std::error::Error;
use xian_zk::{
    shielded_command_binding_hex, shielded_command_execution_tag_hex,
    shielded_command_nullifier_digest_hex, shielded_command_public_inputs_hex,
    shielded_deposit_public_inputs_hex, shielded_note_append_tree_state,
    shielded_output_payload_hash_hex, shielded_output_payload_hash_hexes,
    shielded_transfer_public_inputs_hex, shielded_withdraw_public_inputs_hex,
};

/// Most inputs and outputs a shielded statement has.
const MAX_NOTES: usize = 4;
/// Most levels a note tree's frontier may claim.
const MAX_TREE_LEVELS: usize = 64;
/// `shielded_output_payload_hash` of an absent payload.
const ZERO_FIELD: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const NOT_A_FEE: &str = "fee must be a non-negative integer!";
const NOT_A_PUBLIC_AMOUNT: &str = "public_amount must be a non-negative integer!";
const NOT_AN_AMOUNT: &str = "amount must be a non-negative integer!";
const NO_CONTRACT_NAME: &str = "contract_name must be a non-empty string!";

fn text(value: String) -> VmValue {
    VmValue::String(value)
}

fn texts(values: Vec<String>) -> VmValue {
    VmValue::List(values.into_iter().map(text).collect())
}

fn native<T>(result: Result<T, Box<dyn Error>>) -> Result<T, VmExecutionError> {
    result.map_err(|error| value_error(error.to_string()))
}

/// `shielded_note_append_commitments(note_count, filled_subtrees,
/// commitments)`: the tree state after appending, as the decoded JSON.
pub(super) fn append_commitments(args: &[VmValue]) -> Served {
    let Py::Int(note_count) = py(&args[0]) else {
        return Err(assertion("note_count must be an integer!"));
    };
    if note_count.is_negative() {
        return Err(assertion("note_count must be non-negative!"));
    }
    let filled = field_values("filled_subtrees", &args[1], 1, MAX_TREE_LEVELS)?;
    let commitments = field_values("commitments", &args[2], 1, MAX_PUBLIC_INPUTS)?;
    let note_count = usize::try_from(native_u64(&note_count)?)
        .map_err(|_| VmExecutionError::new("OverflowError: int too big to convert"))?;
    let state = native(shielded_note_append_tree_state(
        note_count,
        &filled,
        &commitments,
    ))?;
    Ok(VmValue::Dict(vec![
        (text("root".to_owned()), text(state.root)),
        (
            text("note_count".to_owned()),
            VmValue::Int(state.note_count.into()),
        ),
        (
            text("filled_subtrees".to_owned()),
            texts(state.filled_subtrees),
        ),
    ]))
}

/// `shielded_command_nullifier_digest(input_nullifiers)`.
pub(super) fn nullifier_digest(args: &[VmValue]) -> Served {
    let nullifiers = field_values("input_nullifiers", &args[0], 1, MAX_PUBLIC_INPUTS)?;
    native(shielded_command_nullifier_digest_hex(&nullifiers)).map(text)
}

/// `shielded_command_binding(eight digests, fee, public_amount)`.
pub(super) fn command_binding(args: &[VmValue]) -> Served {
    let digests = field_list("binding_fields", &args[..8], 8, 8)?;
    let (fee, public_amount) = native_fees(&fees(&args[8], &args[9])?)?;
    native(shielded_command_binding_hex(
        &digests[0],
        &digests[1],
        &digests[2],
        &digests[3],
        &digests[4],
        &digests[5],
        &digests[6],
        &digests[7],
        fee,
        public_amount,
    ))
    .map(text)
}

/// `shielded_command_execution_tag(nullifier_digest, command_binding)`.
pub(super) fn execution_tag(args: &[VmValue]) -> Served {
    let fields = field_list("execution_tag_fields", args, 2, 2)?;
    native(shielded_command_execution_tag_hex(&fields[0], &fields[1])).map(text)
}

/// `shielded_output_payload_hash(payload_hex)`: zero for no payload.
pub(super) fn payload_hash(args: &[VmValue]) -> Served {
    if absent_payload(&args[0]) {
        return Ok(text(ZERO_FIELD.to_owned()));
    }
    let payload = hex("payload_hex", &args[0], MAX_PAYLOAD_HEX_CHARS)?;
    Ok(text(shielded_output_payload_hash_hex(payload)))
}

/// `shielded_output_payload_hashes(payload_hexes)`: an absent payload is
/// passed as "" (its hash is zero). The Python function's check of the
/// native result always passes: every hash is a field element.
pub(super) fn payload_hashes(args: &[VmValue]) -> Served {
    let Py::List(payloads) = py(&args[0]) else {
        return Err(assertion("payload_hexes must be a list!"));
    };
    let mut normalized = Vec::with_capacity(payloads.len());
    for (index, payload) in payloads.iter().enumerate() {
        if absent_payload(payload) {
            normalized.push(String::new());
            continue;
        }
        let name = format!("payload_hexes[{index}]");
        normalized.push(hex(&name, payload, MAX_PAYLOAD_HEX_CHARS)?.to_owned());
    }
    Ok(texts(shielded_output_payload_hash_hexes(&normalized)))
}

/// The output commitments and their payload hashes, `outputs_from` or more
/// of them and at most four, as many hashes as commitments.
fn outputs(
    commitments: &VmValue,
    payload_hashes: &VmValue,
    outputs_from: usize,
) -> Result<(Vec<String>, Vec<String>), VmExecutionError> {
    let commitments = field_values("commitments", commitments, outputs_from, MAX_NOTES)?;
    let hashes = field_values(
        "payload_hashes",
        payload_hashes,
        commitments.len(),
        MAX_NOTES,
    )?;
    if hashes.len() != commitments.len() {
        return Err(assertion("payload_hashes length must match commitments!"));
    }
    Ok((commitments, hashes))
}

/// A statement's contract name and old root (its first two arguments).
fn statement(args: &[VmValue]) -> Result<(&str, &str), VmExecutionError> {
    let contract = non_empty_text(&args[0], NO_CONTRACT_NAME)?;
    Ok((contract, hex("old_root", &args[1], 66)?))
}

/// A command's fee and public amount, checked.
fn fees(fee: &VmValue, public_amount: &VmValue) -> Result<(BigInt, BigInt), VmExecutionError> {
    Ok((
        non_negative(fee, NOT_A_FEE)?,
        non_negative(public_amount, NOT_A_PUBLIC_AMOUNT)?,
    ))
}

/// The fee and public amount as the native helper takes them.
fn native_fees((fee, public_amount): &(BigInt, BigInt)) -> Result<(u64, u64), VmExecutionError> {
    Ok((native_u64(fee)?, native_u64(public_amount)?))
}

fn input_nullifiers(value: &VmValue) -> Result<Vec<String>, VmExecutionError> {
    field_values("input_nullifiers", value, 1, MAX_NOTES)
}

/// `shielded_deposit_public_inputs(contract_name, old_root, amount,
/// commitments, payload_hashes)`.
pub(super) fn deposit_public_inputs(args: &[VmValue]) -> Served {
    let contract = non_empty_text(&args[0], NO_CONTRACT_NAME)?;
    let amount = non_negative(&args[2], NOT_AN_AMOUNT)?;
    let (commitments, hashes) = outputs(&args[3], &args[4], 1)?;
    let old_root = hex("old_root", &args[1], 66)?;
    let amount = native_u64(&amount)?;
    native(shielded_deposit_public_inputs_hex(
        contract,
        old_root,
        amount,
        &commitments,
        &hashes,
    ))
    .map(texts)
}

/// `shielded_transfer_public_inputs(contract_name, old_root,
/// input_nullifiers, commitments, payload_hashes)`.
pub(super) fn transfer_public_inputs(args: &[VmValue]) -> Served {
    let (contract, old_root) = statement(args)?;
    let nullifiers = input_nullifiers(&args[2])?;
    let (commitments, hashes) = outputs(&args[3], &args[4], 1)?;
    native(shielded_transfer_public_inputs_hex(
        contract,
        old_root,
        &nullifiers,
        &commitments,
        &hashes,
    ))
    .map(texts)
}

/// `shielded_withdraw_public_inputs(contract_name, old_root, amount,
/// recipient, input_nullifiers, commitments, payload_hashes)`.
pub(super) fn withdraw_public_inputs(args: &[VmValue]) -> Served {
    let contract = non_empty_text(&args[0], NO_CONTRACT_NAME)?;
    let amount = non_negative(&args[2], NOT_AN_AMOUNT)?;
    let recipient = non_empty_text(&args[3], "recipient must be a non-empty string!")?;
    let old_root = hex("old_root", &args[1], 66)?;
    let nullifiers = input_nullifiers(&args[4])?;
    let (commitments, hashes) = outputs(&args[5], &args[6], 0)?;
    let amount = native_u64(&amount)?;
    native(shielded_withdraw_public_inputs_hex(
        contract,
        old_root,
        amount,
        recipient,
        &nullifiers,
        &commitments,
        &hashes,
    ))
    .map(texts)
}

/// `shielded_command_public_inputs(contract_name, old_root,
/// command_binding, execution_tag, fee, public_amount, input_nullifiers,
/// commitments, payload_hashes)`.
pub(super) fn command_public_inputs(args: &[VmValue]) -> Served {
    let (contract, old_root) = statement(args)?;
    let fields = field_list("command_public_fields", &args[2..4], 2, 2)?;
    let fees = fees(&args[4], &args[5])?;
    let nullifiers = input_nullifiers(&args[6])?;
    let (commitments, hashes) = outputs(&args[7], &args[8], 0)?;
    let (fee, public_amount) = native_fees(&fees)?;
    native(shielded_command_public_inputs_hex(
        contract,
        old_root,
        &fields[0],
        &fields[1],
        fee,
        public_amount,
        &nullifiers,
        &commitments,
        &hashes,
    ))
    .map(texts)
}
