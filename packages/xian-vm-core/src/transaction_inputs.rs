//! A block transaction's execution inputs, read from its wire bytes.
//!
//! The node admitted the bytes (`transaction_admission`); this reads what
//! execution needs from them, as the Python node built it per transaction:
//! the call (`payload`), the keyword arguments as the VM receives them
//! (`coerce_call_kwargs(decode_wire_numbers(kwargs))`, i.e. the stored-value
//! reader over their canonical JSON), the transaction context
//! (`TxProcessor.get_environment` and `_vm_context`: `__input_hash` is
//! SHA3-256 of the block nanoseconds followed by the signature, `now` the
//! block time at microsecond precision) and the canonical size
//! (`canonical_transaction_size_bytes`: the document's JSON with every
//! character outside `' '..='~'` escaped).
//!
//! `None` means bytes admission refuses (the node runs only admitted
//! transactions).
use crate::stored_value::decode_stored_value;
use crate::{VmDateTime, VmExecutionContext, VmValue};
use chrono::{DateTime, Datelike, Timelike};
use num_bigint::BigInt;
use serde_json::{Map, Value};
use sha3::{Digest, Sha3_256};
use xian_fastpath_core::{canonical_json, decode_transaction};

const NANOS_PER_SECOND: i64 = 1_000_000_000;

/// One transaction's inputs, as the Python node converted them.
pub(crate) struct PreparedTx {
    pub(crate) sender: String,
    pub(crate) contract: String,
    pub(crate) function: String,
    pub(crate) kwargs: Vec<(String, VmValue)>,
    /// signer, caller, this, entry, submission name and block context; the
    /// owner is read by the executor.
    pub(crate) context: VmExecutionContext,
    pub(crate) chi_budget: BigInt,
    pub(crate) size_bytes: usize,
}

/// What every transaction of a block shares (`current_block_meta`).
#[derive(Clone, Debug)]
pub(crate) struct BlockMeta {
    /// The block time in nanoseconds since the epoch.
    pub(crate) nanos: i64,
    pub(crate) height: VmValue,
    pub(crate) hash: VmValue,
    pub(crate) chain_id: VmValue,
}

/// The transaction `raw` as the block executor runs it, or `None` for bytes
/// admission refuses.
pub(crate) fn prepared_tx(raw: &[u8], meta: &BlockMeta) -> Option<PreparedTx> {
    let decoded = decode_transaction(raw).ok()?;
    let (payload, signature) = sections(&decoded.document)?;
    let call = Call::read(payload)?;
    let context = context(meta, &call, signature)?;
    Some(PreparedTx {
        size_bytes: ascii_json_size(&decoded.text),
        sender: call.sender,
        contract: call.contract,
        function: call.function,
        kwargs: call.kwargs,
        chi_budget: call.chi_budget,
        context,
    })
}

/// The payload and signature of a document holding exactly the two.
fn sections(document: &Value) -> Option<(&Map<String, Value>, &str)> {
    let document = document
        .as_object()
        .filter(|document| document.len() == 2)?;
    let payload = document.get("payload")?.as_object()?;
    let signature = document.get("metadata")?.get("signature")?.as_str()?;
    Some((payload, signature))
}

/// The call a payload makes.
struct Call {
    sender: String,
    contract: String,
    function: String,
    kwargs: Vec<(String, VmValue)>,
    chi_budget: BigInt,
}

impl Call {
    fn read(payload: &Map<String, Value>) -> Option<Self> {
        let text = |key: &str| payload.get(key)?.as_str().map(str::to_owned);
        Some(Self {
            sender: text("sender")?,
            contract: text("contract")?,
            function: text("function")?,
            kwargs: call_kwargs(payload.get("kwargs")?)?,
            chi_budget: integer(payload.get("chi_supplied")?)?,
        })
    }
}

/// A JSON integer (the budget of a node-built transaction may be any).
fn integer(value: &Value) -> Option<BigInt> {
    let number = value.as_number()?;
    number
        .as_i64()
        .map(BigInt::from)
        .or_else(|| number.as_u64().map(BigInt::from))
}

/// The keyword arguments as the VM receives them, in their JSON key order.
fn call_kwargs(kwargs: &Value) -> Option<Vec<(String, VmValue)>> {
    let json = canonical_json(kwargs).ok()?;
    let VmValue::Dict(entries) = decode_stored_value(json.as_bytes()).ok()? else {
        return None;
    };
    entries
        .into_iter()
        .map(|(key, value)| match key {
            VmValue::String(key) => Some((key, value)),
            _ => None,
        })
        .collect()
}

fn context(meta: &BlockMeta, call: &Call, signature: &str) -> Option<VmExecutionContext> {
    Some(VmExecutionContext {
        this: Some(call.contract.clone()),
        caller: Some(call.sender.clone()),
        signer: Some(call.sender.clone()),
        owner: None,
        entry: Some((call.contract.clone(), call.function.clone())),
        submission_name: submission_name(&call.contract, &call.kwargs),
        now: block_time(meta.nanos)?,
        block_num: meta.height.clone(),
        block_hash: meta.hash.clone(),
        chain_id: meta.chain_id.clone(),
        input_hash: VmValue::String(input_hash(meta.nanos, signature)),
    })
}

/// The `name` argument of a call to the submission contract, when it is
/// text (revision 14: a name of another type is no submission name; the
/// deployment then refuses it).
fn submission_name(contract: &str, kwargs: &[(String, VmValue)]) -> Option<String> {
    if contract != "submission" {
        return None;
    }
    match kwargs.iter().find(|(key, _)| key == "name") {
        Some((_, VmValue::String(name))) => Some(name.clone()),
        _ => None,
    }
}

/// `nanoseconds_to_utc_datetime`: whole seconds in UTC, microseconds
/// truncated.
fn block_time(nanos: i64) -> Option<VmValue> {
    let seconds = nanos.div_euclid(NANOS_PER_SECOND);
    let micros = nanos.rem_euclid(NANOS_PER_SECOND) / 1_000;
    let time = DateTime::from_timestamp(seconds, 0)?.naive_utc();
    VmDateTime::new(
        i64::from(time.year()),
        i64::from(time.month()),
        i64::from(time.day()),
        i64::from(time.hour()),
        i64::from(time.minute()),
        i64::from(time.second()),
        micros,
    )
    .ok()
    .map(VmValue::DateTime)
}

/// `TxProcessor.get_timestamp_hash_from_tx`.
fn input_hash(nanos: i64, signature: &str) -> String {
    hex::encode(Sha3_256::digest(format!("{nanos}{signature}").as_bytes()))
}

/// The length of the canonical text with Python's ASCII escaping: a
/// character outside `' '..='~'` takes `\uXXXX` (two of them beyond the
/// basic plane). The canonical text has no raw control characters.
fn ascii_json_size(text: &str) -> usize {
    text.chars()
        .map(|character| match u32::from(character) {
            0..=0x7e => 1,
            0x7f..=0xffff => 6,
            _ => 12,
        })
        .sum()
}

#[cfg(test)]
mod tests;
