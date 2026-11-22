//! ABCI receipt bytes for a native transaction outcome.
use crate::block_executor::{event_value, TxOutcome};
use crate::stored_value_encoder::{write_scalar, write_string};
use crate::tx_rewards::{Credits, RewardRecord, TxRewards};
use crate::{VmExecutionError, VmValue};

pub(crate) fn encode_receipt(
    hash: &str,
    outcome: &TxOutcome,
    failure: Option<&str>,
) -> Result<Vec<u8>, VmExecutionError> {
    let mut out = String::new();
    out.push_str("{\"chi_used\":");
    value(&mut out, &VmValue::Int(outcome.chi_used.clone()))?;
    out.push_str(",\"events\":");
    array(&mut out, &outcome.events, |out, event| {
        value(out, &event_value(event))
    })?;
    out.push_str(",\"hash\":");
    write_string(&mut out, hash);
    out.push_str(",\"result\":");
    if outcome.status == 0 {
        value(&mut out, &outcome.result)?;
    } else if let Some(failure) = failure {
        write_string(&mut out, failure);
    } else {
        out.push_str("null");
    }
    out.push_str(",\"reward_records\":");
    let records = outcome
        .rewards
        .as_ref()
        .map_or(&[][..], |rewards| rewards.records.as_slice());
    if records.is_empty() {
        out.push_str("null");
    } else {
        array(&mut out, records, reward_record)?;
    }
    out.push_str(",\"rewards\":");
    rewards(&mut out, outcome.rewards.as_ref())?;
    out.push_str(",\"state\":");
    array(&mut out, &outcome.writes, |out, (key, item)| {
        out.push_str("{\"key\":");
        write_string(out, key);
        out.push_str(",\"value\":");
        value(out, item)?;
        out.push('}');
        Ok(())
    })?;
    out.push_str(",\"status\":");
    out.push_str(&outcome.status.to_string());
    out.push('}');
    Ok(out.into_bytes())
}

fn value(out: &mut String, item: &VmValue) -> Result<(), VmExecutionError> {
    match item {
        VmValue::Reference(reference) => reference.with_value(|item| value(out, item))?,
        VmValue::Bytes(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => write_string(out, text),
            Err(_) => write_string(out, &bytes_repr(bytes)),
        },
        VmValue::DateTime(time) => write_string(out, &time.to_string()),
        VmValue::List(items) | VmValue::Tuple(items) => array(out, items, value)?,
        VmValue::Dict(items) => {
            let mut entries = Vec::with_capacity(items.len());
            for (key, item) in items {
                let VmValue::String(key) = key else {
                    return Err(VmExecutionError::new("receipt keys must be strings"));
                };
                entries.push((key.as_str(), item));
            }
            object(out, entries, value)?;
        }
        VmValue::ContractHandle(handle) => write_string(out, &handle.module),
        VmValue::TypeMarker(name) => write_string(out, name),
        _ => write_scalar(out, item)?,
    }
    Ok(())
}

fn bytes_repr(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let quote = if bytes.contains(&b'\'') && !bytes.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut repr = String::from("b");
    repr.push(char::from(quote));
    for &byte in bytes {
        match byte {
            b'\\' => repr.push_str("\\\\"),
            b'\t' => repr.push_str("\\t"),
            b'\n' => repr.push_str("\\n"),
            b'\r' => repr.push_str("\\r"),
            b if b == quote => {
                repr.push('\\');
                repr.push(char::from(b));
            }
            0x20..=0x7e => repr.push(char::from(byte)),
            _ => write!(repr, "\\x{byte:02x}").expect("writing to a String succeeds"),
        }
    }
    repr.push(char::from(quote));
    repr
}

fn rewards(out: &mut String, rewards: Option<&TxRewards>) -> Result<(), VmExecutionError> {
    if let Some(buckets) = rewards.and_then(|reward| reward.rewards.as_ref()) {
        object(
            out,
            buckets
                .iter()
                .map(|(kind, credits)| (kind.name(), credits))
                .collect(),
            credits,
        )
    } else {
        out.push_str("null");
        Ok(())
    }
}

fn credits(out: &mut String, credits: &Credits) -> Result<(), VmExecutionError> {
    object(
        out,
        credits
            .iter()
            .map(|(recipient, amount)| (recipient.as_str(), amount))
            .collect(),
        |out, amount| value(out, &VmValue::Decimal(amount.clone())),
    )
}

fn reward_record(out: &mut String, record: &RewardRecord) -> Result<(), VmExecutionError> {
    out.push_str("{\"recipient_key\":");
    write_string(out, &record.recipient_key);
    out.push_str(",\"source_contract\":");
    if let Some(source) = &record.source_contract {
        write_string(out, source);
    } else {
        out.push_str("null");
    }
    out.push_str(",\"type\":");
    write_string(out, record.kind.name());
    if let Some(validator) = &record.validator_key {
        out.push_str(",\"validator_key\":");
        write_string(out, validator);
    }
    out.push_str(",\"value\":");
    value(out, &VmValue::Decimal(record.value.clone()))?;
    out.push('}');
    Ok(())
}

fn array<T>(
    out: &mut String,
    items: &[T],
    mut write_value: impl FnMut(&mut String, &T) -> Result<(), VmExecutionError>,
) -> Result<(), VmExecutionError> {
    out.push('[');
    for (index, item) in items.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        write_value(out, item)?;
    }
    out.push(']');
    Ok(())
}

fn object<T>(
    out: &mut String,
    mut entries: Vec<(&str, &T)>,
    mut write_value: impl FnMut(&mut String, &T) -> Result<(), VmExecutionError>,
) -> Result<(), VmExecutionError> {
    entries.sort_unstable_by_key(|(key, _)| *key);
    out.push('{');
    for (index, (key, item)) in entries.into_iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        write_string(out, key);
        out.push(':');
        write_value(out, item)?;
    }
    out.push('}');
    Ok(())
}
