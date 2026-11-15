//! A transaction's outcome as JSON (`TxOutcome` in the package's API).
//!
//! Every contract value is written as its wire JSON *text* (the stored-value
//! encoding, the format transactions and state use), inside a JSON string, so
//! no JSON parser in between reorders, rounds or reinterprets it. A value the
//! wire format cannot carry is written as `{"__repr__": <Python repr>}`.
use crate::block_executor::TxOutcome;
use crate::stored_value_encoder::encode_stored_value;
use crate::{VmEvent, VmException, VmValue};

/// The wire JSON text of `value`.
pub(crate) fn wire_text(value: &VmValue) -> String {
    match encode_stored_value(value) {
        // The encoder writes ASCII JSON (`ensure_ascii`).
        Ok(bytes) => String::from_utf8(bytes).expect("stored values are ASCII"),
        Err(_) => format!("{{\"__repr__\":{}}}", json_string(&value.python_repr())),
    }
}

pub(crate) fn json_string(text: &str) -> String {
    serde_json::to_string(text).expect("a string serializes")
}

/// A JSON object written field by field, in order.
#[derive(Default)]
pub(crate) struct Object {
    out: String,
}

impl Object {
    /// A field whose value is already JSON.
    pub(crate) fn raw(mut self, name: &str, json: &str) -> Self {
        self.out
            .push_str(if self.out.is_empty() { "{" } else { "," });
        self.out.push_str(&json_string(name));
        self.out.push(':');
        self.out.push_str(json);
        self
    }

    pub(crate) fn text(self, name: &str, text: &str) -> Self {
        self.raw(name, &json_string(text))
    }

    /// A field holding a value's wire JSON text.
    pub(crate) fn wire(self, name: &str, value: &VmValue) -> Self {
        self.text(name, &wire_text(value))
    }

    pub(crate) fn finish(self) -> String {
        if self.out.is_empty() {
            "{}".to_owned()
        } else {
            self.out + "}"
        }
    }
}

pub(crate) fn array(items: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", items.into_iter().collect::<Vec<_>>().join(","))
}

fn optional<T>(value: Option<T>, json: impl FnOnce(T) -> String) -> String {
    value.map_or_else(|| "null".to_owned(), json)
}

fn exception_json(exception: &VmException) -> String {
    let args = array(
        exception
            .args
            .iter()
            .map(|arg| json_string(&wire_text(arg))),
    );
    Object::default()
        .text("name", &exception.name)
        .raw("args", &args)
        .finish()
}

fn dict(entries: &[(String, VmValue)]) -> VmValue {
    VmValue::Dict(
        entries
            .iter()
            .map(|(key, value)| (VmValue::String(key.clone()), value.clone()))
            .collect(),
    )
}

fn event_json(event: &VmEvent) -> String {
    Object::default()
        .text("contract", &event.contract)
        .text("event", &event.event)
        .wire("signer", &event.signer)
        .wire("caller", &event.caller)
        .wire("data_indexed", &dict(&event.data_indexed))
        .wire("data", &dict(&event.data))
        .finish()
}

fn write_json((key, value): &(String, VmValue)) -> String {
    let value = match value {
        VmValue::None => "null".to_owned(),
        value => json_string(&wire_text(value)),
    };
    format!("[{},{value}]", json_string(key))
}

/// The message of a failed transaction: its exception's text argument
/// (`str(exception)`), else the failure text it reports as its result.
fn error_json(outcome: &TxOutcome) -> String {
    if outcome.status == 0 {
        return "null".to_owned();
    }
    let args = outcome
        .exception
        .as_ref()
        .map(|exception| exception.args.as_slice());
    let message = match (args, &outcome.result) {
        (Some([VmValue::String(text)]), _) | (_, VmValue::String(text)) => text.clone(),
        (_, other) => other.python_repr(),
    };
    json_string(&message)
}

/// The outcome as the API's `TxOutcome` JSON.
pub(crate) fn outcome_json(outcome: &TxOutcome) -> String {
    let costs = outcome
        .contract_costs
        .iter()
        .fold(Object::default(), |costs, (contract, cost)| {
            costs.raw(contract, &cost.to_string())
        })
        .finish();
    Object::default()
        .raw("status", &outcome.status.to_string())
        .wire("result", &outcome.result)
        .raw("error", &error_json(outcome))
        .raw(
            "exception",
            &optional(outcome.exception.as_ref(), exception_json),
        )
        .raw("chi_used", &outcome.chi_used.to_string())
        .raw("writes", &array(outcome.writes.iter().map(write_json)))
        .raw("events", &array(outcome.events.iter().map(event_json)))
        .raw("contract_costs", &costs)
        .raw(
            "unprepared",
            if outcome.unprepared { "true" } else { "false" },
        )
        .finish()
}
