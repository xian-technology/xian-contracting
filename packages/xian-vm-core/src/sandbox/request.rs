//! A sandbox request: one transaction and how to run it, read from JSON.
//!
//! The call's arguments are read as the node reads a signed transaction's
//! (`transaction_inputs::call_kwargs`: canonical JSON, then the strict
//! stored-value decoder), and its context is the one a block gives a
//! transaction, with the block fields taken from the request's environment.
use super::SandboxError;
use crate::block_executor::PreparedTx;
use crate::stored_value::decode_stored_value;
use crate::transaction_inputs::{call_kwargs, submission_name};
use crate::{VmExecutionContext, VmValue};
use num_bigint::BigInt;
use serde_json::{Map, Value};
use xian_fastpath_core::canonical_json;

/// How a transaction runs and what happens to its effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunOptions {
    pub(crate) metering: bool,
    pub(crate) charge_fees: bool,
    /// Stage the effects into the sandbox's committed state.
    pub(crate) commit: bool,
}

/// One transaction to run.
pub(crate) struct Run {
    pub(crate) tx: PreparedTx,
    pub(crate) options: RunOptions,
}

fn invalid(message: impl Into<String>) -> SandboxError {
    SandboxError(message.into())
}

/// A JSON object's fields, each taken once; any field left over is refused.
pub(crate) struct Fields(Map<String, Value>);

impl Fields {
    pub(crate) fn parse(json: &str, what: &str) -> Result<Self, SandboxError> {
        match serde_json::from_str(json) {
            Ok(Value::Object(fields)) => Ok(Self(fields)),
            Ok(_) => Err(invalid(format!("{what} must be a JSON object"))),
            Err(error) => Err(invalid(format!("{what} is not JSON: {error}"))),
        }
    }

    fn of(value: Value, what: &str) -> Result<Self, SandboxError> {
        match value {
            Value::Object(fields) => Ok(Self(fields)),
            _ => Err(invalid(format!("{what} must be a JSON object"))),
        }
    }

    fn take(&mut self, name: &str) -> Option<Value> {
        self.0.remove(name).filter(|value| !value.is_null())
    }

    pub(crate) fn required(&mut self, name: &str) -> Result<Value, SandboxError> {
        self.take(name)
            .ok_or_else(|| invalid(format!("{name} is required")))
    }

    pub(crate) fn text(&mut self, name: &str) -> Result<String, SandboxError> {
        self.optional_text(name)?
            .ok_or_else(|| invalid(format!("{name} is required")))
    }

    fn optional_text(&mut self, name: &str) -> Result<Option<String>, SandboxError> {
        match self.take(name) {
            None => Ok(None),
            Some(Value::String(text)) => Ok(Some(text)),
            Some(_) => Err(invalid(format!("{name} must be a string"))),
        }
    }

    fn flag(&mut self, name: &str, default: bool) -> Result<bool, SandboxError> {
        match self.take(name) {
            None => Ok(default),
            Some(Value::Bool(flag)) => Ok(flag),
            Some(_) => Err(invalid(format!("{name} must be a boolean"))),
        }
    }

    fn count(&mut self, name: &str) -> Result<u64, SandboxError> {
        match self.take(name) {
            None => Ok(0),
            Some(value) => value
                .as_u64()
                .ok_or_else(|| invalid(format!("{name} must be a non-negative integer"))),
        }
    }

    fn object(&mut self, name: &str) -> Result<Value, SandboxError> {
        match self.take(name) {
            None => Ok(Value::Object(Map::new())),
            Some(value @ Value::Object(_)) => Ok(value),
            Some(_) => Err(invalid(format!("{name} must be a JSON object"))),
        }
    }

    pub(crate) fn finish(self, what: &str) -> Result<(), SandboxError> {
        match self.0.keys().next() {
            None => Ok(()),
            Some(unknown) => Err(invalid(format!("{what} has an unknown field {unknown:?}"))),
        }
    }
}

/// A wire value as the node decodes one from a transaction.
pub(crate) fn wire_value(value: &Value, what: &str) -> Result<VmValue, SandboxError> {
    let json = canonical_json(value).map_err(|error| invalid(format!("{what}: {error}")))?;
    decode_stored_value(json.as_bytes()).map_err(|error| invalid(format!("{what}: {error}")))
}

/// The block a transaction runs in.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Environment {
    pub(crate) now: VmValue,
    pub(crate) block_num: VmValue,
    pub(crate) block_hash: VmValue,
    pub(crate) chain_id: VmValue,
    pub(crate) input_hash: VmValue,
}

impl Environment {
    pub(crate) fn read(fields: &mut Fields) -> Result<Self, SandboxError> {
        let mut environment = Fields::of(fields.object("environment")?, "environment")?;
        let mut field = |name: &str, default: VmValue| match environment.take(name) {
            None => Ok(default),
            Some(value) => wire_value(&value, &format!("environment.{name}")),
        };
        let read = Self {
            now: field("now", VmValue::None)?,
            block_num: field("block_num", VmValue::Int(BigInt::from(-1)))?,
            block_hash: field("block_hash", VmValue::None)?,
            chain_id: field("chain_id", VmValue::None)?,
            input_hash: field("input_hash", VmValue::None)?,
        };
        environment.finish("environment")?;
        Ok(read)
    }
}

/// A call request (`CallRequest`).
pub(crate) fn call(json: &str) -> Result<Run, SandboxError> {
    let mut fields = Fields::parse(json, "call request")?;
    let sender = fields.text("sender")?;
    let contract = fields.text("contract")?;
    let function = fields.text("function")?;
    let kwargs = fields.object("kwargs")?;
    run(fields, "call request", sender, contract, function, kwargs)
}

/// A deploy request (`DeployRequest`): `submission.submit_contract`.
pub(crate) fn deploy(json: &str) -> Result<Run, SandboxError> {
    let mut fields = Fields::parse(json, "deploy request")?;
    let sender = fields.text("sender")?;
    let mut kwargs = Map::new();
    kwargs.insert("name".to_owned(), Value::String(fields.text("name")?));
    kwargs.insert("code".to_owned(), Value::String(fields.text("source")?));
    if let Some(owner) = fields.optional_text("owner")? {
        kwargs.insert("owner".to_owned(), Value::String(owner));
    }
    let constructor_args = fields.object("constructor_args")?;
    kwargs.insert("constructor_args".to_owned(), constructor_args);
    let (contract, function) = ("submission".to_owned(), "submit_contract".to_owned());
    run(
        fields,
        "deploy request",
        sender,
        contract,
        function,
        Value::Object(kwargs),
    )
}

fn run(
    mut fields: Fields,
    what: &str,
    sender: String,
    contract: String,
    function: String,
    kwargs: Value,
) -> Result<Run, SandboxError> {
    let kwargs = call_kwargs(&kwargs)
        .ok_or_else(|| invalid(format!("{what}: arguments the VM does not take")))?;
    let environment = Environment::read(&mut fields)?;
    let options = RunOptions {
        metering: fields.flag("metering", true)?,
        charge_fees: fields.flag("charge_fees", false)?,
        commit: fields.flag("commit", true)?,
    };
    let chi_budget = BigInt::from(fields.count("chi_budget")?);
    let size_bytes = usize::try_from(fields.count("transaction_size_bytes")?)
        .map_err(|_| invalid("transaction_size_bytes is too large"))?;
    fields.finish(what)?;
    let context = VmExecutionContext {
        this: Some(contract.clone()),
        caller: Some(sender.clone()),
        signer: Some(sender.clone()),
        owner: None,
        entry: Some((contract.clone(), function.clone())),
        submission_name: submission_name(&contract, &kwargs),
        now: environment.now,
        block_num: environment.block_num,
        block_hash: environment.block_hash,
        chain_id: environment.chain_id,
        input_hash: environment.input_hash,
    };
    let tx = PreparedTx {
        sender,
        contract,
        function,
        kwargs,
        context,
        chi_budget,
        size_bytes,
    };
    Ok(Run { tx, options })
}
