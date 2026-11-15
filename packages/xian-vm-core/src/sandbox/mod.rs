//! A chain in memory: committed state in a `MemoryStore`, transactions run
//! one at a time by the block executor's rules (`execute_tx`'s code), each
//! over a fresh block overlay that is committed afterwards (or dropped for a
//! dry run). This is what the browser build exposes (`wasm_bindings`); it
//! holds no logic of its own beyond reading requests and writing JSON.
mod contracts;
mod outcome;
mod request;
#[cfg(test)]
mod tests;

use crate::block_executor::{BlockExecutor, BlockPolicy, FeeMode};
use crate::block_host::{compile, IR_KEY, SOURCE_KEY, TIME_KEY};
use crate::block_state::{lock, BlockState};
use crate::committed_store::{storage_key_error, CommittedStore};
use crate::memory_store::MemoryStore;
use crate::panic_guard::catching;
use crate::settlement::Stop;
use crate::state_root_storage::{storage_state_root, HashedKeys};
use crate::state_view::StateView;
use crate::stored_value::decode_stored_value;
use crate::stored_value_encoder::encode_stored_value;
use crate::VmValue;
use outcome::{array, json_string, Object};
use request::{Environment, Fields, Run};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

/// The built-in submission contract, installed in every new sandbox.
const SUBMISSION_SOURCE: &str =
    include_str!("../../../../src/contracting/contracts/submission_source.s.py");
/// The key the execution policy lives at: contract effects may not write it.
const EXECUTION_POLICY_KEY: &str = "__execution_policy";
/// The snapshot format written by `export` and read by `import`.
const SNAPSHOT_FORMAT: &str = "xian-vm-state/1";

/// A refused request, snapshot or value; the text says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SandboxError(pub(crate) String);

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub(crate) struct Sandbox {
    store: Arc<MemoryStore>,
}

/// The stored bytes of `value` (`None` stores a deletion).
fn stored(value: &VmValue) -> Result<Option<Arc<[u8]>>, SandboxError> {
    match value {
        VmValue::None => Ok(None),
        value => encode_stored_value(value)
            .map(|bytes| Some(Arc::from(bytes)))
            .map_err(|error| SandboxError(error.to_string())),
    }
}

impl Sandbox {
    /// A new chain holding the submission contract, installed as a genesis
    /// installs it (`Driver.set_contract`: source, IR and the submission
    /// time; no owner or actors).
    pub(crate) fn create(options: &str) -> Result<Self, SandboxError> {
        let mut fields = Fields::parse(options, "create options")?;
        let environment = Environment::read(&mut fields)?;
        fields.finish("create options")?;
        let (source, ir) = compile("submission", SUBMISSION_SOURCE)
            .map_err(|error| SandboxError(format!("submission contract: {error}")))?;
        let writes = [
            (SOURCE_KEY, VmValue::String(source)),
            (IR_KEY, VmValue::String(ir)),
            (TIME_KEY, environment.now),
        ]
        .into_iter()
        .map(|(field, value)| Ok((format!("submission.{field}"), stored(&value)?)))
        .collect::<Result<BTreeMap<_, _>, SandboxError>>()?;
        let sandbox = Self {
            store: Arc::new(MemoryStore::default()),
        };
        sandbox.store.apply(&writes);
        Ok(sandbox)
    }

    /// An independent copy of the committed state.
    pub(crate) fn duplicate(&self) -> Self {
        Self {
            store: Arc::new(MemoryStore::from_entries(self.store.snapshot())),
        }
    }

    /// Run a call request; see `request::call`.
    pub(crate) fn call(&self, request: &str) -> Result<String, SandboxError> {
        self.execute(request::call(request)?)
    }

    /// Run a deploy request; see `request::deploy`.
    pub(crate) fn deploy(&self, request: &str) -> Result<String, SandboxError> {
        self.execute(request::deploy(request)?)
    }

    fn execute(&self, run: Run) -> Result<String, SandboxError> {
        let overlay = Arc::new(Mutex::new(BlockState::default()));
        let store: Arc<dyn CommittedStore> = self.store.clone();
        let policy = BlockPolicy {
            meter_execution: run.options.metering,
            charge_fees: run.options.charge_fees,
            distribute_fee_rewards: false,
            zk_enabled_without_state: true,
            protected_keys: vec![EXECUTION_POLICY_KEY.to_owned()],
        };
        let executor = BlockExecutor::settling(
            StateView::new(store, Arc::clone(&overlay)),
            policy,
            FeeMode::Reserved,
        );
        let outcome = match catching(|| executor.execute(&run.tx)) {
            Err(panic) => return Err(SandboxError(format!("the executor panicked: {panic}"))),
            Ok(Err(Stop::Fault(fault))) => return Err(SandboxError(fault)),
            Ok(Ok(outcome)) => outcome,
        };
        if run.options.commit {
            self.commit(&overlay)?;
        }
        Ok(outcome::outcome_json(&outcome))
    }

    fn commit(&self, overlay: &Mutex<BlockState>) -> Result<(), SandboxError> {
        lock(overlay)
            .commit(|writes| {
                self.store.apply(writes);
                Ok::<(), Infallible>(())
            })
            .map_err(|error| SandboxError(error.to_string()))?
            .map_err(|never| match never {})
    }

    /// The value stored at `key`, decoded.
    fn value(&self, key: &str) -> Option<VmValue> {
        let mut value = None;
        let _ = self.store.read(key.as_bytes(), &mut |stored| {
            value = stored.and_then(|bytes| decode_stored_value(bytes).ok());
        });
        value
    }

    /// The wire JSON text stored at `key` (the stored bytes are that text).
    pub(crate) fn get(&self, key: &str) -> Option<String> {
        let mut text = None;
        let _ = self.store.read(key.as_bytes(), &mut |stored| {
            text = stored.map(|bytes| String::from_utf8_lossy(bytes).into_owned());
        });
        text
    }

    /// `[[key, wireText], ...]` under `prefix` in key order, at most `limit`.
    pub(crate) fn items(&self, prefix: &str, limit: Option<usize>) -> String {
        let mut entries = Vec::new();
        let limit = limit.unwrap_or(usize::MAX);
        let _ = self.store.scan_from(prefix.as_bytes(), &mut |key, value| {
            if !key.starts_with(prefix.as_bytes()) || entries.len() >= limit {
                return Ok(false);
            }
            entries.push(entry_json(key, value));
            Ok(true)
        });
        array(entries)
    }

    /// Store `wire` (a wire JSON text) at `key`, or delete the key.
    pub(crate) fn set_value(&self, key: &str, wire: Option<&str>) -> Result<(), SandboxError> {
        if let Some(error) = storage_key_error(key) {
            return Err(SandboxError(error));
        }
        let value = match wire {
            None => VmValue::None,
            Some(text) => {
                let json = serde_json::from_str(text)
                    .map_err(|error| SandboxError(format!("value is not JSON: {error}")))?;
                request::wire_value(&json, "value")?
            }
        };
        self.store
            .apply(&BTreeMap::from([(key.to_owned(), stored(&value)?)]));
        Ok(())
    }

    /// Delete every key of contract `name` (`Driver.delete_contract`).
    pub(crate) fn remove_contract(&self, name: &str) {
        let prefix = format!("{name}.");
        let mut doomed = BTreeMap::new();
        let _ = self.store.scan_from(prefix.as_bytes(), &mut |key, _| {
            if !key.starts_with(prefix.as_bytes()) {
                return Ok(false);
            }
            doomed.insert(String::from_utf8_lossy(key).into_owned(), None);
            Ok(true)
        });
        self.store.apply(&doomed);
    }

    /// The names of deployed contracts, sorted, as a JSON array.
    pub(crate) fn contracts(&self) -> String {
        let names = self.store.snapshot().into_iter().filter_map(|(key, _)| {
            let key = std::str::from_utf8(&key).ok()?;
            contracts::contract_of_ir_key(key).map(json_string)
        });
        array(names)
    }

    /// `ContractInfo` JSON of contract `name`, or `None` when not deployed.
    pub(crate) fn contract(&self, name: &str) -> Option<String> {
        contracts::contract_json(name, |key| self.value(key))
    }

    /// The hex state root over every key that does not start with `__`.
    pub(crate) fn state_root(&self) -> Result<String, SandboxError> {
        let hashed = HashedKeys::new(Vec::new(), Vec::new());
        storage_state_root(self.store.as_ref(), &hashed)
            .map(|tree| hex::encode(tree.root_hash()))
            .map_err(|error| SandboxError(format!("state root: {error:?}")))
    }

    /// The committed state as a `StateSnapshot` JSON (keys in byte order).
    pub(crate) fn export(&self) -> String {
        let entries = self
            .store
            .snapshot()
            .into_iter()
            .map(|(key, value)| entry_json(&key, &value));
        Object::default()
            .text("format", SNAPSHOT_FORMAT)
            .raw("entries", &array(entries))
            .finish()
    }

    /// A sandbox holding a `StateSnapshot`; every key and value is checked
    /// as the node would store it.
    pub(crate) fn import(snapshot: &str) -> Result<Self, SandboxError> {
        let mut fields = Fields::parse(snapshot, "snapshot")?;
        if fields.text("format")? != SNAPSHOT_FORMAT {
            return Err(SandboxError(format!(
                "snapshot format is not {SNAPSHOT_FORMAT}"
            )));
        }
        let entries: Vec<(String, String)> = serde_json::from_value(fields.required("entries")?)
            .map_err(|error| SandboxError(format!("snapshot entries: {error}")))?;
        fields.finish("snapshot")?;
        let checked = entries
            .into_iter()
            .map(|(key, text)| checked_entry(key, text))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            store: Arc::new(MemoryStore::from_entries(checked)),
        })
    }
}

/// The engine's versions, as the package's `runtimeInfo()` reports them.
pub(crate) fn runtime_info() -> String {
    Object::default()
        .text("version", env!("CARGO_PKG_VERSION"))
        .text("vm_profile", crate::XIAN_VM_V2_PROFILE)
        .text("execution_revision", crate::XIAN_VM_EXECUTION_REVISION)
        .text("gas_schedule", crate::XIAN_VM_SUPPORTED_GAS_SCHEDULES[0])
        .raw("zk", "true")
        .finish()
}

fn entry_json(key: &[u8], value: &[u8]) -> String {
    format!(
        "[{},{}]",
        json_string(&String::from_utf8_lossy(key)),
        json_string(&String::from_utf8_lossy(value))
    )
}

/// A snapshot entry as stored: a storable key and the canonical stored
/// bytes of a value the node's decoder reads.
fn checked_entry(key: String, text: String) -> Result<(Vec<u8>, Arc<[u8]>), SandboxError> {
    if let Some(error) = storage_key_error(&key) {
        return Err(SandboxError(format!("snapshot key {key:?}: {error}")));
    }
    let value = decode_stored_value(text.as_bytes())
        .map_err(|error| SandboxError(format!("snapshot value at {key:?}: {error}")))?;
    match stored(&value)? {
        Some(bytes) if bytes[..] == *text.as_bytes() => Ok((key.into_bytes(), bytes)),
        _ => Err(SandboxError(format!(
            "snapshot value at {key:?} is not in canonical stored form"
        ))),
    }
}
