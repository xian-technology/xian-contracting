//! The VM host of a block transaction (`NativeVmHost` for the Rust block
//! executor): state from the transaction's host writes, then the block
//! overlay and LMDB. A request it cannot serve marks the transaction for the
//! Python path (`Stop::Handback`); a storage failure halts (`Stop::Fault`).
//!
//! By concern: `modules` holds the contracts' IR as the node prepares it,
//! `metadata` the contract metadata reads and changes, `writes` what one
//! transaction's host syscalls stage, `charges` what they cost. Every other
//! host syscall is still handed back.
#![cfg_attr(not(feature = "python-extension"), allow(dead_code))]

mod charges;
mod metadata;
pub(crate) mod modules;
mod writes;

pub(crate) use charges::HostCharges;
pub(crate) use modules::{Ir, Modules};
pub(crate) use writes::HostWrites;

use crate::settlement::Stop;
use crate::state_view::StateView;
use crate::{VmExecutionError, VmValue};
use std::convert::Infallible;

pub(crate) const IR_KEY: &str = "__xian_ir_v1__";
pub(crate) const SOURCE_KEY: &str = "__source__";
pub(crate) const OWNER_KEY: &str = "__owner__";
pub(crate) const DEVELOPER_KEY: &str = "__developer__";

pub(crate) fn fault(error: String) -> Stop {
    Stop::Fault(error)
}

pub(crate) fn text(value: &str) -> VmValue {
    VmValue::String(value.to_owned())
}

/// The string the Python host receives for `value` (`vm_to_py`): a string
/// or a contract module handle's name.
fn host_text(value: &VmValue) -> Option<&str> {
    match value {
        VmValue::String(text) => Some(text),
        VmValue::ContractHandle(handle) => Some(&handle.module),
        _ => None,
    }
}

pub(crate) struct BlockHost<'a> {
    view: StateView,
    modules: &'a Modules,
    writes: HostWrites,
    charges: HostCharges,
    stop: Option<Stop>,
}

impl<'a> BlockHost<'a> {
    pub(crate) fn new(view: StateView, modules: &'a Modules, charges: HostCharges) -> Self {
        Self {
            view,
            modules,
            writes: HostWrites::default(),
            charges,
            stop: None,
        }
    }

    /// What the transaction's host syscalls staged and cost, or why the
    /// transaction stopped.
    pub(crate) fn finish(self) -> Result<(HostWrites, HostCharges), Stop> {
        match self.stop {
            Some(stop) => Err(stop),
            None => Ok((self.writes, self.charges)),
        }
    }

    /// The IR of `name`: a staged IR text (`NativeVmHost.load_module_ir_json`
    /// reads the pending IR first), else the run's cached read.
    fn ir(&mut self, name: &str) -> Result<Ir, VmExecutionError> {
        let key = format!("{name}.{IR_KEY}");
        if let Some(staged @ VmValue::String(text)) = self.writes.get(&key) {
            if !text.is_empty() {
                return Ok(Ir::of(Some(staged.clone())));
            }
        }
        self.modules
            .ir(&self.view, name)
            .map_err(|error| self.halt(fault(error)))
    }

    fn halt(&mut self, stop: Stop) -> VmExecutionError {
        let message = match &stop {
            Stop::Handback(reason) => format!("handed back to the Python path: {reason}"),
            Stop::Fault(reason) => format!("host fault: {reason}"),
        };
        self.stop.get_or_insert(stop);
        VmExecutionError::new(message)
    }

    /// The value at `key` as `NativeVmHost._lookup_key` reads it: a staged
    /// write first; `None` when missing or deleted.
    fn get(&mut self, key: &str) -> Result<Option<VmValue>, VmExecutionError> {
        let value = match self.writes.get(key) {
            Some(staged) => Ok(Some(staged.clone())),
            None => self.view.get(key),
        };
        match value {
            Ok(value) => Ok(value.filter(|value| !matches!(value, VmValue::None))),
            Err(error) => Err(self.halt(fault(error))),
        }
    }

    fn back<T>(&mut self, reason: impl Into<String>) -> Result<T, VmExecutionError> {
        Err(self.halt(Stop::Handback(reason.into())))
    }

    fn string_arg(&mut self, args: &[VmValue], index: usize) -> Result<String, VmExecutionError> {
        match args.get(index).and_then(host_text) {
            Some(value) => Ok(value.to_owned()),
            None => self.back("syscall argument is not a string"),
        }
    }

    /// The live entries under `prefix` as `NativeVmHost.iter_hash_entries`
    /// sees them, in key order: the staged entries merged into the overlay
    /// and LMDB scan; `visit` returns false to stop.
    fn visit_prefix(
        &mut self,
        prefix: &str,
        visit: &mut dyn FnMut(String, VmValue) -> bool,
    ) -> Result<(), VmExecutionError> {
        let mut merge = self.writes.merge_under(prefix, visit);
        let scanned = self.view.visit_prefix(prefix, &mut |key, value| {
            let Ok(more) = merge.stored(key, || Ok::<_, Infallible>(value));
            more
        });
        merge.finish();
        scanned.map_err(|error| self.halt(fault(error)))
    }
}

#[cfg(feature = "python-extension")]
mod services {
    use super::{metadata, BlockHost, Ir, OWNER_KEY};
    use crate::bundle_executor::{validate_bundle_module, HostServices};
    use crate::interpreter::vm_variable_storage_key;
    use crate::{ValidatedModuleIr, VmExecutionError, VmValue};

    impl HostServices for BlockHost<'_> {
        fn module_ir_json(&mut self, module: &str) -> Result<Option<String>, VmExecutionError> {
            match self.ir(module)? {
                Ir::Text(cached) => Ok(Some(cached.text.clone())),
                _ => Ok(None),
            }
        }

        fn module(
            &mut self,
            module: &str,
            profile: &str,
        ) -> Result<Option<ValidatedModuleIr>, VmExecutionError> {
            let Ir::Text(cached) = self.ir(module)? else {
                return Ok(None);
            };
            let validated = cached.validated(module).map_err(VmExecutionError::new)?;
            validate_bundle_module(&validated, module, profile)?;
            Ok(Some(validated))
        }

        fn read_variable(
            &mut self,
            _contract: &str,
            _binding: &str,
            storage_key: &str,
        ) -> Result<Option<VmValue>, VmExecutionError> {
            self.get(storage_key)
        }

        fn read_hash(
            &mut self,
            _contract: &str,
            _binding: &str,
            _key: &VmValue,
            storage_key: &str,
        ) -> Result<VmValue, VmExecutionError> {
            Ok(self.get(storage_key)?.unwrap_or(VmValue::None))
        }

        fn scan_hash_entries(
            &mut self,
            contract: &str,
            binding: &str,
            prefix: &str,
        ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
            let mut entries = Vec::new();
            self.visit_hash_entries(contract, binding, prefix, &mut |suffix, value| {
                entries.push((suffix, value));
                Ok(())
            })?;
            Ok(entries)
        }

        /// `NativeVmHost.iter_hash_entries`: the hash's entries under
        /// `prefix` (its key suffix with the trailing delimiter), as
        /// `(suffix, value)`.
        fn visit_hash_entries(
            &mut self,
            contract: &str,
            binding: &str,
            prefix: &str,
            visit: &mut dyn FnMut(String, VmValue) -> Result<(), VmExecutionError>,
        ) -> Result<(), VmExecutionError> {
            let base_key = vm_variable_storage_key(contract, binding);
            let full_prefix = format!("{base_key}:{prefix}");
            let suffix_offset = base_key.len() + 1;
            let mut refused = None;
            let mut forward =
                |key: String, value| match visit(key[suffix_offset..].to_owned(), value) {
                    Ok(()) => true,
                    Err(error) => {
                        refused = Some(error);
                        false
                    }
                };
            self.visit_prefix(&full_prefix, &mut forward)?;
            refused.map_or(Ok(()), Err)
        }

        fn owner(&mut self, contract: &str) -> Result<Option<String>, VmExecutionError> {
            match self.get(&format!("{contract}.{OWNER_KEY}"))? {
                None => Ok(None),
                Some(VmValue::String(owner)) => Ok(Some(owner)),
                Some(_) => self.back("contract owner is not a string"),
            }
        }

        fn syscall(
            &mut self,
            syscall_id: &str,
            args: Vec<VmValue>,
            kwargs: Vec<(String, VmValue)>,
        ) -> Result<VmValue, VmExecutionError> {
            match metadata::read(self, syscall_id, &args, &kwargs)
                .or_else(|| metadata::change(self, syscall_id, &args, &kwargs))
            {
                Some(result) => result,
                None => self.back(format!("host syscall {syscall_id}")),
            }
        }
    }
}

#[cfg(test)]
mod tests;
