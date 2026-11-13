//! The contract metadata reads (`NativeVmHost.handle_syscall` for
//! `contract.exists`, `has_export`, `owner_of`, `info` and `code_hash`).
use super::modules::{exports, runnable, Ir};
use super::{host_text, text, BlockHost, IR_KEY, OWNER_KEY, SOURCE_KEY};
use crate::settlement::Stop;
use crate::{VmExecutionError, VmValue};
use sha3::{Digest, Sha3_256};

/// `contract.info`'s fields after the name, and the variables they read.
const CONTRACT_INFO: [(&str, &str); 5] = [
    ("owner", OWNER_KEY),
    ("developer", "__developer__"),
    ("deployer", "__deployer__"),
    ("initiator", "__initiator__"),
    ("submitted", "__submitted__"),
];
/// A contract metadata read served here: the syscall, its fewest and most
/// arguments, and the read of the named contract (the VM binds every
/// argument positionally).
type MetadataRead = (
    &'static str,
    usize,
    usize,
    fn(&mut BlockHost<'_>, &str, &[VmValue]) -> Result<VmValue, VmExecutionError>,
);
const METADATA_READS: [MetadataRead; 5] = [
    ("contract.exists", 1, 1, |host, contract, _| {
        Ok(VmValue::Bool(host.contract_exists(contract)?))
    }),
    ("contract.has_export", 2, 2, |host, contract, args| {
        let export = host.string_arg(args, 1)?;
        Ok(VmValue::Bool(host.contract_has_export(contract, &export)?))
    }),
    ("contract.owner_of", 1, 1, |host, contract, _| {
        host.metadata(contract, OWNER_KEY)
    }),
    ("contract.info", 1, 1, |host, contract, _| {
        host.contract_info(contract)
    }),
    ("contract.code_hash", 1, 2, |host, contract, args| {
        host.code_hash(contract, args.get(1))
    }),
];

/// The metadata read `syscall_id` with these arguments, or `None` when it
/// is not one served here.
pub(super) fn read(
    host: &mut BlockHost<'_>,
    syscall_id: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Option<Result<VmValue, VmExecutionError>> {
    let (_, _, _, read) = METADATA_READS.iter().find(|(id, fewest, most, _)| {
        *id == syscall_id && (*fewest..=*most).contains(&args.len()) && kwargs.is_empty()
    })?;
    Some(
        host.string_arg(args, 0)
            .and_then(|contract| read(host, &contract, args)),
    )
}

impl BlockHost<'_> {
    /// `NativeVmHost._contract_exists`.
    fn contract_exists(&mut self, contract: &str) -> Result<bool, VmExecutionError> {
        if !matches!(self.ir(contract)?, Ir::Absent) {
            return Ok(true);
        }
        Ok(self.get(&format!("{contract}.{SOURCE_KEY}"))?.is_some())
    }

    /// `NativeVmHost._contract_has_export`.
    fn contract_has_export(
        &mut self,
        contract: &str,
        export: &str,
    ) -> Result<bool, VmExecutionError> {
        let Ir::Text(module) = self.ir(contract)? else {
            return Ok(false);
        };
        match runnable(contract, &module) {
            Ok(module) => Ok(exports(&module, export)),
            Err(Stop::Handback(reason)) => self.back(reason),
            Err(stop) => Err(self.halt(stop)),
        }
    }

    /// A contract metadata variable (`NativeVmHost._contract_var`).
    fn metadata(&mut self, contract: &str, variable: &str) -> Result<VmValue, VmExecutionError> {
        Ok(self
            .get(&format!("{contract}.{variable}"))?
            .unwrap_or(VmValue::None))
    }

    /// `contract.info`: the name and the deployment metadata.
    fn contract_info(&mut self, contract: &str) -> Result<VmValue, VmExecutionError> {
        let mut info = vec![(text("name"), text(contract))];
        for (field, variable) in CONTRACT_INFO {
            let value = self.metadata(contract, variable)?;
            info.push((text(field), value));
        }
        Ok(VmValue::Dict(info))
    }

    /// `NativeVmHost._code_hash`: the SHA3-256 hex digest of the contract's
    /// IR (kind "runtime", the default, or "ir") or source ("source"); `None`
    /// when it has none.
    fn code_hash(
        &mut self,
        contract: &str,
        kind: Option<&VmValue>,
    ) -> Result<VmValue, VmExecutionError> {
        let variable = code_variable(kind)?;
        if variable == IR_KEY {
            if let Ir::Text(module) = self.ir(contract)? {
                return Ok(code_digest(&module.text));
            }
        }
        match self.metadata(contract, variable)? {
            VmValue::None => Ok(VmValue::None),
            VmValue::String(code) => Ok(code_digest(&code)),
            _ => self.back("contract code is not a string"),
        }
    }
}

/// The contract variable `code_hash` hashes for `kind`: the IR for
/// "runtime" (the default) and "ir", the source for "source".
fn code_variable(kind: Option<&VmValue>) -> Result<&'static str, VmExecutionError> {
    match kind.map(|kind| (kind, host_text(kind))) {
        None | Some((VmValue::None, _)) | Some((_, Some("runtime" | "ir"))) => Ok(IR_KEY),
        Some((_, Some("source"))) => Ok(SOURCE_KEY),
        // The Python host's VmRuntimeExecutionError, as `host_error` reports it.
        Some(_) => Err(VmExecutionError::new(
            "VmRuntimeExecutionError: Hash kind must be 'ir' or 'source'!",
        )),
    }
}

fn code_digest(code: &str) -> VmValue {
    text(&hex::encode(Sha3_256::digest(code.as_bytes())))
}
