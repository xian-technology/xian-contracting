//! The contract zk syscalls: `contracting.stdlib.bridge.zk` as
//! `NativeVmHost.handle_syscall` serves them, over the `xian-zk` crate this
//! crate links (every node verifies zk proofs: zk is always available).
//!
//! The VM charges a zk call before the host runs it and binds every
//! argument positionally. Each function checks its arguments with the
//! Python function's checks and texts (`checks`), reads verifying keys
//! from `zk_registry` in chain state as the Python path does (the block
//! overlay and LMDB, not the transaction's own writes), verifies through the
//! node's proof caches (`crate::zk_cache`) and returns what the Python
//! function returns after the VM boundary. Revision 14: every zk syscall
//! fails while the chain's zk runtime feature is off (besides contract
//! preparation, `contract.has_export` and deployments refusing a contract
//! that uses them), a call shape or argument type the functions do not take
//! fails with a `TypeError`, and registry metadata the V2 boundary would
//! refuse fails the call.
mod checks;
mod shielded;
#[cfg(test)]
mod tests;

use super::{fault, BlockHost};
use crate::interpreter::numeric_v2;
use crate::zk_cache::{self, RegisteredKey, RegisteredProof};
use crate::{VmExecutionError, VmValue};
use checks::{
    assertion, convertible, hex, is_assertion, public_inputs, py, vk_id, Py, MAX_PROOF_HEX_CHARS,
    MAX_VK_HEX_CHARS,
};
use xian_zk::VerifierError;

type Served = Result<VmValue, VmExecutionError>;

/// `zk.get_vk_info`'s fields after the id, read from the registry.
const INFO_FIELDS: [&str; 24] = [
    "scheme",
    "curve",
    "vk_hash",
    "active",
    "circuit_name",
    "version",
    "created_at",
    "circuit_family",
    "statement_version",
    "contract_name",
    "artifact_contract_name",
    "tree_depth",
    "leaf_capacity",
    "max_inputs",
    "max_outputs",
    "setup_mode",
    "setup_ceremony",
    "artifact_hash",
    "bundle_hash",
    "warning",
    "deprecated",
    "deprecated_at",
    "replacement_vk_id",
    "index",
];

/// A zk function: its name, its number of arguments and what it does.
type Operation = (
    &'static str,
    usize,
    fn(&mut BlockHost<'_>, &[VmValue]) -> Served,
);

const OPERATIONS: [Operation; 18] = [
    ("is_available", 0, |_, _| Ok(VmValue::Bool(true))),
    ("has_verifying_key", 1, has_verifying_key),
    ("get_vk_info", 1, get_vk_info),
    ("verify_groth16_bn254", 3, |_, args| {
        verify_groth16_bn254(args)
    }),
    ("verify_groth16", 3, verify_groth16),
    ("clear_prepared_vk_cache", 0, |_, _| {
        zk_cache::clear_prepared();
        Ok(VmValue::None)
    }),
    ("clear_verified_proof_cache", 0, |_, _| {
        zk_cache::clear_verified();
        Ok(VmValue::None)
    }),
    ("warm_verified_proofs", 1, warm_verified_proofs),
    ("shielded_note_append_commitments", 3, |_, args| {
        shielded::append_commitments(args)
    }),
    ("shielded_command_nullifier_digest", 1, |_, args| {
        shielded::nullifier_digest(args)
    }),
    ("shielded_command_binding", 10, |_, args| {
        shielded::command_binding(args)
    }),
    ("shielded_command_execution_tag", 2, |_, args| {
        shielded::execution_tag(args)
    }),
    ("shielded_command_public_inputs", 9, |_, args| {
        shielded::command_public_inputs(args)
    }),
    ("shielded_deposit_public_inputs", 5, |_, args| {
        shielded::deposit_public_inputs(args)
    }),
    ("shielded_output_payload_hashes", 1, |_, args| {
        shielded::payload_hashes(args)
    }),
    ("shielded_output_payload_hash", 1, |_, args| {
        shielded::payload_hash(args)
    }),
    ("shielded_transfer_public_inputs", 5, |_, args| {
        shielded::transfer_public_inputs(args)
    }),
    ("shielded_withdraw_public_inputs", 7, |_, args| {
        shielded::withdraw_public_inputs(args)
    }),
];

/// The zk syscall `syscall_id` with these arguments, or `None` when it is
/// not one served here.
pub(crate) fn call(
    host: &mut BlockHost<'_>,
    syscall_id: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Option<Served> {
    let name = syscall_id.strip_prefix("zk.")?;
    let (_, arity, run) = OPERATIONS.iter().find(|(id, _, _)| *id == name)?;
    Some(served(host, syscall_id, args, kwargs, *arity, *run))
}

/// A zk syscall: the feature on, the call shape and argument types the zk
/// functions take (revision 14: a `TypeError` otherwise), then the call.
fn served(
    host: &mut BlockHost<'_>,
    syscall_id: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
    arity: usize,
    run: fn(&mut BlockHost<'_>, &[VmValue]) -> Served,
) -> Served {
    host.require_zk_syscall(syscall_id)?;
    if args.len() != arity || !kwargs.is_empty() {
        return Err(type_error(format!(
            "{syscall_id}() takes exactly {arity} positional arguments"
        )));
    }
    if let Some(value) = args.iter().find(|value| !convertible(value)) {
        return Err(type_error(format!(
            "{syscall_id}() cannot take a {} argument",
            value.type_name()
        )));
    }
    run(host, args)
}

fn type_error(message: String) -> VmExecutionError {
    VmExecutionError::described("TypeError", format!("TypeError: {message}"), message)
}

/// A native verifier failure as the bridge raises it.
fn verifier_failure(error: VerifierError) -> VmExecutionError {
    assertion(error.to_string())
}

fn has_verifying_key(host: &mut BlockHost<'_>, args: &[VmValue]) -> Served {
    match host.registered_key(&args[0]) {
        Ok(_) => Ok(VmValue::Bool(true)),
        Err(error) if is_assertion(&error) => Ok(VmValue::Bool(false)),
        Err(error) => Err(error),
    }
}

/// `zk.get_vk_info`: the key's registry metadata, `None` for an unknown key.
fn get_vk_info(host: &mut BlockHost<'_>, args: &[VmValue]) -> Served {
    let vk_id = vk_id(&args[0])?;
    if host.registry_field(vk_id, "vk_hex")?.is_none() {
        return Ok(VmValue::None);
    }
    let mut info = vec![(text("vk_id"), text(vk_id))];
    for field in INFO_FIELDS {
        let value = host.registry_field(vk_id, field)?;
        let value = if field == "deprecated" {
            VmValue::Bool(matches!(value, Some(VmValue::Bool(true))))
        } else {
            value.unwrap_or(VmValue::None)
        };
        info.push((text(field), value));
    }
    let info = VmValue::Dict(info);
    if !v2_returnable(&info) {
        return Err(super::charges::host_runtime_error(format!(
            "zk_registry metadata of '{vk_id}' cannot cross the VM boundary"
        )));
    }
    Ok(info)
}

fn verify_groth16_bn254(args: &[VmValue]) -> Served {
    let vk_hex = hex("vk_hex", &args[0], MAX_VK_HEX_CHARS)?;
    let proof_hex = hex("proof_hex", &args[1], MAX_PROOF_HEX_CHARS)?;
    let inputs = public_inputs(&args[2])?;
    xian_zk::verify_groth16_bn254(vk_hex, proof_hex, &inputs)
        .map(VmValue::Bool)
        .map_err(verifier_failure)
}

/// `zk.verify_groth16`: a proof against a registered key, through the
/// node's proof caches.
fn verify_groth16(host: &mut BlockHost<'_>, args: &[VmValue]) -> Served {
    vk_id(&args[0])?;
    let proof_hex = hex("proof_hex", &args[1], MAX_PROOF_HEX_CHARS)?.to_owned();
    let public_inputs = public_inputs(&args[2])?;
    let key = host.registered_key(&args[0])?;
    let proof = RegisteredProof {
        key,
        proof_hex,
        public_inputs,
    };
    zk_cache::verify_registered(&proof)
        .map(VmValue::Bool)
        .map_err(verifier_failure)
}

/// `zk.warm_verified_proofs`: every request checked and its key read before
/// the proofs not yet cached are verified together.
fn warm_verified_proofs(host: &mut BlockHost<'_>, args: &[VmValue]) -> Served {
    let Py::List(requests) = py(&args[0]) else {
        return Err(assertion("requests must be a list!"));
    };
    let mut proofs = Vec::with_capacity(requests.len());
    for (index, request) in requests.iter().enumerate() {
        proofs.push(host.warm_request(index, request)?);
    }
    let verified = zk_cache::warm(&proofs).map_err(verifier_failure)?;
    Ok(VmValue::List(
        verified.into_iter().map(VmValue::Bool).collect(),
    ))
}

/// `request.get(name)` of a request dict.
fn request_item<'a>(entries: &'a [(VmValue, VmValue)], name: &str) -> &'a VmValue {
    entries
        .iter()
        .rev()
        .find(|(key, _)| matches!(py(key), Py::Str(key) if key == name))
        .map_or(&VmValue::None, |(_, value)| value)
}

/// Whether the V2 boundary takes `value` back from the Python host
/// (`py_to_vm`): ints within 512 bits, no floats or raw decimals, dicts with
/// plain string keys.
fn v2_returnable(value: &VmValue) -> bool {
    if numeric_v2::validate_leaf(value).is_err() {
        return false;
    }
    match value {
        VmValue::List(items)
        | VmValue::Tuple(items)
        | VmValue::Set(items)
        | VmValue::FrozenSet(items) => items.iter().all(v2_returnable),
        VmValue::Dict(entries) => entries
            .iter()
            .all(|(key, item)| numeric_v2::wire_dict_key(key).is_ok() && v2_returnable(item)),
        _ => true,
    }
}

/// The hash of a usable registry entry, or why it is not one, in the
/// order the Python checks refuse it.
fn usable_hash(
    scheme: &Option<VmValue>,
    curve: &Option<VmValue>,
    active: &Option<VmValue>,
    vk_hash: Option<VmValue>,
) -> Result<String, &'static str> {
    let is_text = |value: &Option<VmValue>, expected: &str| matches!(value, Some(VmValue::String(text)) if text == expected);
    if !is_text(scheme, "groth16") {
        return Err("must use Groth16!");
    }
    if !is_text(curve, "bn254") {
        return Err("must use BN254!");
    }
    if !matches!(active, Some(VmValue::Bool(true))) {
        return Err("is inactive!");
    }
    match vk_hash {
        Some(VmValue::String(hash)) if !hash.is_empty() => Ok(hash),
        _ => Err("is missing vk_hash!"),
    }
}

fn text(value: &str) -> VmValue {
    VmValue::String(value.to_owned())
}

impl BlockHost<'_> {
    /// `_registry_field`: a field of `vk_id`'s registry entry, as the Python
    /// path's driver reads it (`None` when missing or null).
    fn registry_field(
        &mut self,
        vk_id: &str,
        field: &str,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        match self
            .view
            .get(&format!("zk_registry.verifying_keys:{vk_id}:{field}"))
        {
            Ok(value) => Ok(value.filter(|value| !matches!(value, VmValue::None))),
            Err(error) => Err(self.halt(fault(error))),
        }
    }

    /// `_registered_vk_record`: a known, active Groth16 BN254 key with a
    /// hash and well-formed bytes.
    fn registered_key(&mut self, vk_id: &VmValue) -> Result<RegisteredKey, VmExecutionError> {
        let vk_id = checks::vk_id(vk_id)?;
        let Some(vk_hex) = self.registry_field(vk_id, "vk_hex")? else {
            return Err(assertion(format!("Unknown verifying key id '{vk_id}'!")));
        };
        let scheme = self.registry_field(vk_id, "scheme")?;
        let curve = self.registry_field(vk_id, "curve")?;
        let vk_hash = self.registry_field(vk_id, "vk_hash")?;
        let active = self.registry_field(vk_id, "active")?;
        let vk_hash = usable_hash(&scheme, &curve, &active, vk_hash)
            .map_err(|refusal| assertion(format!("Verifying key '{vk_id}' {refusal}")))?;
        let vk_hex = hex("registered vk_hex", &vk_hex, MAX_VK_HEX_CHARS)?.to_owned();
        Ok(RegisteredKey {
            vk_id: vk_id.to_owned(),
            vk_hash,
            vk_hex,
        })
    }

    /// One `warm_verified_proofs` request checked, with its key read.
    fn warm_request(
        &mut self,
        index: usize,
        request: &VmValue,
    ) -> Result<RegisteredProof, VmExecutionError> {
        let Py::Dict(entries) = py(request) else {
            return Err(assertion(format!("requests[{index}] must be a dict!")));
        };
        let vk_id = request_item(entries, "vk_id");
        checks::vk_id(vk_id)?;
        let name = format!("requests[{index}].proof_hex");
        let proof_hex = hex(
            &name,
            request_item(entries, "proof_hex"),
            MAX_PROOF_HEX_CHARS,
        )?;
        let public_inputs = public_inputs(request_item(entries, "public_inputs"))?;
        Ok(RegisteredProof {
            key: self.registered_key(vk_id)?,
            proof_hex: proof_hex.to_owned(),
            public_inputs,
        })
    }
}
