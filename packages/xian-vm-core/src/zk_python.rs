//! The zk primitives for the Python host (`contracting.stdlib.bridge.zk`),
//! served by the `xian-zk` crate this module links, so the Python path and
//! the block host verify with one library and share the node's proof caches
//! (`zk_cache`). The node's proof pre-verification fills them through
//! `zk_warm_registered`. Signatures, results and exceptions are those of
//! `xian_zk._native`, whose functions the bridge used before.
use super::{exception_to_py, py_to_vm};
use crate::block_host::{zk, BlockHost, HostCharges, Modules, TxInputs};
use crate::block_state_python::PyBlockState;
use crate::interpreter::numeric_v2;
use crate::lmdb_python::PyLmdbEnvironment;
use crate::settlement::Stop;
use crate::state_view::StateView;
use crate::zk_cache::{self, RegisteredKey, RegisteredProof};
use crate::{VmBudget, VmValue, XIAN_VM_V2_PROFILE};
use pyo3::create_exception;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyList, PyModule};
use std::error::Error;
use xian_zk::VerifierError;

create_exception!(xian_vm_core, ZkEncodingError, PyValueError);
create_exception!(xian_vm_core, ZkVerifierError, PyValueError);

fn verifier_error(error: VerifierError) -> PyErr {
    match error {
        VerifierError::Encoding(message) => ZkEncodingError::new_err(message),
        VerifierError::Verification(message) => ZkVerifierError::new_err(message),
    }
}

fn helper_error(error: Box<dyn Error>) -> PyErr {
    PyValueError::new_err(error.to_string())
}

/// A proof of a registered key: id, hash, key bytes, proof and inputs.
type Registered = (String, String, String, String, Vec<String>);

fn registered((vk_id, vk_hash, vk_hex, proof_hex, public_inputs): Registered) -> RegisteredProof {
    RegisteredProof {
        key: RegisteredKey {
            vk_id,
            vk_hash,
            vk_hex,
        },
        proof_hex,
        public_inputs,
    }
}

#[pyfunction]
fn zk_verify_groth16_bn254(
    vk_hex: &str,
    proof_hex: &str,
    public_inputs: Vec<String>,
) -> PyResult<bool> {
    xian_zk::verify_groth16_bn254(vk_hex, proof_hex, &public_inputs).map_err(verifier_error)
}

/// A proof against a registered key, through the node's proof caches.
#[pyfunction]
fn zk_verify_registered(
    vk_id: String,
    vk_hash: String,
    vk_hex: String,
    proof_hex: String,
    public_inputs: Vec<String>,
) -> PyResult<bool> {
    let proof = registered((vk_id, vk_hash, vk_hex, proof_hex, public_inputs));
    zk_cache::verify_registered(&proof).map_err(verifier_error)
}

/// Proofs against registered keys verified into the node's proof cache.
#[pyfunction]
fn zk_warm_registered(proofs: Vec<Registered>) -> PyResult<Vec<bool>> {
    let proofs: Vec<RegisteredProof> = proofs.into_iter().map(registered).collect();
    zk_cache::warm(&proofs).map_err(verifier_error)
}

#[pyfunction]
fn zk_clear_prepared_vk_cache() {
    zk_cache::clear_prepared();
}

#[pyfunction]
fn zk_clear_verified_proof_cache() {
    zk_cache::clear_verified();
}

#[pyfunction]
fn zk_shielded_note_append_tree_state_json(
    note_count: usize,
    filled_subtrees: Vec<String>,
    commitments: Vec<String>,
) -> PyResult<String> {
    let state =
        xian_zk::shielded_note_append_tree_state(note_count, &filled_subtrees, &commitments)
            .map_err(helper_error)?;
    serde_json::to_string(&state).map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn zk_shielded_command_nullifier_digest(input_nullifier_hexes: Vec<String>) -> PyResult<String> {
    xian_zk::shielded_command_nullifier_digest_hex(&input_nullifier_hexes).map_err(helper_error)
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn zk_shielded_command_binding(
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
) -> PyResult<String> {
    xian_zk::shielded_command_binding_hex(
        nullifier_digest_hex,
        target_digest_hex,
        payload_digest_hex,
        relayer_digest_hex,
        expiry_digest_hex,
        chain_digest_hex,
        entrypoint_digest_hex,
        version_digest_hex,
        fee,
        public_amount,
    )
    .map_err(helper_error)
}

#[pyfunction]
fn zk_shielded_command_execution_tag(
    nullifier_digest_hex: &str,
    command_binding_hex_value: &str,
) -> PyResult<String> {
    xian_zk::shielded_command_execution_tag_hex(nullifier_digest_hex, command_binding_hex_value)
        .map_err(helper_error)
}

#[pyfunction]
fn zk_shielded_output_payload_hash(payload_hex: &str) -> String {
    xian_zk::shielded_output_payload_hash_hex(payload_hex)
}

#[pyfunction]
fn zk_shielded_output_payload_hashes(payload_hexes: Vec<String>) -> Vec<String> {
    xian_zk::shielded_output_payload_hash_hexes(&payload_hexes)
}

#[pyfunction]
fn zk_shielded_deposit_public_inputs(
    contract_name: &str,
    old_root_hex: &str,
    amount: u64,
    commitments: Vec<String>,
    payload_hashes: Vec<String>,
) -> PyResult<Vec<String>> {
    xian_zk::shielded_deposit_public_inputs_hex(
        contract_name,
        old_root_hex,
        amount,
        &commitments,
        &payload_hashes,
    )
    .map_err(helper_error)
}

#[pyfunction]
fn zk_shielded_transfer_public_inputs(
    contract_name: &str,
    old_root_hex: &str,
    input_nullifiers: Vec<String>,
    commitments: Vec<String>,
    payload_hashes: Vec<String>,
) -> PyResult<Vec<String>> {
    xian_zk::shielded_transfer_public_inputs_hex(
        contract_name,
        old_root_hex,
        &input_nullifiers,
        &commitments,
        &payload_hashes,
    )
    .map_err(helper_error)
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn zk_shielded_withdraw_public_inputs(
    contract_name: &str,
    old_root_hex: &str,
    amount: u64,
    recipient: &str,
    input_nullifiers: Vec<String>,
    commitments: Vec<String>,
    payload_hashes: Vec<String>,
) -> PyResult<Vec<String>> {
    xian_zk::shielded_withdraw_public_inputs_hex(
        contract_name,
        old_root_hex,
        amount,
        recipient,
        &input_nullifiers,
        &commitments,
        &payload_hashes,
    )
    .map_err(helper_error)
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
fn zk_shielded_command_public_inputs(
    contract_name: &str,
    old_root_hex: &str,
    command_binding_hex_value: &str,
    execution_tag_hex_value: &str,
    fee: u64,
    public_amount: u64,
    input_nullifiers: Vec<String>,
    commitments: Vec<String>,
    payload_hashes: Vec<String>,
) -> PyResult<Vec<String>> {
    xian_zk::shielded_command_public_inputs_hex(
        contract_name,
        old_root_hex,
        command_binding_hex_value,
        execution_tag_hex_value,
        fee,
        public_amount,
        &input_nullifiers,
        &commitments,
        &payload_hashes,
    )
    .map_err(helper_error)
}

/// Parity hook: zk syscalls (`(syscall id, [args])`, as the VM passes them)
/// served by the block host over the node's LMDB environment and block
/// overlay, at the V2 VM boundary. Each outcome is `("ok", value)` with the
/// value's `Debug` rendering, `("raised", text, exception)` with
/// `exception` as `(type name, [args])` or `None`, or `("fault", reason)`.
#[pyfunction]
fn _zk_syscalls_debug(
    py: Python<'_>,
    environment: PyRef<'_, PyLmdbEnvironment>,
    overlay: PyRef<'_, PyBlockState>,
    calls: Vec<(String, Bound<'_, PyList>)>,
) -> PyResult<Vec<Py<PyAny>>> {
    let _scope = numeric_v2::Scope::enter(XIAN_VM_V2_PROFILE);
    let view = StateView::new(environment.env().clone(), overlay.shared());
    let modules = Modules::default();
    let mut outcomes = Vec::with_capacity(calls.len());
    for (syscall_id, args) in calls {
        let args = args
            .iter()
            .map(|value| py_to_vm(value).map_err(|error| PyValueError::new_err(error.to_string())))
            .collect::<PyResult<Vec<VmValue>>>()?;
        let charges = HostCharges::new(VmBudget::new(0, XIAN_VM_V2_PROFILE), false, "");
        let inputs = TxInputs {
            context: Default::default(),
            zk_enabled_without_state: true,
        };
        let mut host = BlockHost::new(view.clone(), &modules, charges, inputs);
        let served = zk::call(&mut host, &syscall_id, &args, &[])
            .ok_or_else(|| PyValueError::new_err(format!("{syscall_id} is not a zk syscall")))?;
        outcomes.push(outcome(py, served, host.finish().err())?);
    }
    Ok(outcomes)
}

fn outcome(
    py: Python<'_>,
    served: Result<VmValue, crate::VmExecutionError>,
    stop: Option<Stop>,
) -> PyResult<Py<PyAny>> {
    let outcome = match (served, stop) {
        (_, Some(Stop::Fault(reason))) => ("fault", reason),
        (Ok(value), None) => ("ok", format!("{value:?}")),
        (Err(error), None) => {
            let exception = exception_to_py(py, error.exception())?;
            let raised = ("raised", error.to_string(), exception).into_pyobject(py)?;
            return Ok(raised.into_any().unbind());
        }
    };
    Ok(outcome.into_pyobject(py)?.into_any().unbind())
}

pub(super) fn register(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("ZkEncodingError", py.get_type::<ZkEncodingError>())?;
    module.add("ZkVerifierError", py.get_type::<ZkVerifierError>())?;
    let functions = [
        wrap_pyfunction!(zk_verify_groth16_bn254, module),
        wrap_pyfunction!(zk_verify_registered, module),
        wrap_pyfunction!(zk_warm_registered, module),
        wrap_pyfunction!(zk_clear_prepared_vk_cache, module),
        wrap_pyfunction!(zk_clear_verified_proof_cache, module),
        wrap_pyfunction!(zk_shielded_note_append_tree_state_json, module),
        wrap_pyfunction!(zk_shielded_command_nullifier_digest, module),
        wrap_pyfunction!(zk_shielded_command_binding, module),
        wrap_pyfunction!(zk_shielded_command_execution_tag, module),
        wrap_pyfunction!(zk_shielded_output_payload_hash, module),
        wrap_pyfunction!(zk_shielded_output_payload_hashes, module),
        wrap_pyfunction!(zk_shielded_deposit_public_inputs, module),
        wrap_pyfunction!(zk_shielded_transfer_public_inputs, module),
        wrap_pyfunction!(zk_shielded_withdraw_public_inputs, module),
        wrap_pyfunction!(zk_shielded_command_public_inputs, module),
        wrap_pyfunction!(_zk_syscalls_debug, module),
    ];
    for function in functions {
        module.add_function(function?)?;
    }
    Ok(())
}
