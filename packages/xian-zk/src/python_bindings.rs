use crate::core::{
    prepare_groth16_bn254_vk as prepare_impl, verify_groth16_bn254 as verify_impl,
    verify_groth16_bn254_prepared as verify_prepared_impl,
    PreparedGroth16Bn254Key as CorePreparedGroth16Bn254Key, VerifierError,
};
use crate::shielded_notes::{
    build_insecure_dev_shielded_note_bundle as build_dev_bundle_impl,
    prove_shielded_deposit as prove_deposit_impl, prove_shielded_transfer as prove_transfer_impl,
    prove_shielded_withdraw as prove_withdraw_impl, shielded_note_asset_id_hex,
    shielded_note_commitment_hex, shielded_note_nullifier_hex, shielded_note_recipient_digest_hex,
    shielded_note_root_hex, shielded_note_zero_root_hex, ShieldedDepositRequest,
    ShieldedProverBundle as CoreShieldedProverBundle, ShieldedTransferRequest,
    ShieldedWithdrawRequest,
};
use pyo3::create_exception;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

create_exception!(xian_zk, ZkEncodingError, PyValueError);
create_exception!(xian_zk, ZkVerifierError, PyValueError);

fn to_pyerr(error: VerifierError) -> PyErr {
    match error {
        VerifierError::Encoding(message) => ZkEncodingError::new_err(message),
        VerifierError::Verification(message) => ZkVerifierError::new_err(message),
    }
}

#[pyclass(unsendable)]
struct PreparedGroth16Bn254Key {
    inner: CorePreparedGroth16Bn254Key,
}

#[pyclass(unsendable)]
struct ShieldedNoteProverBundle {
    inner: CoreShieldedProverBundle,
}

#[pyfunction]
fn prepare_groth16_bn254_vk(vk_hex: &str) -> PyResult<PreparedGroth16Bn254Key> {
    prepare_impl(vk_hex)
        .map(|inner| PreparedGroth16Bn254Key { inner })
        .map_err(to_pyerr)
}

#[pyfunction]
fn verify_groth16_bn254(
    vk_hex: &str,
    proof_hex: &str,
    public_inputs: Vec<String>,
) -> PyResult<bool> {
    verify_impl(vk_hex, proof_hex, &public_inputs).map_err(to_pyerr)
}

#[pyfunction]
fn verify_groth16_bn254_prepared(
    prepared: &PreparedGroth16Bn254Key,
    proof_hex: &str,
    public_inputs: Vec<String>,
) -> PyResult<bool> {
    verify_prepared_impl(&prepared.inner, proof_hex, &public_inputs).map_err(to_pyerr)
}

#[pyfunction]
fn build_insecure_dev_shielded_note_bundle_json() -> PyResult<String> {
    serde_json::to_string_pretty(
        &build_dev_bundle_impl().map_err(|error| PyValueError::new_err(error.to_string()))?,
    )
    .map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn load_shielded_note_prover_bundle(bundle_json: &str) -> PyResult<ShieldedNoteProverBundle> {
    let inner: CoreShieldedProverBundle = serde_json::from_str(bundle_json)
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    Ok(ShieldedNoteProverBundle { inner })
}

#[pyfunction]
fn shielded_note_zero_root() -> String {
    shielded_note_zero_root_hex()
}

#[pyfunction]
fn shielded_note_asset_id(contract_name: &str) -> String {
    shielded_note_asset_id_hex(contract_name)
}

#[pyfunction]
fn shielded_note_recipient_digest(recipient: &str) -> String {
    shielded_note_recipient_digest_hex(recipient)
}

#[pyfunction]
fn shielded_note_note_commitment(
    asset_id_hex: &str,
    owner_secret_hex: &str,
    amount: u64,
    rho_hex: &str,
    blind_hex: &str,
) -> PyResult<String> {
    shielded_note_commitment_hex(asset_id_hex, owner_secret_hex, amount, rho_hex, blind_hex)
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn shielded_note_nullifier(
    asset_id_hex: &str,
    owner_secret_hex: &str,
    rho_hex: &str,
) -> PyResult<String> {
    shielded_note_nullifier_hex(asset_id_hex, owner_secret_hex, rho_hex)
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn shielded_note_root(commitments: Vec<String>) -> PyResult<String> {
    shielded_note_root_hex(&commitments).map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn prove_shielded_note_deposit(
    bundle: &ShieldedNoteProverBundle,
    request_json: &str,
) -> PyResult<String> {
    let request: ShieldedDepositRequest = serde_json::from_str(request_json)
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    let result = prove_deposit_impl(&bundle.inner, &request)
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    serde_json::to_string_pretty(&result).map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn prove_shielded_note_transfer(
    bundle: &ShieldedNoteProverBundle,
    request_json: &str,
) -> PyResult<String> {
    let request: ShieldedTransferRequest = serde_json::from_str(request_json)
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    let result = prove_transfer_impl(&bundle.inner, &request)
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    serde_json::to_string_pretty(&result).map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn prove_shielded_note_withdraw(
    bundle: &ShieldedNoteProverBundle,
    request_json: &str,
) -> PyResult<String> {
    let request: ShieldedWithdrawRequest = serde_json::from_str(request_json)
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    let result = prove_withdraw_impl(&bundle.inner, &request)
        .map_err(|error| PyValueError::new_err(error.to_string()))?;
    serde_json::to_string_pretty(&result).map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pymodule]
fn _native(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PreparedGroth16Bn254Key>()?;
    module.add_class::<ShieldedNoteProverBundle>()?;
    module.add_function(wrap_pyfunction!(prepare_groth16_bn254_vk, module)?)?;
    module.add_function(wrap_pyfunction!(verify_groth16_bn254, module)?)?;
    module.add_function(wrap_pyfunction!(verify_groth16_bn254_prepared, module)?)?;
    module.add_function(wrap_pyfunction!(
        build_insecure_dev_shielded_note_bundle_json,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(load_shielded_note_prover_bundle, module)?)?;
    module.add_function(wrap_pyfunction!(shielded_note_zero_root, module)?)?;
    module.add_function(wrap_pyfunction!(shielded_note_asset_id, module)?)?;
    module.add_function(wrap_pyfunction!(shielded_note_recipient_digest, module)?)?;
    module.add_function(wrap_pyfunction!(shielded_note_note_commitment, module)?)?;
    module.add_function(wrap_pyfunction!(shielded_note_nullifier, module)?)?;
    module.add_function(wrap_pyfunction!(shielded_note_root, module)?)?;
    module.add_function(wrap_pyfunction!(prove_shielded_note_deposit, module)?)?;
    module.add_function(wrap_pyfunction!(prove_shielded_note_transfer, module)?)?;
    module.add_function(wrap_pyfunction!(prove_shielded_note_withdraw, module)?)?;
    module.add("ZkEncodingError", py.get_type::<ZkEncodingError>())?;
    module.add("ZkVerifierError", py.get_type::<ZkVerifierError>())?;
    Ok(())
}
