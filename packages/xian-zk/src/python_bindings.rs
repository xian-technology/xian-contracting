use crate::core::{
    prepare_groth16_bn254_vk as prepare_impl,
    verify_groth16_bn254 as verify_impl,
    verify_groth16_bn254_prepared as verify_prepared_impl,
    PreparedGroth16Bn254Key as CorePreparedGroth16Bn254Key,
    VerifierError,
};
use pyo3::create_exception;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

create_exception!(xian_zk, ZkEncodingError, PyValueError);
create_exception!(xian_zk, ZkVerifierError, PyValueError);

fn to_pyerr(error: VerifierError) -> PyErr {
    match error {
        VerifierError::Encoding(message) => ZkEncodingError::new_err(message),
        VerifierError::Verification(message) => {
            ZkVerifierError::new_err(message)
        }
    }
}

#[pyclass(unsendable)]
struct PreparedGroth16Bn254Key {
    inner: CorePreparedGroth16Bn254Key,
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
    verify_prepared_impl(&prepared.inner, proof_hex, &public_inputs)
        .map_err(to_pyerr)
}

#[pymodule]
fn _native(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PreparedGroth16Bn254Key>()?;
    module.add_function(wrap_pyfunction!(prepare_groth16_bn254_vk, module)?)?;
    module.add_function(wrap_pyfunction!(verify_groth16_bn254, module)?)?;
    module.add_function(wrap_pyfunction!(
        verify_groth16_bn254_prepared,
        module
    )?)?;
    module.add("ZkEncodingError", py.get_type::<ZkEncodingError>())?;
    module.add("ZkVerifierError", py.get_type::<ZkVerifierError>())?;
    Ok(())
}
