use crate::core::{verify_groth16_bn254 as verify_impl, VerifierError};
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

#[pyfunction]
fn verify_groth16_bn254(
    vk_hex: &str,
    proof_hex: &str,
    public_inputs: Vec<String>,
) -> PyResult<bool> {
    verify_impl(vk_hex, proof_hex, &public_inputs).map_err(to_pyerr)
}

#[pymodule]
fn _native(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(verify_groth16_bn254, module)?)?;
    module.add("ZkEncodingError", py.get_type::<ZkEncodingError>())?;
    module.add("ZkVerifierError", py.get_type::<ZkVerifierError>())?;
    Ok(())
}
