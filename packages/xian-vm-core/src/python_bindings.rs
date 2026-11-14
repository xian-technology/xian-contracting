use crate::interpreter::numeric_v2;
#[path = "block_executor_python.rs"]
mod block_executor_python;
#[path = "random_python.rs"]
mod random_python;
#[path = "settlement_python.rs"]
mod settlement_python;
#[path = "single_tx_python.rs"]
mod single_tx_python;
#[path = "transaction_admission_python.rs"]
mod transaction_admission_python;
#[path = "transaction_inputs_python.rs"]
mod transaction_inputs_python;
#[path = "zk_python.rs"]
mod zk_python;
use crate::XIAN_VM_V2_PROFILE;
use crate::{
    parse_module_ir, VmDateTime, VmDecimal, VmExecutionContext, VmExecutionError, VmTimeDelta,
    VmValue, XIAN_IR_V1, XIAN_VM_EXECUTION_REVISION, XIAN_VM_HOST_CATALOG_V1, XIAN_VM_SET_CODEC,
    XIAN_VM_SUPPORTED_BYTECODE_VERSIONS, XIAN_VM_SUPPORTED_GAS_SCHEDULES,
};
use num_bigint::BigInt;
use pyo3::create_exception;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyByteArray, PyBytes, PyDict, PyList, PyModule, PyTuple};
use serde_json::json;
use std::str::FromStr;

create_exception!(xian_vm_core, VmIrValidationError, PyValueError);
create_exception!(xian_vm_core, VmRuntimeExecutionError, PyValueError);

/// A Python error met while converting a value at the boundary.
fn host_error(error: PyErr) -> VmExecutionError {
    VmExecutionError::new(error.to_string())
}

/// `(type name, [arguments])` for a structured failure. An argument that cannot
/// cross the boundary as a value is passed as its representation.
fn exception_to_py(py: Python<'_>, exception: Option<&crate::VmException>) -> PyResult<Py<PyAny>> {
    let Some(exception) = exception else {
        return Ok(py.None());
    };
    let args = PyList::empty(py);
    for arg in &exception.args {
        match vm_to_py(py, arg) {
            Ok(value) => args.append(value)?,
            Err(_) => args.append(arg.python_repr())?,
        }
    }
    Ok((exception.name.as_str(), args)
        .into_pyobject(py)?
        .into_any()
        .unbind())
}

pub(crate) fn py_to_vm(value: Bound<'_, PyAny>) -> Result<VmValue, VmExecutionError> {
    if value.is_none() {
        return Ok(VmValue::None);
    }
    let type_name = python_type_name(&value);
    if numeric_v2::active() && matches!(type_name.as_str(), "float" | "Decimal" | "DecimalTuple") {
        return Err(VmExecutionError::new(
            "binary float and raw Decimal are unavailable in xian_vm_v2",
        ));
    }
    if let Ok(boolean) = value.extract::<bool>() {
        if type_name == "bool" {
            return Ok(VmValue::Bool(boolean));
        }
    }
    if value.is_instance_of::<PyList>() {
        let values = value
            .cast::<PyList>()
            .map_err(|error| VmExecutionError::new(error.to_string()))?
            .iter()
            .map(py_to_vm)
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(VmValue::List(values));
    }
    if python_class_path(&value)
        .is_some_and(|(module, name)| module == "decimal" && name == "DecimalTuple")
    {
        return py_decimal_tuple_to_vm(&value);
    }
    if value.is_instance_of::<PyTuple>() {
        let values = value
            .cast::<PyTuple>()
            .map_err(|error| VmExecutionError::new(error.to_string()))?
            .iter()
            .map(py_to_vm)
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(VmValue::Tuple(values));
    }
    if value.is_instance_of::<PyDict>() {
        let dict = value
            .cast::<PyDict>()
            .map_err(|error| VmExecutionError::new(error.to_string()))?;
        let mut entries = Vec::new();
        for (key, item) in dict.iter() {
            let key = py_to_vm(key)?;
            if numeric_v2::active() {
                numeric_v2::wire_dict_key(&key)?;
            }
            entries.push((key, py_to_vm(item)?));
        }
        return Ok(VmValue::Dict(entries));
    }
    if value.is_instance_of::<PyBytes>() {
        let bytes = value
            .cast::<PyBytes>()
            .map_err(|error| VmExecutionError::new(error.to_string()))?;
        return Ok(VmValue::Bytes(bytes.as_bytes().to_vec()));
    }
    if value.is_instance_of::<PyByteArray>() {
        let bytes = value
            .cast::<PyByteArray>()
            .map_err(|error| VmExecutionError::new(error.to_string()))?;
        return Ok(VmValue::ByteArray(bytes.to_vec()));
    }
    if let Some((module, name)) = python_class_path(&value) {
        match (module.as_str(), name.as_str()) {
            ("xian_runtime_types.collections", "ContractingSet") => {
                let values = value
                    .try_iter()
                    .map_err(host_error)?
                    .map(|item| item.map_err(host_error).and_then(py_to_vm))
                    .collect::<Result<Vec<_>, _>>()?;
                return Ok(VmValue::Set(values));
            }
            ("xian_runtime_types.collections", "ContractingFrozenSet") => {
                let values = value
                    .try_iter()
                    .map_err(host_error)?
                    .map(|item| item.map_err(host_error).and_then(py_to_vm))
                    .collect::<Result<Vec<_>, _>>()?;
                return Ok(VmValue::FrozenSet(values));
            }
            ("decimal", "Decimal") => {
                return Ok(VmValue::RawDecimal(crate::VmRawDecimal::parse(
                    value
                        .str()
                        .map_err(host_error)?
                        .to_str()
                        .map_err(host_error)?,
                )?));
            }
            ("xian_runtime_types.decimal", "ContractingDecimal") => {
                let rendered = value.str().map_err(host_error)?;
                let text = rendered.to_str().map_err(host_error)?;
                return Ok(VmValue::Decimal(if numeric_v2::active() {
                    numeric_v2::exact_decimal(text)?
                } else {
                    VmDecimal::from_str_literal(text)?
                }));
            }
            ("xian_runtime_types.time", "Datetime") | ("datetime", "datetime") => {
                return Ok(VmValue::DateTime(VmDateTime::new(
                    extract_i64_attr(&value, "year")?,
                    extract_i64_attr(&value, "month")?,
                    extract_i64_attr(&value, "day")?,
                    extract_i64_attr(&value, "hour")?,
                    extract_i64_attr(&value, "minute")?,
                    extract_i64_attr(&value, "second")?,
                    extract_i64_attr(&value, "microsecond")?,
                )?));
            }
            ("xian_runtime_types.time", "Timedelta") | ("datetime", "timedelta") => {
                if let Ok(seconds) = extract_i64_attr(&value, "seconds") {
                    return Ok(VmValue::TimeDelta(VmTimeDelta::from_raw_seconds(seconds)?));
                }
            }
            _ => {}
        }
    }
    if let Ok(number) = value.extract::<f64>() {
        if type_name == "float" {
            return Ok(VmValue::Float(number));
        }
    }
    if type_name == "int" {
        if numeric_v2::active()
            && value
                .call_method0("bit_length")
                .and_then(|n| n.extract::<u64>())
                .map_err(host_error)?
                > xian_numeric::INTEGER_BITS
        {
            return Err(VmExecutionError::new(
                "integer exceeds the 512-bit magnitude limit",
            ));
        }
        let rendered = value
            .str()
            .map_err(host_error)?
            .to_str()
            .map_err(host_error)?
            .to_owned();
        return Ok(VmValue::Int(
            BigInt::from_str(&rendered)
                .map_err(|error| VmExecutionError::new(error.to_string()))?,
        ));
    }
    if let Ok(string_value) = value.extract::<String>() {
        return Ok(VmValue::String(string_value));
    }
    Err(VmExecutionError::new(format!(
        "unsupported Python value at VM boundary: {}",
        type_name
    )))
}

fn py_decimal_tuple_to_vm(value: &Bound<'_, PyAny>) -> Result<VmValue, VmExecutionError> {
    let components = (|| -> PyResult<(u8, Vec<u8>, Bound<'_, PyAny>)> {
        Ok((
            value.getattr("sign")?.extract()?,
            value.getattr("digits")?.extract()?,
            value.getattr("exponent")?,
        ))
    })()
    .map_err(host_error)?;
    let (sign, digits, exponent) = components;
    if sign > 1 {
        return Err(VmExecutionError::new("DecimalTuple sign must be 0 or 1"));
    }
    let (finite, special) = if let Ok(number) = exponent.extract::<i32>() {
        (Some(number), None)
    } else {
        let marker = exponent.extract::<char>().map_err(host_error)?;
        (None, Some(marker))
    };
    Ok(VmValue::DecimalTuple(crate::VmDecimalTuple::from_parts(
        sign == 1,
        digits,
        finite,
        special,
    )?))
}

fn bigint_to_py(py: Python<'_>, value: &BigInt) -> PyResult<Py<PyAny>> {
    Ok(PyModule::import(py, "builtins")?
        .getattr("int")?
        .call1((value.to_string(),))?
        .unbind())
}

fn vm_to_py(py: Python<'_>, value: &VmValue) -> PyResult<Py<PyAny>> {
    match value {
        VmValue::Reference(_) => vm_to_py(
            py,
            &value
                .detached()
                .map_err(|e| VmRuntimeExecutionError::new_err(e.to_string()))?,
        ),
        VmValue::Iterator(_) | VmValue::Range(_) | VmValue::View(_) => {
            Err(VmRuntimeExecutionError::new_err(
                "iterators and ranges cannot cross the VM boundary; materialize them first",
            ))
        }
        VmValue::None => Ok(py.None()),
        VmValue::Bool(value) => Ok((*value).into_pyobject(py)?.to_owned().into_any().unbind()),
        VmValue::Int(value) => bigint_to_py(py, value),
        VmValue::Float(value) => Ok(value.into_pyobject(py)?.into_any().unbind()),
        VmValue::RawDecimal(value) => Ok(PyModule::import(py, "decimal")?
            .getattr("Decimal")?
            .call1((value.to_string(),))?
            .unbind()),
        VmValue::Decimal(value) => {
            let module = PyModule::import(py, "xian_runtime_types.decimal")?;
            Ok(module
                .getattr("ContractingDecimal")?
                .call_method1("_from_scaled", (bigint_to_py(py, &value.scaled)?,))?
                .unbind())
        }
        VmValue::DateTime(value) => {
            let module = PyModule::import(py, "xian_runtime_types.time")?;
            let kwargs = PyDict::new(py);
            kwargs.set_item("microsecond", value.microsecond())?;
            Ok(module
                .getattr("Datetime")?
                .call(
                    (
                        value.year(),
                        value.month(),
                        value.day(),
                        value.hour(),
                        value.minute(),
                        value.second(),
                    ),
                    Some(&kwargs),
                )?
                .unbind())
        }
        VmValue::TimeDelta(value) => {
            let module = PyModule::import(py, "xian_runtime_types.time")?;
            let kwargs = PyDict::new(py);
            kwargs.set_item("seconds", value.seconds())?;
            Ok(module
                .getattr("Timedelta")?
                .call((), Some(&kwargs))?
                .unbind())
        }
        VmValue::String(value) => Ok(value.clone().into_pyobject(py)?.into_any().unbind()),
        VmValue::Bytes(value) => Ok(PyBytes::new(py, value).into_any().unbind()),
        VmValue::ByteArray(value) => Ok(PyByteArray::new(py, value).into_any().unbind()),
        VmValue::BuiltinSet(_) => Err(PyValueError::new_err(
            "builtin sets cannot cross the VM boundary; convert with set() first",
        )),
        VmValue::Set(values) => set_to_py(py, "ContractingSet", values),
        VmValue::FrozenSet(values) => set_to_py(py, "ContractingFrozenSet", values),
        VmValue::List(values) => {
            let list = PyList::empty(py);
            for item in values {
                list.append(vm_to_py(py, item)?)?;
            }
            Ok(list.into_any().unbind())
        }
        VmValue::DecimalTuple(value) => {
            let fields = value
                .as_values()
                .iter()
                .map(|item| vm_to_py(py, item))
                .collect::<PyResult<Vec<_>>>()?;
            Ok(PyModule::import(py, "decimal")?
                .getattr("DecimalTuple")?
                .call1(PyTuple::new(py, fields)?)?
                .unbind())
        }
        VmValue::Tuple(values) => {
            let converted = values
                .iter()
                .map(|item| vm_to_py(py, item))
                .collect::<PyResult<Vec<_>>>()?;
            Ok(PyTuple::new(py, converted)?.into_any().unbind())
        }
        VmValue::Dict(entries) => {
            let dict = PyDict::new(py);
            for (key, value) in entries {
                dict.set_item(vm_to_py(py, key)?, vm_to_py(py, value)?)?;
            }
            Ok(dict.into_any().unbind())
        }
        VmValue::ContractHandle(handle) => {
            Ok(handle.module.clone().into_pyobject(py)?.into_any().unbind())
        }
        VmValue::TypeMarker(name) => Ok(name.clone().into_pyobject(py)?.into_any().unbind()),
        other => Err(PyTypeError::new_err(format!(
            "unsupported VM value at Python boundary: {}",
            format!("{other:?}")
        ))),
    }
}

/// A set as its `xian_runtime_types` class with V2 members (True and 1 stay
/// apart): every value crossing to Python is a V2 value, whatever numeric
/// scope the caller is in.
fn set_to_py(py: Python<'_>, class: &str, values: &[VmValue]) -> PyResult<Py<PyAny>> {
    let list = PyList::empty(py);
    for item in values {
        list.append(vm_to_py(py, item)?)?;
    }
    Ok(PyModule::import(py, "xian_runtime_types.collections")?
        .getattr(class)?
        .call_method1("_from_v2_members", (list,))?
        .unbind())
}

fn python_class_path(value: &Bound<'_, PyAny>) -> Option<(String, String)> {
    let class = value.getattr("__class__").ok()?;
    let module = class.getattr("__module__").ok()?.extract::<String>().ok()?;
    let name = class.getattr("__name__").ok()?.extract::<String>().ok()?;
    Some((module, name))
}

fn python_type_name(value: &Bound<'_, PyAny>) -> String {
    value
        .get_type()
        .name()
        .ok()
        .and_then(|name| name.extract::<String>().ok())
        .unwrap_or_else(|| "<unknown-python-type>".to_owned())
}

fn extract_i64_attr(value: &Bound<'_, PyAny>, attr: &str) -> Result<i64, VmExecutionError> {
    value
        .getattr(attr)
        .map_err(host_error)?
        .extract::<i64>()
        .map_err(host_error)
}

fn optional_string_item(
    dict: &Bound<'_, PyDict>,
    key: &str,
) -> Result<Option<String>, VmExecutionError> {
    let Some(value) = dict.get_item(key).map_err(host_error)? else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    value.extract::<String>().map(Some).map_err(host_error)
}

fn context_from_py(context: &Bound<'_, PyAny>) -> Result<VmExecutionContext, VmExecutionError> {
    let dict = context
        .cast::<PyDict>()
        .map_err(|error| VmExecutionError::new(error.to_string()))?;
    let this = optional_string_item(dict, "this")?;
    let caller = optional_string_item(dict, "caller")?;
    let signer = optional_string_item(dict, "signer")?;
    let owner = optional_string_item(dict, "owner")?;
    let submission_name = optional_string_item(dict, "submission_name")?;
    let entry = dict
        .get_item("entry")
        .map_err(host_error)?
        .map(|value| {
            if value.is_none() {
                return Ok(None);
            }
            let tuple = value
                .cast::<PyTuple>()
                .map_err(|error| VmExecutionError::new(error.to_string()))?;
            if tuple.len() != 2 {
                return Err(VmExecutionError::new("context.entry must be a 2-tuple"));
            }
            Ok(Some((
                tuple
                    .get_item(0)
                    .map_err(host_error)?
                    .extract::<String>()
                    .map_err(host_error)?,
                tuple
                    .get_item(1)
                    .map_err(host_error)?
                    .extract::<String>()
                    .map_err(host_error)?,
            )))
        })
        .transpose()?
        .flatten();
    let now = dict
        .get_item("now")
        .map_err(host_error)?
        .map(py_to_vm)
        .transpose()?
        .unwrap_or(VmValue::None);
    let block_num = dict
        .get_item("block_num")
        .map_err(host_error)?
        .map(py_to_vm)
        .transpose()?
        .unwrap_or(VmValue::Int(BigInt::from(-1)));
    let block_hash = dict
        .get_item("block_hash")
        .map_err(host_error)?
        .map(py_to_vm)
        .transpose()?
        .unwrap_or(VmValue::None);
    let chain_id = dict
        .get_item("chain_id")
        .map_err(host_error)?
        .map(py_to_vm)
        .transpose()?
        .unwrap_or(VmValue::None);
    let input_hash = dict
        .get_item("__input_hash")
        .map_err(host_error)?
        .map(py_to_vm)
        .transpose()?
        .unwrap_or(VmValue::None);

    Ok(VmExecutionContext {
        this,
        caller,
        signer,
        owner,
        entry,
        submission_name,
        now,
        block_num,
        block_hash,
        chain_id,
        input_hash,
    })
}

/// An event as the host's event dictionary.
fn event_to_py<'py>(py: Python<'py>, event: &crate::VmEvent) -> PyResult<Bound<'py, PyDict>> {
    let event_dict = PyDict::new(py);
    event_dict.set_item("contract", &event.contract)?;
    event_dict.set_item("event", &event.event)?;
    event_dict.set_item("signer", vm_to_py(py, &event.signer)?)?;
    event_dict.set_item("caller", vm_to_py(py, &event.caller)?)?;
    let data_indexed = PyDict::new(py);
    for (key, value) in &event.data_indexed {
        data_indexed.set_item(key, vm_to_py(py, value)?)?;
    }
    let data = PyDict::new(py);
    for (key, value) in &event.data {
        data.set_item(key, vm_to_py(py, value)?)?;
    }
    event_dict.set_item("data_indexed", data_indexed)?;
    event_dict.set_item("data", data)?;
    Ok(event_dict)
}

struct ProfilePolicy {
    bytecode: &'static [&'static str],
    gas: &'static [&'static str],
    revision: &'static str,
}

fn profile_policy(vm_profile: &str) -> Option<ProfilePolicy> {
    match vm_profile {
        XIAN_VM_V2_PROFILE => Some(ProfilePolicy {
            bytecode: XIAN_VM_SUPPORTED_BYTECODE_VERSIONS,
            gas: XIAN_VM_SUPPORTED_GAS_SCHEDULES,
            revision: XIAN_VM_EXECUTION_REVISION,
        }),
        _ => None,
    }
}

#[pyfunction(signature=(vm_profile="xian_vm_v2"))]
fn runtime_info_json(vm_profile: &str) -> PyResult<String> {
    let policy =
        profile_policy(vm_profile).ok_or_else(|| PyValueError::new_err("unknown VM profile"))?;
    serde_json::to_string(&json!({
        "ir_version": XIAN_IR_V1,
        "vm_profile": vm_profile,
        "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
        "supported_bytecode_versions": policy.bytecode,
        "supported_gas_schedules": policy.gas,
        "execution_revision": policy.revision,
        "max_tx_chi": crate::max_transaction_chi(vm_profile),
        "set_codec": XIAN_VM_SET_CODEC,
        "tx_admission_revision": xian_fastpath_core::ADMISSION_REVISION,
    }))
    .map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction(signature=(bytecode_version,gas_schedule,vm_profile="xian_vm_v2"))]
fn supports_execution_policy(bytecode_version: &str, gas_schedule: &str, vm_profile: &str) -> bool {
    profile_policy(vm_profile).is_some_and(|policy| {
        policy.bytecode.contains(&bytecode_version) && policy.gas.contains(&gas_schedule)
    })
}

/// Parity hook: the `VmValue` the Rust stored-value reader yields for `data`,
/// rendered with `Debug`. Raises `ValueError` for a value it rejects.
#[pyfunction]
fn _stored_value_debug(data: &[u8]) -> PyResult<String> {
    crate::stored_value::decode_stored_value(data)
        .map(|value| format!("{value:?}"))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Parity hook: the stored-value bytes Rust writes for the `VmValue` a Python
/// value becomes at the V2 VM boundary. Raises `ValueError` when refused.
#[pyfunction]
fn _stored_value_encode_debug(py: Python<'_>, value: Bound<'_, PyAny>) -> PyResult<Py<PyBytes>> {
    let _scope = numeric_v2::Scope::enter(XIAN_VM_V2_PROFILE);
    py_to_vm(value)
        .and_then(|value| crate::stored_value_encoder::encode_stored_value(&value))
        .map(|bytes| PyBytes::new(py, &bytes).unbind())
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Parity hook: stored-value bytes decoded and written again in Rust.
#[pyfunction]
fn _stored_value_reencode_debug(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    let _scope = numeric_v2::Scope::enter(XIAN_VM_V2_PROFILE);
    crate::stored_value::decode_stored_value(data)
        .and_then(|value| crate::stored_value_encoder::encode_stored_value(&value))
        .map(|bytes| PyBytes::new(py, &bytes).unbind())
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Parity hook: the `VmValue` a Python value becomes at the V2 VM boundary,
/// rendered with `Debug`. Raises `ValueError` for a value it rejects.
#[pyfunction]
fn _vm_value_debug(value: Bound<'_, PyAny>) -> PyResult<String> {
    let _scope = numeric_v2::Scope::enter(XIAN_VM_V2_PROFILE);
    py_to_vm(value)
        .map(|value| format!("{value:?}"))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn validate_module_ir_json(module_ir_json: &str) -> PyResult<()> {
    parse_module_ir(module_ir_json)
        .map(|_| ())
        .map_err(|error| VmIrValidationError::new_err(error.to_string()))
}

#[pyfunction(signature=(
    module_name,
    artifacts_json,
    *,
    input_source=None,
    vm_profile="xian_vm_v2"
))]
fn validate_deployment_artifacts_json(
    py: Python<'_>,
    module_name: &str,
    artifacts_json: &str,
    input_source: Option<&str>,
    vm_profile: &str,
) -> PyResult<Py<PyAny>> {
    let bundle = crate::validate_contract_artifacts_json(
        module_name,
        artifacts_json,
        input_source,
        vm_profile,
    )
    .map_err(|error| VmRuntimeExecutionError::new_err(error.to_string()))?;
    let payload = PyDict::new(py);
    payload.set_item("source", bundle.source)?;
    payload.set_item("vm_ir_json", bundle.vm_ir_json)?;
    Ok(payload.into_any().unbind())
}

#[pymodule]
fn _native(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("VmIrValidationError", py.get_type::<VmIrValidationError>())?;
    module.add(
        "VmRuntimeExecutionError",
        py.get_type::<VmRuntimeExecutionError>(),
    )?;
    module.add_function(wrap_pyfunction!(runtime_info_json, module)?)?;
    module.add_function(wrap_pyfunction!(supports_execution_policy, module)?)?;
    module.add_function(wrap_pyfunction!(validate_module_ir_json, module)?)?;
    module.add_function(wrap_pyfunction!(
        validate_deployment_artifacts_json,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(_stored_value_debug, module)?)?;
    module.add_function(wrap_pyfunction!(_vm_value_debug, module)?)?;
    module.add_function(wrap_pyfunction!(_stored_value_encode_debug, module)?)?;
    module.add_function(wrap_pyfunction!(_stored_value_reencode_debug, module)?)?;
    crate::lmdb_python::register(py, module)?;
    crate::block_state_python::register(module)?;
    settlement_python::register(module)?;
    block_executor_python::register(module)?;
    single_tx_python::register(module)?;
    random_python::register(module)?;
    transaction_admission_python::register(module)?;
    zk_python::register(py, module)?;
    module.add_function(wrap_pyfunction!(
        transaction_inputs_python::_transaction_inputs_debug,
        module
    )?)?;
    crate::state_root_python::register(module)?;
    Ok(())
}
