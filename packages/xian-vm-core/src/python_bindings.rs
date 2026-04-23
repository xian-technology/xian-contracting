use crate::{
    parse_module_ir, VmContractCall, VmContractTarget, VmDateTime, VmDecimal, VmEvent,
    VmExecutionContext, VmExecutionError, VmExecutionStats, VmHost, VmInstance, VmMeterConfig,
    VmTimeDelta, VmValue, VM_GAS_CROSS_CONTRACT_CALL_BASE, VM_GAS_CROSS_CONTRACT_CALL_REPEAT,
    XIAN_IR_V1, XIAN_VM_HOST_CATALOG_V1, XIAN_VM_SUPPORTED_BYTECODE_VERSIONS,
    XIAN_VM_SUPPORTED_GAS_SCHEDULES, XIAN_VM_V1_PROFILE,
};
use num_bigint::BigInt;
use pyo3::create_exception;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyByteArray, PyBytes, PyDict, PyList, PyModule, PyTuple};
use serde_json::{json, Value as JsonValue};
use std::collections::HashMap;
use std::str::FromStr;

create_exception!(xian_vm_core, VmIrValidationError, PyValueError);
create_exception!(xian_vm_core, VmRuntimeExecutionError, PyValueError);

struct PythonBundleExecutor {
    host: Py<PyAny>,
    modules: HashMap<String, crate::ModuleIr>,
    instances: HashMap<String, VmInstance>,
    events: Vec<VmEvent>,
    meter: crate::VmMeter,
    contract_call_count: u64,
}

impl PythonBundleExecutor {
    fn new(
        host: Py<PyAny>,
        bundle_ir_json: &str,
        meter_config: VmMeterConfig,
    ) -> Result<Self, VmExecutionError> {
        let parsed: JsonValue = serde_json::from_str(bundle_ir_json)
            .map_err(|error| VmExecutionError::new(error.to_string()))?;
        let object = parsed
            .as_object()
            .ok_or_else(|| VmExecutionError::new("bundle_ir_json must be a JSON object"))?;
        let mut modules = HashMap::new();
        for (module_name, module_value) in object {
            let module = parse_module_ir(
                &serde_json::to_string(module_value)
                    .map_err(|error| VmExecutionError::new(error.to_string()))?,
            )
            .map_err(|error| VmExecutionError::new(error.to_string()))?;
            modules.insert(module_name.clone(), module);
        }
        Ok(Self {
            host,
            modules,
            instances: HashMap::new(),
            events: Vec::new(),
            meter: crate::VmMeter::new(meter_config),
            contract_call_count: 0,
        })
    }

    fn execute_entry(
        &mut self,
        entry_module: &str,
        function_name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        context: VmExecutionContext,
    ) -> PyExecutionResult {
        let execution = (|| -> Result<VmValue, VmExecutionError> {
            self.meter.charge_transaction_bytes()?;
            self.meter
                .charge_execution_cost(crate::VM_GAS_CALL_DISPATCH)?;
            self.meter.begin_contract_metering(entry_module);
            let result = self.execute_call(entry_module, function_name, args, kwargs, context)?;
            self.meter.charge_return_value(&result)?;
            Ok(result)
        })();
        let contract_costs = self.meter.finalize_contracts(Some(entry_module));
        let stats = self.meter.execution_stats(contract_costs);
        match execution {
            Ok(result) => {
                let mut snapshots = self
                    .instances
                    .values()
                    .map(VmInstance::storage_snapshot)
                    .filter(|snapshot| {
                        !snapshot.variables.is_empty() || !snapshot.hashes.is_empty()
                    })
                    .collect::<Vec<_>>();
                snapshots.sort_by(|left, right| left.contract_name.cmp(&right.contract_name));
                PyExecutionResult {
                    status_code: 0,
                    result,
                    snapshots,
                    events: self.events.clone(),
                    stats,
                }
            }
            Err(error) => PyExecutionResult {
                status_code: 1,
                result: VmValue::String(error.to_string()),
                snapshots: Vec::new(),
                events: Vec::new(),
                stats,
            },
        }
    }

    fn execute_call(
        &mut self,
        module_name: &str,
        function_name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        mut context: VmExecutionContext,
    ) -> Result<VmValue, VmExecutionError> {
        self.ensure_module(module_name)?;
        if !self.instances.contains_key(module_name) {
            self.instantiate_module(module_name, &context)?;
        }
        let mut instance = self
            .instances
            .remove(module_name)
            .ok_or_else(|| VmExecutionError::new(format!("unknown module '{module_name}'")))?;
        let previous_context = instance.context().clone();
        context.this = Some(module_name.to_owned());
        if context.owner.is_none() {
            context.owner = self.load_owner(module_name)?;
        }
        *instance.context_mut() = context;
        let result = instance.call_function(self, function_name, args, kwargs);
        *instance.context_mut() = previous_context;
        self.instances.insert(module_name.to_owned(), instance);
        result
    }

    fn ensure_module(&mut self, module_name: &str) -> Result<(), VmExecutionError> {
        if self.modules.contains_key(module_name) {
            return Ok(());
        }
        let module_ir_json = Python::with_gil(|py| -> PyResult<Option<String>> {
            let host = self.host.bind(py);
            let response = host.call_method1("load_module_ir_json", (module_name,))?;
            if response.is_none() {
                Ok(None)
            } else {
                response.extract::<Option<String>>()
            }
        })
        .map_err(|error| VmExecutionError::new(error.to_string()))?;
        let Some(module_ir_json) = module_ir_json else {
            return Err(VmExecutionError::new(format!(
                "native VM could not load module '{module_name}'"
            )));
        };
        let module = parse_module_ir(&module_ir_json)
            .map_err(|error| VmExecutionError::new(error.to_string()))?;
        self.modules.insert(module_name.to_owned(), module);
        Ok(())
    }

    fn instantiate_module(
        &mut self,
        module_name: &str,
        context: &VmExecutionContext,
    ) -> Result<(), VmExecutionError> {
        let module = self
            .modules
            .get(module_name)
            .cloned()
            .ok_or_else(|| VmExecutionError::new(format!("unknown module '{module_name}'")))?;
        let mut instance_context = context.clone();
        instance_context.this = Some(module_name.to_owned());
        if instance_context.owner.is_none() {
            instance_context.owner = self.load_owner(module_name)?;
        }
        let instance = VmInstance::new_with_host(module, instance_context, self)?;
        self.instances.insert(module_name.to_owned(), instance);
        Ok(())
    }

    fn ensure_exported_function(
        &mut self,
        module_name: &str,
        function_name: &str,
    ) -> Result<(), VmExecutionError> {
        self.ensure_module(module_name)?;
        let module = self
            .modules
            .get(module_name)
            .ok_or_else(|| VmExecutionError::new(format!("unknown module '{module_name}'")))?;
        let function = module
            .functions
            .iter()
            .find(|candidate| candidate.name == function_name)
            .ok_or_else(|| {
                VmExecutionError::new(format!(
                    "AssertionError(\"Exported function '{function_name}' does not exist on contract '{module_name}'!\")"
                ))
            })?;
        if function.visibility != "export" {
            return Err(VmExecutionError::new(format!(
                "AssertionError(\"Exported function '{function_name}' does not exist on contract '{module_name}'!\")"
            )));
        }
        Ok(())
    }
}

impl VmHost for PythonBundleExecutor {
    fn charge_execution_cost(&mut self, cost: u64) -> Result<(), VmExecutionError> {
        self.meter.charge_execution_cost(cost)
    }

    fn charge_storage_read(&mut self, key: &str, value: &VmValue) -> Result<(), VmExecutionError> {
        self.meter.charge_read(key, value)
    }

    fn charge_storage_write(&mut self, key: &str, value: &VmValue) -> Result<(), VmExecutionError> {
        self.meter.charge_write(key, value)
    }

    fn emit_event(&mut self, event: VmEvent) -> Result<(), VmExecutionError> {
        self.events.push(event);
        Ok(())
    }

    fn read_variable(
        &mut self,
        contract: &str,
        binding: &str,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        if let Some(instance) = self.instances.get(contract) {
            if let Some(value) = instance.peek_variable_value(binding) {
                return Ok(Some(value));
            }
        }
        Python::with_gil(|py| -> Result<Option<VmValue>, VmExecutionError> {
            let host = self.host.bind(py);
            let response = host
                .call_method1("read_variable", (contract, binding))
                .map_err(|error| VmExecutionError::new(error.to_string()))?;
            py_optional_to_vm(response)
        })
    }

    fn read_hash(
        &mut self,
        contract: &str,
        binding: &str,
        key: &VmValue,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        if let Some(instance) = self.instances.get(contract) {
            if let Some(value) = instance.peek_hash_entry(binding, key)? {
                return Ok(Some(value));
            }
        }
        Python::with_gil(|py| -> Result<Option<VmValue>, VmExecutionError> {
            let host = self.host.bind(py);
            let key_py =
                vm_to_py(py, key).map_err(|error| VmExecutionError::new(error.to_string()))?;
            let response = host
                .call_method1("read_hash", (contract, binding, key_py))
                .map_err(|error| VmExecutionError::new(error.to_string()))?;
            py_optional_to_vm(response)
        })
    }

    fn scan_hash_entries(
        &mut self,
        contract: &str,
        binding: &str,
        prefix: &str,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        Python::with_gil(|py| -> Result<Vec<(String, VmValue)>, VmExecutionError> {
            let host = self.host.bind(py);
            let response = host
                .call_method1("scan_hash_entries", (contract, binding, prefix))
                .map_err(|error| VmExecutionError::new(error.to_string()))?;
            py_hash_entries_to_vm(response)
        })
    }

    fn load_owner(&mut self, contract: &str) -> Result<Option<String>, VmExecutionError> {
        Python::with_gil(|py| -> Result<Option<String>, VmExecutionError> {
            let host = self.host.bind(py);
            let response = host
                .call_method1("get_owner", (contract,))
                .map_err(|error| VmExecutionError::new(error.to_string()))?;
            if response.is_none() {
                Ok(None)
            } else {
                response
                    .extract::<Option<String>>()
                    .map_err(|error| VmExecutionError::new(error.to_string()))
            }
        })
    }

    fn call_contract(&mut self, call: VmContractCall) -> Result<VmValue, VmExecutionError> {
        let target_module = match &call.target {
            VmContractTarget::StaticImport { module, .. }
            | VmContractTarget::DynamicImport { module }
            | VmContractTarget::LocalHandle { module, .. }
            | VmContractTarget::FactoryCall { module, .. } => module.clone(),
        };
        self.ensure_exported_function(&target_module, &call.function)?;
        let owner = self.load_owner(&target_module)?;
        let caller = call.caller_contract.clone().or_else(|| call.signer.clone());
        if let Some(owner) = owner.as_deref() {
            if caller.as_deref() != Some(owner) {
                return Err(VmExecutionError::new(
                    "Exception(\"Caller is not the owner!\")",
                ));
            }
        }
        let call_index = self.contract_call_count;
        self.contract_call_count = self.contract_call_count.saturating_add(1);
        self.meter.charge_execution_cost(
            VM_GAS_CROSS_CONTRACT_CALL_BASE
                + VM_GAS_CROSS_CONTRACT_CALL_REPEAT.saturating_mul(call_index),
        )?;
        self.meter.enter_contract_metering(&target_module);
        let context = VmExecutionContext {
            this: Some(target_module.clone()),
            caller,
            signer: call.signer.clone(),
            owner,
            entry: call.entry.clone(),
            submission_name: call.submission_name.clone(),
            now: call.now.clone(),
            block_num: call.block_num.clone(),
            block_hash: call.block_hash.clone(),
            chain_id: call.chain_id.clone(),
        };
        let result = self.execute_call(
            &target_module,
            &call.function,
            call.args,
            call.kwargs,
            context,
        );
        self.meter.exit_contract_metering();
        result
    }

    fn handle_syscall(
        &mut self,
        syscall_id: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        Python::with_gil(|py| -> Result<VmValue, VmExecutionError> {
            let host = self.host.bind(py);
            let py_args = PyList::empty(py);
            for value in &args {
                py_args
                    .append(
                        vm_to_py(py, value)
                            .map_err(|error| VmExecutionError::new(error.to_string()))?,
                    )
                    .map_err(|error| VmExecutionError::new(error.to_string()))?;
            }
            let py_kwargs = PyDict::new(py);
            for (key, value) in &kwargs {
                py_kwargs
                    .set_item(
                        key,
                        vm_to_py(py, value)
                            .map_err(|error| VmExecutionError::new(error.to_string()))?,
                    )
                    .map_err(|error| VmExecutionError::new(error.to_string()))?;
            }
            let response = host
                .call_method1("handle_syscall", (syscall_id, py_args, py_kwargs))
                .map_err(|error| VmExecutionError::new(error.to_string()))?;
            py_to_vm(response)
        })
    }
}

struct PyExecutionResult {
    status_code: i32,
    result: VmValue,
    snapshots: Vec<crate::interpreter::VmModuleStorageSnapshot>,
    events: Vec<VmEvent>,
    stats: VmExecutionStats,
}

fn py_optional_to_vm(value: Bound<'_, PyAny>) -> Result<Option<VmValue>, VmExecutionError> {
    if value.is_none() {
        Ok(None)
    } else {
        py_to_vm(value).map(Some)
    }
}

fn py_hash_entries_to_vm(
    value: Bound<'_, PyAny>,
) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
    let sequence = value
        .downcast::<PyList>()
        .map_err(|_| VmExecutionError::new("expected list of hash entries"))?;
    let mut entries = Vec::with_capacity(sequence.len());
    for item in sequence.iter() {
        let pair = item
            .downcast::<PyTuple>()
            .map_err(|_| VmExecutionError::new("hash entry must be a tuple"))?;
        if pair.len() != 2 {
            return Err(VmExecutionError::new(
                "hash entry tuples must contain key and value",
            ));
        }
        let key = pair
            .get_item(0)
            .map_err(|error| VmExecutionError::new(error.to_string()))?
            .extract::<String>()
            .map_err(|error| VmExecutionError::new(error.to_string()))?;
        let item_value = pair
            .get_item(1)
            .map_err(|error| VmExecutionError::new(error.to_string()))?;
        entries.push((key, py_to_vm(item_value)?));
    }
    Ok(entries)
}

fn py_to_vm(value: Bound<'_, PyAny>) -> Result<VmValue, VmExecutionError> {
    if value.is_none() {
        return Ok(VmValue::None);
    }
    let type_name = python_type_name(&value);
    if let Ok(boolean) = value.extract::<bool>() {
        if type_name == "bool" {
            return Ok(VmValue::Bool(boolean));
        }
    }
    if value.is_instance_of::<PyList>() {
        let values = value
            .downcast::<PyList>()
            .map_err(|error| VmExecutionError::new(error.to_string()))?
            .iter()
            .map(py_to_vm)
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(VmValue::List(values));
    }
    if value.is_instance_of::<PyTuple>() {
        let values = value
            .downcast::<PyTuple>()
            .map_err(|error| VmExecutionError::new(error.to_string()))?
            .iter()
            .map(py_to_vm)
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(VmValue::Tuple(values));
    }
    if value.is_instance_of::<PyDict>() {
        let dict = value
            .downcast::<PyDict>()
            .map_err(|error| VmExecutionError::new(error.to_string()))?;
        let mut entries = Vec::new();
        for (key, item) in dict.iter() {
            entries.push((py_to_vm(key)?, py_to_vm(item)?));
        }
        return Ok(VmValue::Dict(entries));
    }
    if value.is_instance_of::<PyBytes>() {
        let bytes = value
            .downcast::<PyBytes>()
            .map_err(|error| VmExecutionError::new(error.to_string()))?;
        return Ok(VmValue::Bytes(bytes.as_bytes().to_vec()));
    }
    if value.is_instance_of::<PyByteArray>() {
        let bytes = value
            .downcast::<PyByteArray>()
            .map_err(|error| VmExecutionError::new(error.to_string()))?;
        return Ok(VmValue::ByteArray(bytes.to_vec()));
    }
    if let Some((module, name)) = python_class_path(&value) {
        match (module.as_str(), name.as_str()) {
            ("xian_runtime_types.collections", "ContractingSet") => {
                let values = value
                    .try_iter()
                    .map_err(|error| VmExecutionError::new(error.to_string()))?
                    .map(|item| {
                        item.map_err(|error| VmExecutionError::new(error.to_string()))
                            .and_then(py_to_vm)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                return Ok(VmValue::Set(values));
            }
            ("xian_runtime_types.collections", "ContractingFrozenSet") => {
                let values = value
                    .try_iter()
                    .map_err(|error| VmExecutionError::new(error.to_string()))?
                    .map(|item| {
                        item.map_err(|error| VmExecutionError::new(error.to_string()))
                            .and_then(py_to_vm)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                return Ok(VmValue::FrozenSet(values));
            }
            ("xian_runtime_types.decimal", "ContractingDecimal") => {
                return Ok(VmValue::Decimal(VmDecimal::from_str_literal(
                    value
                        .str()
                        .map_err(|error| VmExecutionError::new(error.to_string()))?
                        .to_str()
                        .map_err(|error| VmExecutionError::new(error.to_string()))?,
                )?));
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
        let rendered = value
            .str()
            .map_err(|error| VmExecutionError::new(error.to_string()))?
            .to_str()
            .map_err(|error| VmExecutionError::new(error.to_string()))?
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

fn vm_to_py(py: Python<'_>, value: &VmValue) -> PyResult<PyObject> {
    match value {
        VmValue::None => Ok(py.None()),
        VmValue::Bool(value) => Ok((*value).into_pyobject(py)?.to_owned().into_any().unbind()),
        VmValue::Int(value) => {
            let builtins = PyModule::import(py, "builtins")?;
            Ok(builtins
                .getattr("int")?
                .call1((value.to_string(),))?
                .unbind())
        }
        VmValue::Float(value) => Ok(value.into_pyobject(py)?.into_any().unbind()),
        VmValue::Decimal(value) => {
            let module = PyModule::import(py, "xian_runtime_types.decimal")?;
            Ok(module
                .getattr("ContractingDecimal")?
                .call1((value.to_string(),))?
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
        VmValue::Set(values) => {
            let module = PyModule::import(py, "xian_runtime_types.collections")?;
            let list = PyList::empty(py);
            for item in values {
                list.append(vm_to_py(py, item)?)?;
            }
            Ok(module.getattr("ContractingSet")?.call1((list,))?.unbind())
        }
        VmValue::FrozenSet(values) => {
            let module = PyModule::import(py, "xian_runtime_types.collections")?;
            let list = PyList::empty(py);
            for item in values {
                list.append(vm_to_py(py, item)?)?;
            }
            Ok(module
                .getattr("ContractingFrozenSet")?
                .call1((list,))?
                .unbind())
        }
        VmValue::List(values) => {
            let list = PyList::empty(py);
            for item in values {
                list.append(vm_to_py(py, item)?)?;
            }
            Ok(list.into_any().unbind())
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
        .map_err(|error| VmExecutionError::new(error.to_string()))?
        .extract::<i64>()
        .map_err(|error| VmExecutionError::new(error.to_string()))
}

fn optional_string_item(
    dict: &Bound<'_, PyDict>,
    key: &str,
) -> Result<Option<String>, VmExecutionError> {
    let Some(value) = dict
        .get_item(key)
        .map_err(|error| VmExecutionError::new(error.to_string()))?
    else {
        return Ok(None);
    };
    if value.is_none() {
        return Ok(None);
    }
    value
        .extract::<String>()
        .map(Some)
        .map_err(|error| VmExecutionError::new(error.to_string()))
}

fn context_from_py(context: &Bound<'_, PyAny>) -> Result<VmExecutionContext, VmExecutionError> {
    let dict = context
        .downcast::<PyDict>()
        .map_err(|error| VmExecutionError::new(error.to_string()))?;
    let this = optional_string_item(dict, "this")?;
    let caller = optional_string_item(dict, "caller")?;
    let signer = optional_string_item(dict, "signer")?;
    let owner = optional_string_item(dict, "owner")?;
    let submission_name = optional_string_item(dict, "submission_name")?;
    let entry = dict
        .get_item("entry")
        .map_err(|error| VmExecutionError::new(error.to_string()))?
        .map(|value| {
            if value.is_none() {
                return Ok(None);
            }
            let tuple = value
                .downcast::<PyTuple>()
                .map_err(|error| VmExecutionError::new(error.to_string()))?;
            if tuple.len() != 2 {
                return Err(VmExecutionError::new("context.entry must be a 2-tuple"));
            }
            Ok(Some((
                tuple
                    .get_item(0)
                    .map_err(|error| VmExecutionError::new(error.to_string()))?
                    .extract::<String>()
                    .map_err(|error| VmExecutionError::new(error.to_string()))?,
                tuple
                    .get_item(1)
                    .map_err(|error| VmExecutionError::new(error.to_string()))?
                    .extract::<String>()
                    .map_err(|error| VmExecutionError::new(error.to_string()))?,
            )))
        })
        .transpose()?
        .flatten();
    let now = dict
        .get_item("now")
        .map_err(|error| VmExecutionError::new(error.to_string()))?
        .map(py_to_vm)
        .transpose()?
        .unwrap_or(VmValue::None);
    let block_num = dict
        .get_item("block_num")
        .map_err(|error| VmExecutionError::new(error.to_string()))?
        .map(py_to_vm)
        .transpose()?
        .unwrap_or(VmValue::Int(BigInt::from(-1)));
    let block_hash = dict
        .get_item("block_hash")
        .map_err(|error| VmExecutionError::new(error.to_string()))?
        .map(py_to_vm)
        .transpose()?
        .unwrap_or(VmValue::None);
    let chain_id = dict
        .get_item("chain_id")
        .map_err(|error| VmExecutionError::new(error.to_string()))?
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
    })
}

fn execution_result_to_py(py: Python<'_>, result: PyExecutionResult) -> PyResult<PyObject> {
    let payload = PyDict::new(py);
    payload.set_item("status_code", result.status_code)?;
    payload.set_item("result", vm_to_py(py, &result.result)?)?;

    let snapshots = PyList::empty(py);
    for snapshot in result.snapshots {
        let snapshot_dict = PyDict::new(py);
        snapshot_dict.set_item("contract_name", snapshot.contract_name)?;
        let variables = PyList::empty(py);
        for variable in snapshot.variables {
            let item = PyDict::new(py);
            item.set_item("binding", variable.binding)?;
            item.set_item("default_value", vm_to_py(py, &variable.default_value)?)?;
            if let Some(value) = variable.value {
                item.set_item("value", vm_to_py(py, &value)?)?;
            } else {
                item.set_item("value", py.None())?;
            }
            variables.append(item)?;
        }
        let hashes = PyList::empty(py);
        for hash in snapshot.hashes {
            let item = PyDict::new(py);
            item.set_item("binding", hash.binding)?;
            item.set_item("default_value", vm_to_py(py, &hash.default_value)?)?;
            let entries = PyDict::new(py);
            for (key, value) in hash.entries {
                entries.set_item(key, vm_to_py(py, &value)?)?;
            }
            item.set_item("entries", entries)?;
            hashes.append(item)?;
        }
        snapshot_dict.set_item("variables", variables)?;
        snapshot_dict.set_item("hashes", hashes)?;
        snapshots.append(snapshot_dict)?;
    }
    payload.set_item("snapshots", snapshots)?;

    let events = PyList::empty(py);
    for event in result.events {
        let event_dict = PyDict::new(py);
        event_dict.set_item("contract", event.contract)?;
        event_dict.set_item("event", event.event)?;
        event_dict.set_item("signer", vm_to_py(py, &event.signer)?)?;
        event_dict.set_item("caller", vm_to_py(py, &event.caller)?)?;
        let data_indexed = PyDict::new(py);
        for (key, value) in event.data_indexed {
            data_indexed.set_item(key, vm_to_py(py, &value)?)?;
        }
        let data = PyDict::new(py);
        for (key, value) in event.data {
            data.set_item(key, vm_to_py(py, &value)?)?;
        }
        event_dict.set_item("data_indexed", data_indexed)?;
        event_dict.set_item("data", data)?;
        events.append(event_dict)?;
    }
    payload.set_item("events", events)?;
    payload.set_item("raw_cost", result.stats.raw_cost)?;
    payload.set_item("chi_used", result.stats.chi_used)?;
    let contract_costs = PyDict::new(py);
    for (contract, cost) in result.stats.contract_costs {
        contract_costs.set_item(contract, cost)?;
    }
    payload.set_item("contract_costs", contract_costs)?;
    Ok(payload.into_any().unbind())
}

#[pyfunction]
fn runtime_info_json() -> PyResult<String> {
    serde_json::to_string(&json!({
        "ir_version": XIAN_IR_V1,
        "vm_profile": XIAN_VM_V1_PROFILE,
        "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
        "supported_bytecode_versions": XIAN_VM_SUPPORTED_BYTECODE_VERSIONS,
        "supported_gas_schedules": XIAN_VM_SUPPORTED_GAS_SCHEDULES,
    }))
    .map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn supports_execution_policy(bytecode_version: &str, gas_schedule: &str) -> bool {
    XIAN_VM_SUPPORTED_BYTECODE_VERSIONS.contains(&bytecode_version)
        && XIAN_VM_SUPPORTED_GAS_SCHEDULES.contains(&gas_schedule)
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
    vm_profile="xian_vm_v1"
))]
fn validate_deployment_artifacts_json(
    py: Python<'_>,
    module_name: &str,
    artifacts_json: &str,
    input_source: Option<&str>,
    vm_profile: &str,
) -> PyResult<PyObject> {
    let bundle = crate::validate_contract_artifacts_json(
        module_name,
        artifacts_json,
        input_source,
        vm_profile,
    )
    .map_err(|error| VmRuntimeExecutionError::new_err(error.to_string()))?;
    let payload = PyDict::new(py);
    payload.set_item("source", bundle.source)?;
    payload.set_item("runtime_code", bundle.runtime_code)?;
    payload.set_item("vm_ir_json", bundle.vm_ir_json)?;
    Ok(payload.into_any().unbind())
}

#[pyfunction(signature=(
    bundle_ir_json,
    entry_module,
    function_name,
    args,
    kwargs,
    context,
    host,
    *,
    meter=false,
    chi_budget_raw=0,
    transaction_size_bytes=0
))]
fn execute_bundle(
    py: Python<'_>,
    bundle_ir_json: &str,
    entry_module: &str,
    function_name: &str,
    args: Py<PyAny>,
    kwargs: Py<PyAny>,
    context: Py<PyAny>,
    host: Py<PyAny>,
    meter: bool,
    chi_budget_raw: u64,
    transaction_size_bytes: usize,
) -> PyResult<PyObject> {
    let args = args.bind(py);
    let kwargs = kwargs.bind(py);
    let context = context.bind(py);
    let args = args
        .downcast::<PyList>()
        .map_err(|error| PyTypeError::new_err(error.to_string()))?
        .iter()
        .map(py_to_vm)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| VmRuntimeExecutionError::new_err(error.to_string()))?;
    let kwargs_dict = kwargs
        .downcast::<PyDict>()
        .map_err(|error| PyTypeError::new_err(error.to_string()))?;
    let mut converted_kwargs = Vec::new();
    for (key, value) in kwargs_dict.iter() {
        converted_kwargs.push((
            key.extract::<String>()
                .map_err(|error| PyTypeError::new_err(error.to_string()))?,
            py_to_vm(value).map_err(|error| VmRuntimeExecutionError::new_err(error.to_string()))?,
        ));
    }
    let context = context_from_py(context)
        .map_err(|error| VmRuntimeExecutionError::new_err(error.to_string()))?;
    let mut executor = PythonBundleExecutor::new(
        host,
        bundle_ir_json,
        VmMeterConfig {
            enabled: meter,
            chi_budget_raw,
            transaction_size_bytes,
        },
    )
    .map_err(|error| VmRuntimeExecutionError::new_err(error.to_string()))?;
    let result =
        executor.execute_entry(entry_module, function_name, args, converted_kwargs, context);
    execution_result_to_py(py, result)
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
    module.add_function(wrap_pyfunction!(execute_bundle, module)?)?;
    Ok(())
}
