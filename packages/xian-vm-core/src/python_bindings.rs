use crate::interpreter::numeric_v2;
use crate::interpreter::{vm_hash_storage_key, vm_variable_storage_key};
use crate::XIAN_VM_V2_PROFILE;
use crate::{
    parse_module_ir, VmContractCall, VmContractTarget, VmDateTime, VmDecimal, VmEvent,
    VmExecutionContext, VmExecutionError, VmExecutionStats, VmHost, VmInstance, VmMeterConfig,
    VmTimeDelta, VmValue, VM_GAS_CROSS_CONTRACT_CALL_BASE, VM_GAS_CROSS_CONTRACT_CALL_REPEAT,
    XIAN_IR_V1, XIAN_VM_EXECUTION_REVISION, XIAN_VM_HOST_CATALOG_V1, XIAN_VM_SET_CODEC,
    XIAN_VM_SUPPORTED_BYTECODE_VERSIONS, XIAN_VM_SUPPORTED_GAS_SCHEDULES, XIAN_VM_V1_PROFILE,
};
use num_bigint::BigInt;
use pyo3::create_exception;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyByteArray, PyBytes, PyDict, PyList, PyModule, PyTuple};
use serde_json::{json, Value as JsonValue};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;

create_exception!(xian_vm_core, VmIrValidationError, PyValueError);
create_exception!(xian_vm_core, VmRuntimeExecutionError, PyValueError);

#[pyclass(name = "_TransactionBudget")]
struct PyTransactionBudget {
    budget: crate::VmBudget,
}

#[pymethods]
impl PyTransactionBudget {
    #[new]
    fn new(chi_budget_raw: u64) -> Self {
        Self {
            budget: crate::VmBudget::new(chi_budget_raw),
        }
    }

    #[getter]
    fn limit(&self) -> u64 {
        self.budget.limit()
    }

    fn charge(&self, raw_cost: u64) -> PyResult<()> {
        self.budget
            .charge(raw_cost)
            .map_err(|error| VmRuntimeExecutionError::new_err(error.to_string()))
    }
}

struct PythonBundleExecutor {
    heap: crate::heap::VmHeap,
    host: Py<PyAny>,
    modules: HashMap<String, crate::ModuleIr>,
    instances: HashMap<String, VmInstance>,
    interface_members: HashMap<String, BTreeMap<String, crate::VmInterfaceMember>>,
    public_callables: HashMap<String, BTreeMap<String, crate::VmPublicCallable>>,
    initializing_modules: HashSet<String>,
    storage_overlay: HashMap<String, VmValue>,
    events: Vec<VmEvent>,
    meter: crate::VmMeter,
    contract_call_count: u64,
    vm_profile: String,
}

fn validate_bundle_module(
    module: &crate::ModuleIr,
    name: &str,
    profile: &str,
) -> Result<(), VmExecutionError> {
    if module.vm_profile != profile || (profile == XIAN_VM_V2_PROFILE && module.module_name != name)
    {
        return Err(VmExecutionError::new(
            "bundle module name or execution profile mismatch",
        ));
    }
    Ok(())
}

impl PythonBundleExecutor {
    fn new(
        host: Py<PyAny>,
        bundle_ir_json: &str,
        meter_config: VmMeterConfig,
        budget: Option<crate::VmBudget>,
        vm_profile: &str,
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
            validate_bundle_module(&module, module_name, vm_profile)?;
            modules.insert(module_name.clone(), module);
        }
        let budget = budget.unwrap_or_else(|| crate::VmBudget::new(meter_config.chi_budget_raw));
        Ok(Self {
            heap: crate::heap::VmHeap::with_execution_stack(budget.execution_stack.clone()),
            host,
            modules,
            instances: HashMap::new(),
            interface_members: HashMap::new(),
            public_callables: HashMap::new(),
            initializing_modules: HashSet::new(),
            storage_overlay: HashMap::new(),
            events: Vec::new(),
            meter: crate::VmMeter::with_budget(meter_config, budget),
            contract_call_count: 0,
            vm_profile: vm_profile.to_owned(),
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
            let result = self
                .execute_call(entry_module, function_name, args, kwargs, context)?
                .external_value()?;
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
                    storage_writes: self.storage_overlay.clone(),
                    events: self.events.clone(),
                    stats,
                }
            }
            Err(error) => PyExecutionResult {
                status_code: 1,
                result: VmValue::String(error.to_string()),
                snapshots: Vec::new(),
                storage_writes: HashMap::new(),
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
        let result = instance.call_function_shared(self, function_name, args, kwargs);
        *instance.context_mut() = previous_context;
        self.instances.insert(module_name.to_owned(), instance);
        result
    }

    fn ensure_module(&mut self, module_name: &str) -> Result<(), VmExecutionError> {
        if self.modules.contains_key(module_name) {
            return Ok(());
        }
        let module_ir_json = Python::attach(|py| -> PyResult<Option<String>> {
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
        validate_bundle_module(&module, module_name, &self.vm_profile)?;
        self.modules.insert(module_name.to_owned(), module);
        Ok(())
    }

    fn instantiate_module(
        &mut self,
        module_name: &str,
        context: &VmExecutionContext,
    ) -> Result<(), VmExecutionError> {
        if !self.initializing_modules.insert(module_name.to_owned()) {
            return Err(VmExecutionError::new("circular module initialization"));
        }
        let result = self.instantiate_module_inner(module_name, context);
        self.initializing_modules.remove(module_name);
        result
    }

    fn instantiate_module_inner(
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
        let heap = self.heap.clone();
        let instance = VmInstance::new_with_heap(module, instance_context, self, heap)?;
        self.meter
            .charge_execution_cost(instance.interface_metadata_work())?;
        let interface_members = instance.interface_members()?;
        self.meter
            .charge_execution_cost(instance.public_callable_metadata_work())?;
        let public_callables = instance.public_callables();
        self.interface_members
            .insert(module_name.to_owned(), interface_members);
        // Admitted function bodies cannot rebind module globals. These specs
        // contain only immutable callable metadata, never mutable receivers or
        // raw values; final initialization overrides have already been applied.
        // Keep them available while execute_call temporarily removes an active
        // instance, so nested callers cannot accidentally reinitialize it.
        self.public_callables
            .insert(module_name.to_owned(), public_callables);
        self.instances.insert(module_name.to_owned(), instance);
        Ok(())
    }

    fn ensure_initialized_metadata(
        &mut self,
        contract: &str,
        mut context: VmExecutionContext,
    ) -> Result<(), VmExecutionError> {
        if self.interface_members.contains_key(contract) {
            return Ok(());
        }
        self.ensure_module(contract)?;
        context.caller = context.this.clone();
        context.this = Some(contract.to_owned());
        context.owner = self.load_owner(contract)?;
        self.meter.enter_contract_metering(contract);
        let result = self.instantiate_module(contract, &context);
        self.meter.exit_contract_metering();
        result
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
    fn interface_member(
        &mut self,
        contract: &str,
        name: &str,
        context: VmExecutionContext,
    ) -> Result<crate::VmInterfaceMember, VmExecutionError> {
        self.ensure_initialized_metadata(contract, context)?;
        let member = self.interface_members[contract].get(name);
        self.meter.charge_execution_cost(
            name.len() as u64 + member.map_or(1, crate::VmInterfaceMember::inspection_work),
        )?;
        Ok(member.cloned().unwrap_or(crate::VmInterfaceMember::Missing))
    }

    fn public_callable(
        &mut self,
        contract: &str,
        name: &str,
        context: VmExecutionContext,
    ) -> Result<Option<crate::VmPublicCallable>, VmExecutionError> {
        self.ensure_initialized_metadata(contract, context)?;
        let member = self.public_callables[contract].get(name);
        self.meter.charge_execution_cost(
            (name.len() as u64)
                .saturating_add(member.map_or(1, crate::VmPublicCallable::inspection_work)),
        )?;
        Ok(member.cloned())
    }

    fn charge_execution_cost(&mut self, cost: u64) -> Result<(), VmExecutionError> {
        self.meter.charge_execution_cost(cost)
    }

    fn charge_storage_read(&mut self, key: &str, value: &VmValue) -> Result<(), VmExecutionError> {
        self.meter.charge_read(key, value)
    }

    fn charge_storage_write(&mut self, key: &str, value: &VmValue) -> Result<(), VmExecutionError> {
        self.meter.charge_write(key, value)
    }

    fn record_storage_write(&mut self, key: &str, value: &VmValue) -> Result<(), VmExecutionError> {
        self.storage_overlay
            .insert(key.to_owned(), value.storage_value()?);
        Ok(())
    }

    fn read_recorded_storage_write(
        &mut self,
        key: &str,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        Ok(self.storage_overlay.get(key).cloned())
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
        let storage_key = vm_variable_storage_key(contract, binding);
        if let Some(value) = self.storage_overlay.get(&storage_key) {
            return Ok(Some(value.clone()));
        }
        if let Some(instance) = self.instances.get(contract) {
            if let Some(value) = instance.peek_variable_value(binding) {
                return Ok(Some(value));
            }
        }
        Python::attach(|py| -> Result<Option<VmValue>, VmExecutionError> {
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
        let storage_key = vm_hash_storage_key(contract, binding, key)?;
        if let Some(value) = self.storage_overlay.get(&storage_key) {
            return Ok(Some(value.clone()));
        }
        if let Some(instance) = self.instances.get(contract) {
            if let Some(value) = instance.peek_hash_entry(binding, key)? {
                return Ok(Some(value));
            }
        }
        Python::attach(|py| -> Result<Option<VmValue>, VmExecutionError> {
            let host = self.host.bind(py);
            let key_py =
                vm_to_py(py, key).map_err(|error| VmExecutionError::new(error.to_string()))?;
            let response = host
                .call_method1("read_hash", (contract, binding, key_py))
                .map_err(|error| VmExecutionError::new(error.to_string()))?;
            // Driver reads are authoritative, including missing/deleted keys.
            py_to_vm(response).map(Some)
        })
    }

    fn scan_hash_entries(
        &mut self,
        contract: &str,
        binding: &str,
        prefix: &str,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        let base_key = vm_variable_storage_key(contract, binding);
        let full_prefix = if prefix.is_empty() {
            format!("{base_key}:")
        } else {
            format!("{base_key}:{prefix}:")
        };
        let suffix_offset = base_key.len() + 1;
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        for (storage_key, value) in &self.storage_overlay {
            if storage_key.starts_with(&full_prefix) {
                let suffix = storage_key[suffix_offset..].to_owned();
                seen.insert(suffix.clone());
                if !matches!(value, VmValue::None) {
                    entries.push((suffix, value.clone()));
                }
            }
        }
        Python::attach(|py| -> Result<Vec<(String, VmValue)>, VmExecutionError> {
            let host = self.host.bind(py);
            let response = host
                .call_method1("scan_hash_entries", (contract, binding, prefix))
                .map_err(|error| VmExecutionError::new(error.to_string()))?;
            py_hash_entries_to_vm(response)
        })
        .map(|host_entries| {
            for (suffix, value) in host_entries {
                if seen.insert(suffix.clone()) {
                    entries.push((suffix, value));
                }
            }
            entries
        })
    }

    fn scan_hash_entries_metered(
        &mut self,
        contract: &str,
        binding: &str,
        prefix: &str,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        let base_key = vm_variable_storage_key(contract, binding);
        let full_prefix = if prefix.is_empty() {
            format!("{base_key}:")
        } else {
            format!("{base_key}:{prefix}:")
        };
        let suffix_offset = base_key.len() + 1;
        let mut overlay = self
            .storage_overlay
            .iter()
            .filter(|(key, _)| key.starts_with(&full_prefix))
            .map(|(key, value)| (key[suffix_offset..].to_owned(), value.clone()))
            .collect::<std::collections::BTreeMap<_, _>>()
            .into_iter()
            .peekable();
        Python::attach(|py| {
            let host_owner = self.host.clone_ref(py);
            let host = host_owner.bind(py);
            let streaming = host
                .hasattr("iter_hash_entries")
                .map_err(|e| VmExecutionError::new(e.to_string()))?;
            let response = host
                .call_method1(
                    if streaming {
                        "iter_hash_entries"
                    } else {
                        "scan_hash_entries"
                    },
                    (contract, binding, prefix),
                )
                .map_err(|e| VmExecutionError::new(e.to_string()))?;
            let mut remote: Box<dyn Iterator<Item = Result<(String, VmValue), VmExecutionError>>> =
                if streaming {
                    Box::new(
                        response
                            .try_iter()
                            .map_err(|e| VmExecutionError::new(e.to_string()))?
                            .map(|item| {
                                py_hash_entry_to_vm(
                                    item.map_err(|e| VmExecutionError::new(e.to_string()))?,
                                )
                            }),
                    )
                } else {
                    // Compatibility for trusted embedded hosts. The production host
                    // always supplies the lazy ordered iterator above.
                    let mut entries = py_hash_entries_to_vm(response)?;
                    entries.sort_by(|a, b| a.0.cmp(&b.0));
                    Box::new(entries.into_iter().map(Ok))
                };
            let mut entries = Vec::new();
            let mut budget = crate::storage_scan::ScanBudget::default();
            let mut previous: Option<String> = None;
            let mut retain = |suffix: String, value: VmValue| -> Result<(), VmExecutionError> {
                let key = format!("{base_key}:{suffix}");
                self.meter.charge_read(&key, &value)?;
                budget.observe(&key, &value)?;
                entries.push((suffix, value));
                Ok(())
            };
            for entry in remote.by_ref() {
                let (suffix, value) = entry?;
                if previous.as_ref().is_some_and(|key| key >= &suffix) {
                    return Err(VmExecutionError::new(
                        "storage scan host returned unordered or duplicate keys",
                    ));
                }
                previous = Some(suffix.clone());
                while overlay.peek().is_some_and(|(key, _)| key <= &suffix) {
                    let (key, local) = overlay.next().unwrap();
                    let same = key == suffix;
                    retain(key, local)?;
                    if same {
                        break;
                    }
                }
                // A tombstone is retained as an overlay entry so instance-local
                // state cannot resurrect it after a nested contract call.
                if !self
                    .storage_overlay
                    .contains_key(&format!("{base_key}:{suffix}"))
                {
                    retain(suffix, value)?;
                }
            }
            for (suffix, value) in overlay {
                retain(suffix, value)?;
            }
            Ok(entries)
        })
    }

    fn load_owner(&mut self, contract: &str) -> Result<Option<String>, VmExecutionError> {
        Python::attach(|py| -> Result<Option<String>, VmExecutionError> {
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

    fn validate_contract_export(
        &mut self,
        contract: &str,
        function: &str,
    ) -> Result<(), VmExecutionError> {
        self.ensure_exported_function(contract, function)
    }

    fn call_contract_shared(&mut self, call: VmContractCall) -> Result<VmValue, VmExecutionError> {
        // Retain aliases, not detached copies: a callee can mutate shared input
        // graphs even when its explicit result is None.
        let inputs = call
            .args
            .iter()
            .chain(call.kwargs.iter().map(|(_, value)| value))
            .cloned()
            .collect::<Vec<_>>();
        crate::heap::validate_contract_values(inputs.iter())?;
        let result = self.call_contract(call)?;
        crate::heap::validate_contract_values(inputs.iter().chain(std::iter::once(&result)))?;
        Ok(result)
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
        Python::attach(|py| -> Result<VmValue, VmExecutionError> {
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
    storage_writes: HashMap<String, VmValue>,
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

fn py_hash_entry_to_vm(item: Bound<'_, PyAny>) -> Result<(String, VmValue), VmExecutionError> {
    let pair = item
        .cast::<PyTuple>()
        .map_err(|_| VmExecutionError::new("hash entry must be a tuple"))?;
    if pair.len() != 2 {
        return Err(VmExecutionError::new(
            "hash entry tuples must contain key and value",
        ));
    }
    let key = pair
        .get_item(0)
        .map_err(|e| VmExecutionError::new(e.to_string()))?
        .extract::<String>()
        .map_err(|e| VmExecutionError::new(e.to_string()))?;
    let value = pair
        .get_item(1)
        .map_err(|e| VmExecutionError::new(e.to_string()))?;
    Ok((key, py_to_vm(value)?))
}

fn py_hash_entries_to_vm(
    value: Bound<'_, PyAny>,
) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
    value
        .try_iter()
        .map_err(|e| VmExecutionError::new(e.to_string()))?
        .map(|item| py_hash_entry_to_vm(item.map_err(|e| VmExecutionError::new(e.to_string()))?))
        .collect()
}

fn py_to_vm(value: Bound<'_, PyAny>) -> Result<VmValue, VmExecutionError> {
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
            ("decimal", "Decimal") => {
                return Ok(VmValue::RawDecimal(crate::VmRawDecimal::parse(
                    value
                        .str()
                        .map_err(|error| VmExecutionError::new(error.to_string()))?
                        .to_str()
                        .map_err(|error| VmExecutionError::new(error.to_string()))?,
                )?));
            }
            ("xian_runtime_types.decimal", "ContractingDecimal") => {
                let rendered = value
                    .str()
                    .map_err(|error| VmExecutionError::new(error.to_string()))?;
                let text = rendered
                    .to_str()
                    .map_err(|error| VmExecutionError::new(error.to_string()))?;
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
                .map_err(|error| VmExecutionError::new(error.to_string()))?
                > xian_numeric::INTEGER_BITS
        {
            return Err(VmExecutionError::new(
                "integer exceeds the 512-bit magnitude limit",
            ));
        }
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

fn py_decimal_tuple_to_vm(value: &Bound<'_, PyAny>) -> Result<VmValue, VmExecutionError> {
    let components = (|| -> PyResult<(u8, Vec<u8>, Bound<'_, PyAny>)> {
        Ok((
            value.getattr("sign")?.extract()?,
            value.getattr("digits")?.extract()?,
            value.getattr("exponent")?,
        ))
    })()
    .map_err(|error| VmExecutionError::new(error.to_string()))?;
    let (sign, digits, exponent) = components;
    if sign > 1 {
        return Err(VmExecutionError::new("DecimalTuple sign must be 0 or 1"));
    }
    let (finite, special) = if let Ok(number) = exponent.extract::<i32>() {
        (Some(number), None)
    } else {
        let marker = exponent
            .extract::<char>()
            .map_err(|error| VmExecutionError::new(error.to_string()))?;
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
        VmValue::Set(values) | VmValue::FrozenSet(values) => {
            let class = if matches!(value, VmValue::Set(_)) {
                "ContractingSet"
            } else {
                "ContractingFrozenSet"
            };
            let wrapper = PyModule::import(py, "xian_runtime_types.collections")?.getattr(class)?;
            let list = PyList::empty(py);
            for item in values {
                list.append(vm_to_py(py, item)?)?;
            }
            let set = if numeric_v2::active() {
                wrapper.call_method1("_from_v2_members", (list,))?
            } else {
                wrapper.call1((list,))?
            };
            Ok(set.unbind())
        }
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
        .cast::<PyDict>()
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
                .cast::<PyTuple>()
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

fn execution_result_to_py(py: Python<'_>, result: PyExecutionResult) -> PyResult<Py<PyAny>> {
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

    let storage_writes = PyDict::new(py);
    for (key, value) in result.storage_writes {
        storage_writes.set_item(key, vm_to_py(py, &value)?)?;
    }
    payload.set_item("storage_writes", storage_writes)?;

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
        XIAN_VM_V1_PROFILE => Some(ProfilePolicy {
            bytecode: &["xvm-1"],
            gas: &["xvm-gas-2"],
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
        "set_codec": XIAN_VM_SET_CODEC,
    }))
    .map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction(signature=(bytecode_version,gas_schedule,vm_profile="xian_vm_v2"))]
fn supports_execution_policy(bytecode_version: &str, gas_schedule: &str, vm_profile: &str) -> bool {
    profile_policy(vm_profile).is_some_and(|policy| {
        policy.bytecode.contains(&bytecode_version) && policy.gas.contains(&gas_schedule)
    })
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
    transaction_size_bytes=0,
    budget=None,
    vm_profile="xian_vm_v2"
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
    budget: Option<PyRef<'_, PyTransactionBudget>>,
    vm_profile: &str,
) -> PyResult<Py<PyAny>> {
    if !matches!(vm_profile, XIAN_VM_V1_PROFILE | XIAN_VM_V2_PROFILE) {
        return Err(PyValueError::new_err("unknown VM profile"));
    }
    let _scope = numeric_v2::Scope::enter(vm_profile);
    let args = args.bind(py);
    let kwargs = kwargs.bind(py);
    let context = context.bind(py);
    let args = args
        .cast::<PyList>()
        .map_err(|error| PyTypeError::new_err(error.to_string()))?
        .iter()
        .map(py_to_vm)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| VmRuntimeExecutionError::new_err(error.to_string()))?;
    let kwargs_dict = kwargs
        .cast::<PyDict>()
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
        budget.map(|shared| shared.budget.clone()),
        vm_profile,
    )
    .map_err(|error| VmRuntimeExecutionError::new_err(error.to_string()))?;
    let result =
        executor.execute_entry(entry_module, function_name, args, converted_kwargs, context);
    execution_result_to_py(py, result)
}

#[pymodule]
fn _native(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyTransactionBudget>()?;
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
