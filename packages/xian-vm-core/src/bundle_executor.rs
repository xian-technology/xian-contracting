//! A VM bundle execution: module loading and instantiation, cross-contract
//! calls, storage overlay, events and metering, over a `HostServices` host.
#![cfg_attr(not(feature = "python-extension"), allow(dead_code))]
use crate::interpreter::{vm_hash_storage_key, vm_variable_storage_key};
use crate::module_cache::shared_module;
use crate::XIAN_VM_V2_PROFILE;
use crate::{
    VmContractCall, VmContractTarget, VmEvent, VmExecutionContext, VmExecutionError,
    VmExecutionStats, VmHost, VmInstance, VmMeterConfig, VmValue, VM_GAS_CROSS_CONTRACT_CALL_BASE,
    VM_GAS_CROSS_CONTRACT_CALL_REPEAT,
};
use std::collections::{BTreeMap, HashMap, HashSet};

/// What a VM execution needs from its host beyond the executor's own state:
/// module IR, storage the execution has not touched, contract owners and
/// host syscalls. The Python host (`NativeVmHost`) and the Rust block host
/// implement it; the executor logic is shared.
pub(crate) trait HostServices {
    /// The IR JSON text of `module`, or `None` when it has none.
    fn module_ir_json(&mut self, module: &str) -> Result<Option<String>, VmExecutionError>;
    /// `module` validated for `profile`, or `None` when it has no IR.
    fn module(
        &mut self,
        module: &str,
        profile: &str,
    ) -> Result<Option<crate::ValidatedModuleIr>, VmExecutionError> {
        self.module_ir_json(module)?
            .map(|ir_json| load_bundle_module(module, &ir_json, profile))
            .transpose()
    }
    /// A variable not in the executor's state; `None` when missing.
    fn read_variable(
        &mut self,
        contract: &str,
        binding: &str,
        storage_key: &str,
    ) -> Result<Option<VmValue>, VmExecutionError>;
    /// A hash entry not in the executor's state; missing reads as `VmValue::None`.
    fn read_hash(
        &mut self,
        contract: &str,
        binding: &str,
        key: &VmValue,
        storage_key: &str,
    ) -> Result<VmValue, VmExecutionError>;
    /// The stored entries of a hash under `prefix`, as `(suffix, value)`.
    fn scan_hash_entries(
        &mut self,
        contract: &str,
        binding: &str,
        prefix: &str,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError>;
    /// The stored entries of a hash under `prefix`, in key order, each passed
    /// to `visit` (which may stop the scan with an error).
    fn visit_hash_entries(
        &mut self,
        contract: &str,
        binding: &str,
        prefix: &str,
        visit: &mut dyn FnMut(String, VmValue) -> Result<(), VmExecutionError>,
    ) -> Result<(), VmExecutionError>;
    /// The owner of `contract`.
    fn owner(&mut self, contract: &str) -> Result<Option<String>, VmExecutionError>;
    fn syscall(
        &mut self,
        syscall_id: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError>;
}

/// A host lent to a nested execution (a contract's constructor during its
/// deployment), which reads and stages through it for its duration.
impl<H: HostServices + ?Sized> HostServices for &mut H {
    fn module_ir_json(&mut self, module: &str) -> Result<Option<String>, VmExecutionError> {
        (**self).module_ir_json(module)
    }

    fn module(
        &mut self,
        module: &str,
        profile: &str,
    ) -> Result<Option<crate::ValidatedModuleIr>, VmExecutionError> {
        (**self).module(module, profile)
    }

    fn read_variable(
        &mut self,
        contract: &str,
        binding: &str,
        storage_key: &str,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        (**self).read_variable(contract, binding, storage_key)
    }

    fn read_hash(
        &mut self,
        contract: &str,
        binding: &str,
        key: &VmValue,
        storage_key: &str,
    ) -> Result<VmValue, VmExecutionError> {
        (**self).read_hash(contract, binding, key, storage_key)
    }

    fn scan_hash_entries(
        &mut self,
        contract: &str,
        binding: &str,
        prefix: &str,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        (**self).scan_hash_entries(contract, binding, prefix)
    }

    fn visit_hash_entries(
        &mut self,
        contract: &str,
        binding: &str,
        prefix: &str,
        visit: &mut dyn FnMut(String, VmValue) -> Result<(), VmExecutionError>,
    ) -> Result<(), VmExecutionError> {
        (**self).visit_hash_entries(contract, binding, prefix, visit)
    }

    fn owner(&mut self, contract: &str) -> Result<Option<String>, VmExecutionError> {
        (**self).owner(contract)
    }

    fn syscall(
        &mut self,
        syscall_id: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        (**self).syscall(syscall_id, args, kwargs)
    }
}

pub(crate) struct BundleExecutor<H> {
    heap: crate::heap::VmHeap,
    pub(crate) host: H,
    modules: HashMap<String, crate::ValidatedModuleIr>,
    instances: HashMap<String, VmInstance>,
    interface_members: HashMap<String, BTreeMap<String, crate::VmInterfaceMember>>,
    public_callables: HashMap<String, BTreeMap<String, crate::VmPublicCallable>>,
    initializing_modules: HashSet<String>,
    storage_overlay: HashMap<String, VmValue>,
    /// Owners read from the host since its last syscall: only a syscall can
    /// change an owner during an execution.
    owners: HashMap<String, Option<String>>,
    events: Vec<VmEvent>,
    meter: crate::VmMeter,
    contract_call_count: u64,
    vm_profile: String,
}

pub(crate) fn validate_bundle_module(
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

pub(crate) fn load_bundle_module(
    name: &str,
    module_ir_json: &str,
    profile: &str,
) -> Result<crate::ValidatedModuleIr, VmExecutionError> {
    let module = shared_module(name, module_ir_json)
        .map_err(|error| VmExecutionError::new(error.to_string()))?;
    validate_bundle_module(&module, name, profile)?;
    Ok(module)
}

impl<H: HostServices> BundleExecutor<H> {
    /// `bundle` maps module names to their IR JSON text, checked in name order.
    pub(crate) fn new(
        host: H,
        bundle: BTreeMap<String, String>,
        meter_config: VmMeterConfig,
        budget: Option<crate::VmBudget>,
        vm_profile: &str,
    ) -> Result<Self, VmExecutionError> {
        let mut modules = HashMap::new();
        for (module_name, module_ir_json) in bundle {
            let module = load_bundle_module(&module_name, &module_ir_json, vm_profile)?;
            modules.insert(module_name, module);
        }
        Ok(Self::with_modules(
            host,
            modules,
            meter_config,
            budget,
            vm_profile,
        ))
    }

    /// An executor whose bundle is already loaded and checked.
    pub(crate) fn with_modules(
        host: H,
        modules: HashMap<String, crate::ValidatedModuleIr>,
        meter_config: VmMeterConfig,
        budget: Option<crate::VmBudget>,
        vm_profile: &str,
    ) -> Self {
        let budget =
            budget.unwrap_or_else(|| crate::VmBudget::new(meter_config.chi_budget_raw, vm_profile));
        Self {
            heap: crate::heap::VmHeap::with_execution_stack(budget.execution_stack.clone()),
            host,
            modules,
            instances: HashMap::new(),
            interface_members: HashMap::new(),
            public_callables: HashMap::new(),
            initializing_modules: HashSet::new(),
            storage_overlay: HashMap::new(),
            owners: HashMap::new(),
            events: Vec::new(),
            meter: crate::VmMeter::with_budget(meter_config, budget),
            contract_call_count: 0,
            vm_profile: vm_profile.to_owned(),
        }
    }

    pub(crate) fn execute_entry(
        &mut self,
        entry_module: &str,
        function_name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        context: VmExecutionContext,
    ) -> ExecutionOutcome {
        let _work = crate::work_meter::Isolation::enter();
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
                ExecutionOutcome {
                    status_code: 0,
                    result,
                    snapshots,
                    storage_writes: self.storage_overlay.clone(),
                    events: self.events.clone(),
                    stats,
                    exception: None,
                }
            }
            Err(error) => ExecutionOutcome {
                status_code: 1,
                exception: error.exception().cloned(),
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
        let Some(module) = self.host.module(module_name, &self.vm_profile)? else {
            return Err(VmExecutionError::new(format!(
                "native VM could not load module '{module_name}'"
            )));
        };
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
        let instance = VmInstance::new_with_heap(&module, instance_context, self, heap)?;
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
            .ok_or_else(|| missing_export(module_name, function_name))?;
        if function.visibility != "export" {
            return Err(missing_export(module_name, function_name));
        }
        Ok(())
    }
}

impl<H: HostServices> VmHost for BundleExecutor<H> {
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
        self.host.read_variable(contract, binding, &storage_key)
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
        self.host
            .read_hash(contract, binding, key, &storage_key)
            .map(Some)
    }

    fn scan_hash_entries(
        &mut self,
        contract: &str,
        binding: &str,
        prefix: &str,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        let base_key = vm_variable_storage_key(contract, binding);
        let full_prefix = format!("{base_key}:{prefix}");
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
        self.host
            .scan_hash_entries(contract, binding, prefix)
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
        let full_prefix = format!("{base_key}:{prefix}");
        let suffix_offset = base_key.len() + 1;
        let mut overlay = self
            .storage_overlay
            .iter()
            .filter(|(key, _)| key.starts_with(&full_prefix))
            .map(|(key, value)| (key[suffix_offset..].to_owned(), value.clone()))
            .collect::<std::collections::BTreeMap<_, _>>()
            .into_iter()
            .peekable();
        let mut entries = Vec::new();
        let mut budget = crate::storage_scan::ScanBudget::default();
        let meter = &mut self.meter;
        let mut retain = |suffix: String, value: VmValue| -> Result<(), VmExecutionError> {
            let key = format!("{base_key}:{suffix}");
            meter.charge_scan_entry(&key, &value)?;
            budget.observe(&key, &value)?;
            entries.push((suffix, value));
            Ok(())
        };
        let storage_overlay = &self.storage_overlay;
        let mut previous: Option<String> = None;
        self.host
            .visit_hash_entries(contract, binding, prefix, &mut |suffix, value| {
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
                if !storage_overlay.contains_key(&format!("{base_key}:{suffix}")) {
                    retain(suffix, value)?;
                }
                Ok(())
            })?;
        for (suffix, value) in overlay {
            retain(suffix, value)?;
        }
        Ok(entries)
    }

    fn load_owner(&mut self, contract: &str) -> Result<Option<String>, VmExecutionError> {
        if let Some(owner) = self.owners.get(contract) {
            return Ok(owner.clone());
        }
        let owner = self.host.owner(contract)?;
        self.owners.insert(contract.to_owned(), owner.clone());
        Ok(owner)
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
                let message = "Caller is not the owner!";
                return Err(VmExecutionError::described(
                    "Exception",
                    format!("Exception({message:?})"),
                    message,
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
            input_hash: call.input_hash.clone(),
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
        self.owners.clear();
        self.host.syscall(syscall_id, args, kwargs)
    }
}

pub(crate) fn missing_export(module_name: &str, function_name: &str) -> VmExecutionError {
    let message =
        format!("Exported function '{function_name}' does not exist on contract '{module_name}'!");
    VmExecutionError::described(
        "AssertionError",
        format!("AssertionError({message:?})"),
        message,
    )
}

/// The result of one bundle execution.
pub(crate) struct ExecutionOutcome {
    pub(crate) status_code: i32,
    pub(crate) exception: Option<crate::VmException>,
    pub(crate) result: VmValue,
    pub(crate) snapshots: Vec<crate::interpreter::VmModuleStorageSnapshot>,
    pub(crate) storage_writes: HashMap<String, VmValue>,
    pub(crate) events: Vec<VmEvent>,
    pub(crate) stats: VmExecutionStats,
}

impl ExecutionOutcome {
    /// The storage writes as `execute_contract` reports them, taken out of
    /// the outcome: the module snapshots' variables and hash entries, then
    /// the recorded storage writes, by key.
    pub(crate) fn take_writes(&mut self) -> BTreeMap<String, VmValue> {
        let mut writes = BTreeMap::new();
        for snapshot in std::mem::take(&mut self.snapshots) {
            for variable in snapshot.variables {
                writes.insert(
                    format!("{}.{}", snapshot.contract_name, variable.binding),
                    variable.value.unwrap_or(VmValue::None),
                );
            }
            for hash in snapshot.hashes {
                for (key, value) in hash.entries {
                    writes.insert(
                        format!("{}.{}:{}", snapshot.contract_name, hash.binding, key),
                        value,
                    );
                }
            }
        }
        writes.extend(std::mem::take(&mut self.storage_writes));
        writes
    }
}
