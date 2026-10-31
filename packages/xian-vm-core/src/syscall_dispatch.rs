//! Route syscalls across storage, contract, event, and host boundaries.
use super::*;

impl VmInstance {
    pub(super) fn eval_syscall(
        &mut self,
        object: &Map<String, Value>,
        syscall_id: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        _scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
        target: Option<VmContractTarget>,
    ) -> Result<VmValue, VmExecutionError> {
        let shared_args = args.clone();
        let shared_kwargs = kwargs.clone();
        let args = args.iter().map(VmValue::snapshot).collect::<Vec<_>>();
        let kwargs = kwargs
            .into_iter()
            .map(|(k, v)| (k, v.snapshot()))
            .collect::<Vec<_>>();
        match syscall_id {
            "storage.foreign_hash.new" => {
                foreign_storage::new_reference("ForeignHash", args, kwargs)
            }
            "storage.foreign_variable.new" => {
                foreign_storage::new_reference("ForeignVariable", args, kwargs)
            }
            "numeric.decimal.new" => {
                if !kwargs.is_empty() || args.len() != 1 {
                    return Err(VmExecutionError::new("decimal() expects one argument"));
                }
                Ok(VmValue::Decimal(VmDecimal::from_vm_value(
                    args.first().expect("decimal() argument should exist"),
                )?))
            }
            "time.datetime.new" => time_datetime_new(args, kwargs),
            "time.datetime.strptime" => time_datetime_strptime(args, kwargs),
            "time.timedelta.new" => time_timedelta_new(args, kwargs),
            "hash.sha3_256_text" => hash_sha3_256_text(args, kwargs),
            "hash.sha3_256_hex" => hash_sha3_256_hex(args, kwargs),
            "hash.sha256_legacy" => hash_legacy(false, args, kwargs),
            "hash.sha3_256_legacy" => hash_legacy(true, args, kwargs),
            "hash.sha256_text" => hash_sha256_text(args, kwargs),
            "hash.sha256_hex" => hash_sha256_hex(args, kwargs),
            "crypto.ed25519_verify" => crypto_ed25519_verify(args, kwargs),
            "crypto.key_is_valid" => crypto_key_is_valid(args, kwargs),
            "storage.variable.get" => {
                host.charge_execution_cost(VM_GAS_VARIABLE_GET)?;
                let binding = required_string(object, "receiver_binding")?;
                self.variable_get(binding, host)
            }
            "storage.variable.set" => self.syscall_variable_set(object, args, host),
            "storage.foreign_variable.get" => {
                host.charge_execution_cost(VM_GAS_VARIABLE_GET)?;
                let binding = required_string(object, "receiver_binding")?;
                self.variable_get(binding, host)
            }
            "storage.hash.all" | "storage.foreign_hash.all" => {
                host.charge_execution_cost(VM_GAS_HASH_SCAN)?;
                let binding = required_string(object, "receiver_binding")?;
                self.hash_all(binding, &args, host)
            }
            "contract.import" => {
                let module = resolve_contract_import_arg(&args, &kwargs)?;
                Ok(VmValue::ContractHandle(VmContractHandle {
                    module,
                    origin: "dynamic_import".to_owned(),
                }))
            }
            "contract.call" => self.syscall_contract_call(args, kwargs, host),
            "event.log.emit" => self.syscall_emit_event(object, args, kwargs, host),
            "contract.export_call" => {
                let function_name = required_string(object, "function_name")?;

                let target = target
                    .ok_or_else(|| VmExecutionError::new("missing resolved contract target"))?;
                host.call_contract_shared(VmContractCall {
                    target,
                    function: function_name.to_owned(),
                    args: shared_args,
                    kwargs: shared_kwargs,
                    caller_contract: self.context.this.clone(),
                    signer: self.context.signer.clone(),
                    entry: self.context.entry.clone(),
                    submission_name: self.context.submission_name.clone(),
                    now: self.context.now.clone(),
                    block_num: self.context.block_num.clone(),
                    block_hash: self.context.block_hash.clone(),
                    chain_id: self.context.chain_id.clone(),
                })
            }
            "event.indexed" => {
                let type_value = if args.len() == 1 {
                    coerce_type_marker(args[0].clone())
                } else {
                    VmValue::Tuple(args.into_iter().map(coerce_type_marker).collect())
                };
                Ok(VmValue::Dict(vec![
                    (VmValue::String("type".to_owned()), type_value),
                    (VmValue::String("idx".to_owned()), VmValue::Bool(true)),
                ]))
            }
            "random.shuffle" => shuffle_shared(&shared_args, &shared_kwargs, host),
            "random.choice" | "random.choices" => {
                random_selection_shared(syscall_id, shared_args, shared_kwargs, host)
            }
            other => {
                // Contract metadata syscalls are checked against the contract
                // executing right now, not the transaction's entry contract,
                // so a constructor or a contract called from submission can't
                // use them.
                if SUBMISSION_ONLY_SYSCALLS.contains(&other)
                    && self.context.this.as_deref() != Some(SUBMISSION_CONTRACT)
                {
                    return Err(VmExecutionError::new(
                        "Contract metadata changes are restricted to submission.",
                    ));
                }
                if let Some(cost) = explicit_syscall_metering_cost(other, &args, &kwargs)? {
                    host.charge_execution_cost(cost)?;
                }
                host.handle_syscall(
                    other,
                    args.iter()
                        .map(VmValue::detached)
                        .collect::<Result<_, _>>()?,
                    kwargs
                        .into_iter()
                        .map(|(k, v)| Ok((k, v.detached()?)))
                        .collect::<Result<_, VmExecutionError>>()?,
                )
            }
        }
    }

    pub(super) fn resolve_contract_target(
        &mut self,
        value: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmContractTarget, VmExecutionError> {
        let object = as_object(value, "contract_target")?;
        match required_string(object, "kind")? {
            "static_import" => {
                let binding = required_string(object, "binding")?.to_owned();
                let module = self.imports.get(&binding).cloned().ok_or_else(|| {
                    VmExecutionError::new(format!("unknown static import binding '{binding}'"))
                })?;
                Ok(VmContractTarget::StaticImport { binding, module })
            }
            "dynamic_import" => {
                let source = required_value(object, "source")?;
                let handle = self
                    .eval_expression(source, scope, host)?
                    .as_contract_handle()?;
                Ok(VmContractTarget::DynamicImport {
                    module: handle.module,
                })
            }
            "local_handle" => {
                let binding = required_string(object, "binding")?.to_owned();
                let source = required_value(object, "source")?;
                let handle = self
                    .eval_expression(source, scope, host)?
                    .as_contract_handle()?;
                Ok(VmContractTarget::LocalHandle {
                    binding,
                    module: handle.module,
                })
            }
            "factory_call" => {
                let factory = required_string(object, "factory")?.to_owned();
                let source = required_value(object, "source")?;
                let handle = self
                    .eval_expression(source, scope, host)?
                    .as_contract_handle()?;
                Ok(VmContractTarget::FactoryCall {
                    factory,
                    module: handle.module,
                })
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported contract target kind '{other}'"
            ))),
        }
    }

    fn syscall_contract_call(
        &mut self,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if !kwargs.is_empty() || args.len() > 3 {
            return Err(VmExecutionError::new(
                "contract.call expects target, function, and optional kwargs dict",
            ));
        }
        let target = match args
            .first()
            .cloned()
            .ok_or_else(|| VmExecutionError::new("contract.call expects a target"))?
        {
            VmValue::String(module) => VmContractTarget::DynamicImport { module },
            VmValue::ContractHandle(handle) => VmContractTarget::DynamicImport {
                module: handle.module,
            },
            other => {
                return Err(VmExecutionError::new(format!(
                    "contract.call target must be a contract name or handle, got {}",
                    other.type_name()
                )))
            }
        };
        let function = args
            .get(1)
            .ok_or_else(|| VmExecutionError::new("contract.call expects a function"))?
            .as_string()?;
        let call_kwargs = match args.get(2) {
            None | Some(VmValue::None) => Vec::new(),
            Some(VmValue::Dict(entries)) => entries
                .iter()
                .map(|(key, value)| Ok((key.as_string()?, value.clone())))
                .collect::<Result<Vec<_>, VmExecutionError>>()?,
            Some(other) => {
                return Err(VmExecutionError::new(format!(
                    "contract.call kwargs must be a dict, got {}",
                    other.type_name()
                )))
            }
        };
        host.call_contract_shared(VmContractCall {
            target,
            function,
            args: Vec::new(),
            kwargs: call_kwargs,
            caller_contract: self.context.this.clone(),
            signer: self.context.signer.clone(),
            entry: self.context.entry.clone(),
            submission_name: self.context.submission_name.clone(),
            now: self.context.now.clone(),
            block_num: self.context.block_num.clone(),
            block_hash: self.context.block_hash.clone(),
            chain_id: self.context.chain_id.clone(),
        })
    }

    fn syscall_emit_event(
        &mut self,
        object: &Map<String, Value>,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        host.charge_execution_cost(VM_GAS_EVENT_EMIT)?;
        let event_binding = required_string(object, "event_binding")?;
        let event = self.globals.get(event_binding).cloned().ok_or_else(|| {
            VmExecutionError::new(format!("unknown event binding '{event_binding}'"))
        })?;
        let event = match event {
            VmValue::EventRef(event) => *event,
            other => {
                return Err(VmExecutionError::new(format!(
                    "binding '{event_binding}' is not an event reference but {}",
                    other.type_name()
                )))
            }
        };
        let payload = if let Some(first) = args.first() {
            first.clone()
        } else if kwargs.is_empty() {
            VmValue::None
        } else {
            VmValue::Dict(
                kwargs
                    .iter()
                    .map(|(key, value)| (VmValue::String(key.clone()), value.clone()))
                    .collect(),
            )
        };
        let (data_indexed, data) = normalize_event_payload(&event.params, payload)?;
        for (key, value) in data_indexed.iter().map(|(key, value)| (key, value)) {
            host.charge_storage_write(key, value)?;
        }
        for (key, value) in data.iter().map(|(key, value)| (key, value)) {
            host.charge_storage_write(key, value)?;
        }
        host.emit_event(VmEvent {
            contract: self
                .context
                .this
                .clone()
                .unwrap_or_else(|| self.module.module_name.clone()),
            event: event.event_name,
            signer: option_string_value(&self.context.signer),
            caller: option_string_value(&self.context.caller),
            data_indexed,
            data,
        })?;
        Ok(VmValue::None)
    }

    fn syscall_variable_set(
        &mut self,
        object: &Map<String, Value>,
        args: Vec<VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        host.charge_execution_cost(VM_GAS_VARIABLE_SET)?;
        let binding = required_string(object, "receiver_binding")?;
        let value = args
            .first()
            .cloned()
            .ok_or_else(|| VmExecutionError::new("Variable.set expects one argument"))?;
        self.variable_set(binding, value.clone())?;
        let storage_key = variable_storage_key(&self.module.module_name, binding);
        host.record_storage_write(&storage_key, &value.detached()?)?;
        host.charge_storage_write(&storage_key, &value.detached()?)?;
        Ok(VmValue::None)
    }
}
