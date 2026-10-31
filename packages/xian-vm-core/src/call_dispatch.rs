//! Resolve callable values and evaluate call arguments in source order.
use super::*;

impl VmInstance {
    pub(super) fn host_binding_root_is_shadowed(
        &self,
        object: &Map<String, Value>,
        scope: &HashMap<String, VmValue>,
    ) -> Result<bool, VmExecutionError> {
        let Some(root) = ir_root_name(required_value(object, "value")?)? else {
            return Ok(false);
        };
        Ok(scope.contains_key(root) || self.globals.contains_key(root))
    }

    pub(super) fn resolve_host_binding(
        &self,
        host_binding_id: &str,
    ) -> Result<VmValue, VmExecutionError> {
        match host_binding_id {
            "numeric.decimal.new" => Ok(VmValue::TypeMarker("decimal".to_owned())),
            "typing.any" => Ok(VmValue::TypeMarker("Any".to_owned())),
            "storage.variable.new" => Ok(VmValue::TypeMarker("Variable".to_owned())),
            "storage.hash.new" => Ok(VmValue::TypeMarker("Hash".to_owned())),
            "storage.foreign_variable.new" => Ok(VmValue::TypeMarker("ForeignVariable".to_owned())),
            "storage.foreign_hash.new" => Ok(VmValue::TypeMarker("ForeignHash".to_owned())),
            "event.log.new" => Ok(VmValue::TypeMarker("LogEvent".to_owned())),
            "module.importlib" => Ok(VmValue::Builtin("importlib".to_owned())),
            "module.hashlib" => Ok(VmValue::Builtin("hashlib".to_owned())),
            "module.crypto" => Ok(VmValue::Builtin("crypto".to_owned())),
            "module.datetime" => Ok(VmValue::Builtin("datetime".to_owned())),
            "module.random" => Ok(VmValue::Builtin("random".to_owned())),
            "module.zk" => Ok(VmValue::Builtin("zk".to_owned())),
            "time.datetime.new" | "time.datetime.strptime" => {
                Ok(VmValue::TypeMarker("datetime.datetime".to_owned()))
            }
            "time.timedelta.new" => Ok(VmValue::TypeMarker("datetime.timedelta".to_owned())),
            "time.seconds" => Ok(VmValue::TimeDelta(VmTimeDelta::new(0, 0, 0, 0, 1)?)),
            "time.minutes" => Ok(VmValue::TimeDelta(VmTimeDelta::new(0, 0, 0, 1, 0)?)),
            "time.hours" => Ok(VmValue::TimeDelta(VmTimeDelta::new(0, 0, 1, 0, 0)?)),
            "time.days" => Ok(VmValue::TimeDelta(VmTimeDelta::new(0, 1, 0, 0, 0)?)),
            "time.weeks" => Ok(VmValue::TimeDelta(VmTimeDelta::new(1, 0, 0, 0, 0)?)),
            "context.caller" => Ok(option_string_value(&self.context.caller)),
            "context.signer" => Ok(option_string_value(&self.context.signer)),
            "context.this" => Ok(option_string_value(&self.context.this)),
            "context.owner" => Ok(option_string_value(&self.context.owner)),
            "context.entry" => Ok(option_entry_value(&self.context.entry)),
            "context.submission_name" => Ok(option_string_value(&self.context.submission_name)),
            "env.now" => Ok(self.context.now.clone()),
            "env.block_num" => Ok(self.context.block_num.clone()),
            "env.block_hash" => Ok(self.context.block_hash.clone()),
            "env.chain_id" => Ok(self.context.chain_id.clone()),
            other => Err(VmExecutionError::new(format!(
                "unsupported host binding '{other}'"
            ))),
        }
    }

    pub(super) fn eval_call(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let func = required_value(object, "func")?;
        if let Some(syscall_id) = optional_string(object, "syscall_id") {
            let target = object
                .get("contract_target")
                .filter(|v| !v.is_null())
                .map(|v| self.resolve_contract_target(v, scope, host))
                .transpose()?;
            let args = self.eval_call_arguments(required_array(object, "args")?, scope, host)?;
            let kwargs =
                self.eval_call_keywords(required_array(object, "keywords")?, scope, host, None)?;
            return self.eval_syscall(object, syscall_id, args, kwargs, scope, host, target);
        }
        let callable = as_object(func, "callable")?;
        if required_string(callable, "node")? == "attribute"
            && optional_string(callable, "host_binding_id").is_none()
        {
            let receiver = self.eval_expression(required_value(callable, "value")?, scope, host)?;
            let method = required_string(callable, "attr")?;
            let args = self.eval_call_arguments(required_array(object, "args")?, scope, host)?;
            let kwargs =
                self.eval_call_keywords(required_array(object, "keywords")?, scope, host, None)?;
            return self.call_receiver(receiver, method, args, kwargs, host);
        }
        let callee = self.eval_expression(func, scope, host)?;
        let args = self.eval_call_arguments(required_array(object, "args")?, scope, host)?;
        let function_name = match &callee {
            VmValue::FunctionRef(name) => Some(name.as_str()),
            _ => None,
        };
        let kwargs = self.eval_call_keywords(
            required_array(object, "keywords")?,
            scope,
            host,
            function_name,
        )?;
        self.call_callable_value(host, callee, args, kwargs)
    }

    pub(super) fn next_item(
        &mut self,
        iterator: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        let item = crate::iteration::next(iterator, &mut |function, args| {
            self.call_callable_value(host, function, args, vec![])
        })?;
        item.map(|value| self.heap.capture(value)).transpose()
    }

    pub(super) fn collect_iterable(
        &mut self,
        value: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<Vec<VmValue>, VmExecutionError> {
        let heap = self.heap.clone();
        crate::iteration::collect(value, &heap, &mut |function, args| {
            self.call_callable_value(host, function, args, vec![])
        })
    }

    pub(super) fn extend_sequence(
        &mut self,
        receiver: &VmValue,
        source: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<(), VmExecutionError> {
        // Self-extension uses the original sequence, as Python does.
        let source = if receiver.identical(source) {
            self.heap.capture(source.snapshot())?
        } else {
            source.clone()
        };
        let iterator = crate::iteration::iter(&source, &self.heap)?;
        let VmValue::Reference(reference) = receiver else {
            return Err(VmExecutionError::new("invalid mutable sequence"));
        };
        while let Some(item) = self.next_item(&iterator, host)? {
            reference.append_sequence(item)?;
        }
        Ok(())
    }

    pub(super) fn call_receiver(
        &mut self,
        receiver: VmValue,
        method: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if method == "to_eng_string" {
            if let VmValue::RawDecimal(value) = receiver.snapshot() {
                if !args.is_empty() || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "to_eng_string() expects no arguments",
                    ));
                }
                return Ok(VmValue::String(value.engineering()));
            }
        }
        if method == "update" && matches!(receiver.snapshot(), VmValue::Dict(_)) {
            return self.update_dictionary(&receiver, args, kwargs, host);
        }
        if method == "setdefault" && matches!(receiver.snapshot(), VmValue::Dict(_)) {
            return collection_methods::setdefault(&receiver, args, kwargs, host);
        }
        if method == "reverse" && matches!(receiver.snapshot(), VmValue::List(_)) {
            return collection_methods::reverse(&receiver, args, kwargs, host);
        }
        if method == "fromhex"
            && (matches!(&receiver, VmValue::Builtin(name) if name == "bytes")
                || matches!(receiver.snapshot(), VmValue::Bytes(_)))
        {
            return collection_methods::fromhex(args, kwargs, host);
        }
        if method == "sort" && matches!(receiver.snapshot(), VmValue::List(_)) {
            return self.sort_list(receiver, args, kwargs, host);
        }
        if method == "fromkeys"
            && (matches!(&receiver, VmValue::Builtin(name) if name == "dict")
                || matches!(receiver.snapshot(), VmValue::Dict(_)))
        {
            if args.is_empty() || args.len() > 2 || !kwargs.is_empty() {
                return Err(VmExecutionError::new(
                    "dict.fromkeys() expects one or two arguments",
                ));
            }
            let default = args.get(1).cloned().unwrap_or(VmValue::None);
            let iterator = crate::iteration::iter(&args[0], &self.heap)?;
            let mut entries = Vec::new();
            while let Some(key) = self.next_item(&iterator, host)? {
                dict_set(&mut entries, key, default.clone())?;
            }
            return Ok(VmValue::Dict(entries));
        }
        if matches!(method, "keys" | "values" | "items")
            && matches!(receiver.snapshot(), VmValue::Dict(_))
        {
            if !args.is_empty() || !kwargs.is_empty() {
                return Err(VmExecutionError::new(
                    "dictionary view methods accept no arguments",
                ));
            }
            let mode = match method {
                "keys" => crate::iteration::ViewMode::Keys,
                "values" => crate::iteration::ViewMode::Values,
                _ => crate::iteration::ViewMode::Items,
            };
            return Ok(VmValue::View(Box::new(crate::VmDictView {
                source: receiver,
                mode,
            })));
        }
        if let VmValue::StorageRef(reference) = &receiver {
            if matches!(method, "clear" | "clone_from") {
                return self.hash_bulk_method(reference, method, args, kwargs, host);
            }
        }
        if let VmValue::ForeignStorageRef(reference) = &receiver {
            return foreign_storage::call_method(reference, method, args, kwargs, host);
        }
        if method == "append" && receiver.is_mutable_sequence() {
            if args.len() != 1 || !kwargs.is_empty() {
                return Err(VmExecutionError::new("append() expects one argument"));
            }
            if let VmValue::Reference(reference) = receiver {
                reference.append_sequence(args[0].clone())?;
            }
            return Ok(VmValue::None);
        }
        if method == "extend" && receiver.is_mutable_sequence() {
            if args.len() != 1 || !kwargs.is_empty() {
                return Err(VmExecutionError::new("extend() expects one argument"));
            }
            self.extend_sequence(&receiver, &args[0], host)?;
            return Ok(VmValue::None);
        }
        let heap = self.heap.clone();
        match call_native_method_with(
            receiver.clone(),
            method,
            args,
            kwargs,
            &heap,
            &mut |function, args| self.call_callable_value(host, function, args, vec![]),
        )? {
            NativeMethodResult::Value(value) => Ok(value),
            NativeMethodResult::Mutated {
                receiver: updated,
                value,
            } => {
                if let VmValue::Reference(reference) = receiver {
                    if method == "clear" {
                        reference.clear_dictionary_slots();
                    }
                    reference.replace(updated)?;
                }
                Ok(value)
            }
        }
    }

    pub(super) fn eval_call_arguments(
        &mut self,
        args: &[Value],
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<Vec<VmValue>, VmExecutionError> {
        self.expand_values(args, scope, host)
    }

    pub(super) fn eval_call_keywords(
        &mut self,
        keywords: &[Value],
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
        function_name: Option<&str>,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        let mut values = Vec::new();
        let mut seen = HashSet::new();
        for keyword in keywords {
            let keyword_object = as_object(keyword, "keyword")?;
            match keyword_object
                .get("node")
                .and_then(Value::as_str)
                .unwrap_or("keyword")
            {
                "keyword" => {
                    let name = required_string(keyword_object, "arg")?.to_owned();
                    let value = self.eval_expression(
                        required_value(keyword_object, "value")?,
                        scope,
                        host,
                    )?;
                    if !seen.insert(name.clone()) {
                        return Err(unpacking::duplicate_keyword(function_name, &name));
                    }
                    values.push((name, value));
                }
                "keyword_unpack" => {
                    let unpacked = self.eval_expression(
                        required_value(keyword_object, "value")?,
                        scope,
                        host,
                    )?;
                    let VmValue::Dict(entries) = unpacked.snapshot() else {
                        return Err(VmExecutionError::new(
                            "keyword unpacking requires a dict value",
                        ));
                    };
                    for (key, value) in entries {
                        let key = key.as_string()?;
                        if !seen.insert(key.clone()) {
                            return Err(unpacking::duplicate_keyword(function_name, &key));
                        }
                        if values.len() >= MAX_SEQUENCE_LENGTH {
                            return Err(VmExecutionError::new("keyword expansion limit exceeded"));
                        }
                        host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
                        values.push((key, value));
                    }
                }
                other => {
                    return Err(VmExecutionError::new(format!(
                        "unsupported keyword node '{other}'"
                    )))
                }
            }
        }
        Ok(values)
    }
}
