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
        Ok(self.lexical_bindings.contains(root)
            || scope.contains_key(root)
            || self.globals.contains_key(root))
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
            "time.datetime.new" => Ok(VmValue::TypeMarker("datetime.datetime".to_owned())),
            "time.datetime.strptime" => Ok(VmValue::BoundMethod(Box::new(VmBoundMethod {
                receiver: VmValue::TypeMarker("datetime.datetime".into()),
                method: "strptime".into(),
            }))),
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
            other => VmHostCallable::for_syscall(other, None)
                .map(VmHostCallable::value)
                .ok_or_else(|| {
                    VmExecutionError::new(format!("unsupported host binding '{other}'"))
                }),
        }
    }

    pub(super) fn eval_call(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let func = required_value(object, "func")?;
        let lexical_call = self.optimized_call_is_local(func)?;
        if optional_string(object, "syscall_id") == Some("contract.export_call")
            && func.get("node").and_then(Value::as_str) == Some("attribute")
        {
            return self.eval_public_attribute_call(
                object,
                as_object(func, "callable")?,
                scope,
                host,
            );
        }
        if let Some(syscall_id) = optional_string(object, "syscall_id").filter(|_| !lexical_call) {
            let target = object
                .get("contract_target")
                .filter(|v| !v.is_null())
                .map(|v| self.resolve_contract_target(v, scope, host))
                .transpose()?;
            let args = self.eval_call_arguments(required_array(object, "args")?, scope, host)?;
            let kwargs =
                self.eval_call_keywords(required_array(object, "keywords")?, scope, host, None)?;
            let (args, kwargs) = if let Some(binding) = optional_string(object, "receiver_binding")
            {
                let method = as_object(func, "callable")?
                    .get("attr")
                    .and_then(Value::as_str);
                match (self.globals.get(binding), method) {
                    (Some(receiver), Some(method))
                        if method_signatures::supports(receiver, method) =>
                    {
                        method_signatures::bind(receiver, method, args, kwargs)?
                    }
                    _ => (args, kwargs),
                }
            } else {
                (args, kwargs)
            };
            let member = as_object(func, "callable")?
                .get("attr")
                .and_then(Value::as_str);
            if let Some(callable) = VmHostCallable::for_syscall(syscall_id, member) {
                return self.call_host_callable(callable, args, kwargs, host);
            }
            return self.eval_syscall(object, syscall_id, args, kwargs, scope, host, target);
        }
        let callable = as_object(func, "callable")?;
        if required_string(callable, "node")? == "attribute"
            && optional_string(callable, "host_binding_id").is_none()
        {
            return self.eval_public_attribute_call(object, callable, scope, host);
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
        self.call_expression_callable_value(host, callee, args, kwargs)
    }

    fn eval_public_attribute_call(
        &mut self,
        object: &Map<String, Value>,
        callable: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let receiver = self.eval_expression(required_value(callable, "value")?, scope, host)?;
        let method = required_string(callable, "attr")?;
        let callee = self.read_attribute(receiver, method, host)?;
        let args = self.eval_call_arguments(required_array(object, "args")?, scope, host)?;
        let kwargs =
            self.eval_call_keywords(required_array(object, "keywords")?, scope, host, None)?;
        return self.call_expression_callable_value(host, callee, args, kwargs);
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
        let receiver = attributes::invocation_receiver(receiver);
        if let Some(class) = orm_methods::class_method(&receiver, method) {
            return self.call_orm_class_method(class, method, args, kwargs, host);
        }
        if method == "is_of" {
            if let Some(class) = interface_descriptors::descriptor_class(&receiver) {
                return self.call_interface_class_method(class, args, kwargs, host);
            }
        }
        if resolves_to!(receiver, VmValue::InterfaceDescriptor(_)) {
            return self.call_interface_method(&receiver, method, args, kwargs, host);
        }
        if deployment_handles::is_instance(&receiver)
            || (deployment_handles::is_class(&receiver) && method == "submit")
        {
            return self.call_deployment_method(&receiver, method, args, kwargs, host);
        }
        if resolves_to!(receiver,VmValue::Builtin(ref module) if module=="Contract") {
            let callable = VmHostCallable::named(&format!("Contract.{method}"))
                .ok_or_else(|| VmExecutionError::new("unknown Contract method"))?;
            return self.call_host_callable(callable, args, kwargs, host);
        }
        if let Some(handle) = receiver.with_resolved(|resolved| match resolved {
            VmValue::ContractHandle(handle) => Some(handle.clone()),
            _ => None,
        }) {
            return self.call_contract_export(handle, method, args, kwargs, host);
        }
        if let Some(class) = method_signatures::wrapper_class(&receiver, method) {
            return self.call_wrapper_function(class, method, args, kwargs, host);
        }
        if let Some(kind) = method_signatures::unbound_class(&receiver, method) {
            let mut arguments = args.into_iter();
            let instance = arguments.next().ok_or_else(|| {
                VmExecutionError::new("unbound method requires a positional receiver")
            })?;
            if !method_signatures::receiver_matches(kind, &instance) {
                return Err(VmExecutionError::new(
                    "unbound method received an incompatible receiver",
                ));
            }
            return self.call_receiver(instance, method, arguments.collect(), kwargs, host);
        }
        let (mut args, kwargs) = method_signatures::bind(&receiver, method, args, kwargs)?;
        if let Some(event) = receiver.with_resolved(|resolved| match resolved {
            VmValue::EventRef(event) => Some(event.clone()),
            _ => None,
        }) {
            return self.emit_declared_event(&event, args.remove(0), host);
        }
        if let Some(mapping) = receiver.with_resolved(|resolved| match resolved {
            VmValue::MappingProxy(mapping) => Some(mapping.clone()),
            _ => None,
        }) {
            return self.call_receiver(*mapping, method, args, kwargs, host);
        }
        if let Some(template) = receiver.with_resolved(|resolved| match resolved {
            VmValue::String(template) => Some(template.clone()),
            _ => None,
        }) {
            if matches!(method, "format" | "format_map") {
                return self.format_string(host, &template, args, kwargs, method == "format_map");
            }
            charge_method_work(
                host,
                support::string_methods::work_cost(&template, method, &args)?,
            )?;
            if method == "translate" {
                let table = args[0].snapshot();
                if matches!(
                    table,
                    VmValue::StorageRef(_) | VmValue::ForeignStorageRef(_)
                ) {
                    let text = support::string_methods::translate_with(&template, |character| {
                        host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
                        let key = vm_int(character as u32);
                        let value = match &table {
                            VmValue::StorageRef(reference) => {
                                self.hash_get(&reference.binding, &key, host)?
                            }
                            VmValue::ForeignStorageRef(reference) => {
                                foreign_storage::read_hash(reference, &key, host)?
                            }
                            _ => unreachable!(),
                        };
                        Ok(Some(value))
                    })?;
                    return Ok(VmValue::String(text));
                }
            }
        }
        if resolves_to!(receiver, VmValue::Builtin(ref name) if name == "str")
            && method == "maketrans"
        {
            charge_method_work(host, support::string_methods::work_cost("", method, &args)?)?;
            return support::string_methods::call("", method, &args);
        }
        if resolves_to!(receiver, VmValue::Bytes(_) | VmValue::ByteArray(_))
            || resolves_to!(receiver, VmValue::Builtin(ref name) if matches!(name.as_str(), "bytes" | "bytearray"))
        {
            charge_method_work(
                host,
                support::binary_methods::work_cost(&receiver, method, &args),
            )?;
        }
        if crate::scalar_methods::supports(&receiver, method) {
            charge_method_work(
                host,
                crate::scalar_methods::work_cost(&receiver, method, &args),
            )?;
            if method == "from_bytes"
                && !resolves_to!(
                    args[0],
                    VmValue::Bytes(_)
                        | VmValue::ByteArray(_)
                        | VmValue::List(_)
                        | VmValue::Tuple(_)
                )
            {
                args[0] = VmValue::List(self.collect_iterable(&args[0], host)?);
            }
            return crate::scalar_methods::call(&receiver, method, args);
        }
        if resolves_to!(receiver, VmValue::RawDecimal(_)) {
            host.charge_execution_cost(crate::decimal_methods::work_cost(
                method, &receiver, &args, &kwargs,
            ))?;
            return crate::decimal_methods::call(receiver, method, args, kwargs);
        }
        if method == "strptime"
            && (resolves_to!(receiver, VmValue::DateTime(_))
                || resolves_to!(receiver, VmValue::TypeMarker(ref name) if name == "datetime.datetime"))
        {
            return time_datetime_strptime(args, kwargs, host);
        }
        if method == "copy" && resolves_to!(receiver, VmValue::FrozenSet(_)) {
            if !args.is_empty() || !kwargs.is_empty() {
                return Err(VmExecutionError::new(
                    "frozenset.copy() expects no arguments",
                ));
            }
            return Ok(receiver);
        }
        if matches!(
            method,
            "count" | "index" | "remove" | "get" | "pop" | "setdefault"
        ) {
            if let Some(needle) = args.first() {
                crate::decimal_metering::comparison(host, &receiver, needle, false)?;
            }
        }
        let set_comparison = resolves_to!(
            receiver,
            VmValue::Set(_) | VmValue::FrozenSet(_) | VmValue::BuiltinSet(_)
        ) && matches!(
            method,
            "add"
                | "remove"
                | "discard"
                | "issubset"
                | "issuperset"
                | "isdisjoint"
                | "union"
                | "intersection"
                | "difference"
                | "symmetric_difference"
                | "update"
                | "intersection_update"
                | "difference_update"
                | "symmetric_difference_update"
        );
        if set_comparison {
            let mut values = vec![receiver.clone()];
            values.extend(args.iter().cloned());
            crate::decimal_metering::normalization(host, &values)?;
        }
        if resolves_to!(receiver, VmValue::BuiltinSet(_)) {
            return self.call_builtin_set_method(receiver, method, args, host);
        }
        if method == "isdisjoint" && resolves_to!(receiver, VmValue::View(_)) {
            return self.view_isdisjoint(&receiver, &args[0], host);
        }
        if method == "update" && resolves_to!(receiver, VmValue::Dict(_)) {
            return self.update_dictionary(&receiver, args, kwargs, host);
        }
        if method == "setdefault" && resolves_to!(receiver, VmValue::Dict(_)) {
            return collection_methods::setdefault(&receiver, args, kwargs, host);
        }
        if method == "reverse" && resolves_to!(receiver, VmValue::List(_)) {
            return collection_methods::reverse(&receiver, args, kwargs, host);
        }
        if method == "fromhex"
            && (matches!(&receiver, VmValue::Builtin(name) if name == "bytes")
                || resolves_to!(receiver, VmValue::Bytes(_)))
        {
            return collection_methods::fromhex(args, kwargs, host);
        }
        if method == "sort" && resolves_to!(receiver, VmValue::List(_)) {
            return self.sort_list(receiver, args, kwargs, host);
        }
        if method == "fromkeys"
            && (matches!(&receiver, VmValue::Builtin(name) if name == "dict")
                || resolves_to!(receiver, VmValue::Dict(_)))
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
                crate::decimal_metering::comparison(
                    host,
                    &VmValue::Dict(entries.clone()),
                    &key,
                    false,
                )?;
                dict_set(&mut entries, key, default.clone())?;
            }
            return Ok(VmValue::Dict(entries));
        }
        if matches!(method, "keys" | "values" | "items") && resolves_to!(receiver, VmValue::Dict(_))
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
            if matches!(
                reference.storage_type.as_str(),
                "Variable" | "ForeignVariable"
            ) {
                return self.variable_method(reference, method, args, kwargs, host);
            }
            if method == "all" {
                host.charge_execution_cost(VM_GAS_HASH_SCAN)?;
                return self.hash_all(&reference.binding, &args, host);
            }
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
        let mut set_inputs = if set_comparison {
            Some(crate::decimal_metering::SetInputs::new(&receiver)?)
        } else {
            None
        };
        match call_native_method_collected(receiver.clone(), method, args, kwargs, &mut |source| {
            let values = self.collect_iterable(source, host)?;
            if method == "join" && resolves_to!(receiver, VmValue::Bytes(_) | VmValue::ByteArray(_))
            {
                let content = values.iter().fold(0u64, |total, value| {
                    total.saturating_add(binary_length(value))
                });
                let separators =
                    binary_length(&receiver).saturating_mul(values.len().saturating_sub(1) as u64);
                charge_method_work(host, content.saturating_add(separators))?;
            }
            if let Some(inputs) = &mut set_inputs {
                inputs.collected(host, &values)?;
            }
            Ok(values)
        })? {
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

    fn call_wrapper_function(
        &mut self,
        class: &str,
        method: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let (instance, args, kwargs) = method_signatures::bind_wrapper_receiver(args, kwargs)?;
        if method == "copy" {
            return self.call_wrapper_copy(class, instance, args, kwargs, host);
        }
        if !method_signatures::wrapper_receiver_compatible(&instance, method) {
            return Err(VmExecutionError::new(
                "unbound method received an incompatible receiver",
            ));
        }
        self.call_receiver(instance, method, args, kwargs, host)
    }

    fn call_wrapper_copy(
        &mut self,
        class: &str,
        instance: VmValue,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if !args.is_empty() || !kwargs.is_empty() {
            return Err(VmExecutionError::new("copy() expects only self"));
        }
        if class == "frozenset" {
            return Ok(instance);
        }
        if !method_signatures::wrapper_receiver_compatible(&instance, "copy") {
            return Err(VmExecutionError::new(
                "unbound method received an incompatible receiver",
            ));
        }
        fn copy_work(value: &VmValue) -> u64 {
            match value {
                VmValue::Reference(reference) => reference.with_value(copy_work),
                VmValue::Set(items) | VmValue::FrozenSet(items) => items.len() as u64,
                _ => 0,
            }
        }
        charge_method_work(host, copy_work(&instance))?;
        Ok(instance.snapshot())
    }

    fn variable_method(
        &mut self,
        reference: &VmStorageRef,
        method: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let mut object = Map::new();
        object.insert(
            "receiver_binding".into(),
            Value::String(reference.binding.clone()),
        );
        if matches!(method, "get" | "set") {
            let syscall = if method == "get" {
                "storage.variable.get"
            } else {
                "storage.variable.set"
            };
            return self.eval_syscall(
                &object,
                syscall,
                args,
                kwargs,
                &mut HashMap::new(),
                host,
                None,
            );
        }
        if reference.storage_type == "ForeignVariable" {
            return Err(VmExecutionError::new("foreign variables are read-only"));
        }
        let value = self.variable_get(&reference.binding, host)?;
        let value = self.heap.capture(value)?;
        let result = self.call_receiver(value.clone(), method, args, kwargs, host)?;
        self.eval_syscall(
            &object,
            "storage.variable.set",
            vec![value],
            vec![],
            &mut HashMap::new(),
            host,
            None,
        )?;
        Ok(result)
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

fn binary_length(value: &VmValue) -> u64 {
    match value {
        VmValue::Reference(reference) => reference.with_value(binary_length),
        VmValue::Bytes(value) | VmValue::ByteArray(value) => value.len() as u64,
        _ => 0,
    }
}

fn charge_method_work(host: &mut dyn VmHost, cost: u64) -> Result<(), VmExecutionError> {
    if cost > 0 {
        host.charge_execution_cost(cost)?;
    }
    Ok(())
}
