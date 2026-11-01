//! Evaluate expressions, capturing heap identity at the eval_expression boundary.
use super::*;

impl VmInstance {
    pub(super) fn read_subscript(
        &mut self,
        value: VmValue,
        index: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let value = match value.snapshot() {
            VmValue::MappingProxy(mapping) => *mapping,
            _ => value,
        };
        if matches!(value.snapshot(), VmValue::Dict(_)) {
            crate::decimal_metering::comparison(host, &value, index, false)?;
        }
        let value = if let VmValue::StorageRef(reference) = &value {
            if reference.storage_type != "Hash" {
                return Err(VmExecutionError::new(
                    "storage value does not support indexing",
                ));
            }
            self.hash_get(&reference.binding, index, host)?
        } else if let VmValue::ForeignStorageRef(reference) = &value {
            foreign_storage::read_hash(reference, index, host)?
        } else {
            subscript_value(value, index)?
        };
        self.heap.capture(value)
    }

    pub(super) fn eval_slice_subscript(
        &mut self,
        value: VmValue,
        slice: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let mut bounds = Vec::new();
        for name in ["lower", "upper", "step"] {
            let bound = match slice.get(name) {
                Some(Value::Null) | None => None,
                Some(expression) => {
                    let value = self.eval_expression(expression, scope, host)?;
                    if matches!(value, VmValue::None) {
                        None
                    } else {
                        Some(value.as_bigint()?)
                    }
                }
            };
            bounds.push(bound);
        }
        let step = bounds.pop().unwrap();
        let upper = bounds.pop().unwrap();
        let lower = bounds.pop().unwrap();
        subscript_slice_value(value, lower, upper, step)
    }

    pub(super) fn eval_expression(
        &mut self,
        expression: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let value = self.eval_expression_value(expression, scope, host)?;
        self.heap.capture(value)
    }

    pub(super) fn eval_expression_value(
        &mut self,
        expression: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let object = as_object(expression, "expression")?;
        let node = required_string(object, "node")?;
        host.charge_execution_cost(vm_expression_gas_cost(node, object)?)?;
        match node {
            "name" => self.eval_name(object, scope),
            "constant" => self.eval_constant(object),
            "list" => {
                let values =
                    self.expand_values(required_array(object, "elements")?, scope, host)?;
                Ok(VmValue::List(values))
            }
            "list_comp" => self.eval_list_comprehension(object, scope, host),
            "dict_comp" => self.eval_dict_comprehension(object, scope, host),
            "tuple" => {
                let values =
                    self.expand_values(required_array(object, "elements")?, scope, host)?;
                Ok(VmValue::Tuple(values))
            }
            "dict" => self.eval_dict(object, scope, host),
            "attribute" => self.eval_attribute(object, scope, host),
            "subscript" => self.eval_subscript(object, scope, host),
            "storage_get" => {
                let binding = required_string(object, "binding")?;
                let key = self.eval_expression(required_value(object, "key")?, scope, host)?;
                self.hash_get(binding, &key, host)
            }
            "slice" => Err(VmExecutionError::new(
                "slice expressions are only supported as subscripts",
            )),
            "call" => self.eval_call(object, scope, host),
            "compare" => self.eval_compare(object, scope, host),
            "bool_op" => self.eval_bool_op(object, scope, host),
            "bin_op" => self.eval_bin_op(object, scope, host),
            "unary_op" => {
                let operand =
                    self.eval_expression(required_value(object, "operand")?, scope, host)?;
                apply_unary_operator(required_string(object, "operator")?, operand)
            }
            "if_expr" => {
                let test = self.eval_expression(required_value(object, "test")?, scope, host)?;
                if test.truthy() {
                    self.eval_expression(required_value(object, "body")?, scope, host)
                } else {
                    self.eval_expression(required_value(object, "orelse")?, scope, host)
                }
            }
            "f_string" => {
                let mut buffer = String::new();
                for value in required_array(object, "values")? {
                    buffer.push_str(
                        &self
                            .eval_expression(value, scope, host)?
                            .try_python_repr()?,
                    );
                }
                Ok(VmValue::String(buffer))
            }
            "formatted_value" => self.eval_formatted_value(object, scope, host),
            other => Err(VmExecutionError::new(format!(
                "unsupported expression node '{other}'"
            ))),
        }
    }

    pub(super) fn eval_list_comprehension(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let element = required_value(object, "element")?;
        let generators = required_array(object, "generators")?;
        let mut results = Vec::new();
        self.eval_list_comprehension_generator(generators, 0, element, scope, host, &mut results)?;
        Ok(VmValue::List(results))
    }

    pub(super) fn eval_list_comprehension_generator(
        &mut self,
        generators: &[Value],
        index: usize,
        element: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
        results: &mut Vec<VmValue>,
    ) -> Result<(), VmExecutionError> {
        let generator = as_object(
            generators
                .get(index)
                .ok_or_else(|| VmExecutionError::new("missing list comprehension generator"))?,
            "list comprehension generator",
        )?;
        let target = required_value(generator, "target")?;
        let iter_value = self.eval_expression(required_value(generator, "iter")?, scope, host)?;
        let iterator = crate::iteration::iter(&iter_value, &self.heap)?;
        let previous_bindings = capture_target_bindings(target, scope)?;

        while let Some(item) = self.next_item(&iterator, host)? {
            host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
            self.assign_target(target, item, scope, host, false)?;
            let mut allowed = true;
            for condition in required_array(generator, "ifs")? {
                if !self.eval_expression(condition, scope, host)?.truthy() {
                    allowed = false;
                    break;
                }
            }
            if !allowed {
                continue;
            }
            if index + 1 == generators.len() {
                if results.len() >= MAX_SEQUENCE_LENGTH {
                    return Err(VmExecutionError::new(
                        "comprehension exceeds allocation limit",
                    ));
                }
                results.push(self.eval_expression(element, scope, host)?);
            } else {
                self.eval_list_comprehension_generator(
                    generators,
                    index + 1,
                    element,
                    scope,
                    host,
                    results,
                )?;
            }
        }

        restore_target_bindings(scope, previous_bindings);
        Ok(())
    }

    pub(super) fn eval_dict_comprehension(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let key = required_value(object, "key")?;
        let value = required_value(object, "value")?;
        let generators = required_array(object, "generators")?;
        let mut results = Vec::new();
        self.eval_dict_comprehension_generator(
            generators,
            0,
            key,
            value,
            scope,
            host,
            &mut results,
        )?;
        Ok(VmValue::Dict(results))
    }

    pub(super) fn eval_dict_comprehension_generator(
        &mut self,
        generators: &[Value],
        index: usize,
        key: &Value,
        value: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
        results: &mut Vec<(VmValue, VmValue)>,
    ) -> Result<(), VmExecutionError> {
        let generator = as_object(
            generators
                .get(index)
                .ok_or_else(|| VmExecutionError::new("missing dict comprehension generator"))?,
            "dict comprehension generator",
        )?;
        let target = required_value(generator, "target")?;
        let iter_value = self.eval_expression(required_value(generator, "iter")?, scope, host)?;
        let iterator = crate::iteration::iter(&iter_value, &self.heap)?;
        let previous_bindings = capture_target_bindings(target, scope)?;

        while let Some(item) = self.next_item(&iterator, host)? {
            host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
            self.assign_target(target, item, scope, host, false)?;
            let mut allowed = true;
            for condition in required_array(generator, "ifs")? {
                if !self.eval_expression(condition, scope, host)?.truthy() {
                    allowed = false;
                    break;
                }
            }
            if !allowed {
                continue;
            }
            if index + 1 == generators.len() {
                let dict_key = self.eval_expression(key, scope, host)?;
                let dict_value = self.eval_expression(value, scope, host)?;
                crate::decimal_metering::comparison(
                    host,
                    &VmValue::Dict(results.clone()),
                    &dict_key,
                    false,
                )?;
                dict_set(results, dict_key, dict_value)?;
            } else {
                self.eval_dict_comprehension_generator(
                    generators,
                    index + 1,
                    key,
                    value,
                    scope,
                    host,
                    results,
                )?;
            }
        }

        restore_target_bindings(scope, previous_bindings);
        Ok(())
    }

    pub(super) fn eval_name(
        &self,
        object: &Map<String, Value>,
        scope: &HashMap<String, VmValue>,
    ) -> Result<VmValue, VmExecutionError> {
        let id = required_string(object, "id")?;
        if let Some(value) = scope.get(id) {
            return Ok(value.clone());
        }
        if let Some(value) = self.globals.get(id) {
            return Ok(value.clone());
        }
        if self.functions.contains_key(id) {
            return Ok(VmValue::FunctionRef(id.to_owned()));
        }
        if let Some(builtin) = builtin_name_value(id) {
            return Ok(builtin);
        }
        if let Some(host_binding_id) = optional_string(object, "host_binding_id") {
            return self.resolve_host_binding(host_binding_id);
        }
        Err(VmExecutionError::new(format!("unknown name '{id}'")))
    }

    pub(super) fn eval_constant(
        &self,
        object: &Map<String, Value>,
    ) -> Result<VmValue, VmExecutionError> {
        match required_string(object, "value_type")? {
            "none" => Ok(VmValue::None),
            "bool" => Ok(VmValue::Bool(required_bool(object, "value")?)),
            "int" => Ok(VmValue::Int(required_bigint(object, "value")?)),
            "float" => {
                let literal = if let Some(literal) = optional_string(object, "literal") {
                    literal.to_owned()
                } else {
                    required_f64(object, "value")?.to_string()
                };
                Ok(VmValue::Decimal(VmDecimal::from_str_literal(&literal)?))
            }
            "str" => Ok(VmValue::String(
                required_string(object, "value")?.to_owned(),
            )),
            "bytes" => Ok(VmValue::Bytes(
                hex::decode(required_string(object, "value")?).map_err(|error| {
                    VmExecutionError::new(format!("invalid bytes constant: {error}"))
                })?,
            )),
            other => Err(VmExecutionError::new(format!(
                "unsupported constant value_type '{other}'"
            ))),
        }
    }

    pub(super) fn eval_attribute(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if let Some(host_binding_id) = optional_string(object, "host_binding_id") {
            if !self.host_binding_root_is_shadowed(object, scope)? {
                return self.resolve_host_binding(host_binding_id);
            }
        }
        let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
        let attr = required_string(object, "attr")?;
        self.read_attribute(value, attr, host)
    }

    pub(super) fn eval_compare(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let mut left = self.eval_expression(required_value(object, "left")?, scope, host)?;
        let operators = required_array(object, "operators")?;
        let comparators = required_array(object, "comparators")?;
        if operators.len() != comparators.len() {
            return Err(VmExecutionError::new(
                "compare operator/comparator count mismatch",
            ));
        }

        for (operator, comparator) in operators.iter().zip(comparators.iter()) {
            let right = self.eval_expression(comparator, scope, host)?;
            let operator = required_string_value(operator)?;
            let view_cost = mapping_views::comparison_work(&left, &right);
            if view_cost > 0 {
                host.charge_execution_cost(view_cost)?;
            }
            let passed = if matches!(operator, "in" | "not_in")
                && matches!(right.snapshot(), VmValue::Iterator(_))
            {
                let iterator = crate::iteration::iter(&right, &self.heap)?;
                let mut found = false;
                while let Some(item) = self.next_item(&iterator, host)? {
                    crate::decimal_metering::comparison(host, &left, &item, true)?;
                    if vm_values_equal(&left, &item)? {
                        found = true;
                        break;
                    }
                }
                if operator == "in" {
                    found
                } else {
                    !found
                }
            } else {
                if !matches!(operator, "is" | "is_not") {
                    crate::decimal_metering::comparison(
                        host,
                        &left,
                        &right,
                        matches!(operator, "eq" | "not_eq"),
                    )?;
                }
                apply_compare_operator(operator, &left, &right)?
            };
            if !passed {
                return Ok(VmValue::Bool(false));
            }
            left = right;
        }

        Ok(VmValue::Bool(true))
    }

    pub(super) fn eval_bool_op(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let operator = required_string(object, "operator")?;
        let values = required_array(object, "values")?;
        match operator {
            "and" => {
                let mut last = VmValue::Bool(true);
                for value in values {
                    last = self.eval_expression(value, scope, host)?;
                    if !last.truthy() {
                        return Ok(last);
                    }
                }
                Ok(last)
            }
            "or" => {
                let mut last = VmValue::Bool(false);
                for value in values {
                    last = self.eval_expression(value, scope, host)?;
                    if last.truthy() {
                        return Ok(last);
                    }
                }
                Ok(last)
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported bool operator '{other}'"
            ))),
        }
    }

    fn eval_dict(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let mut entries = Vec::new();
        for entry in required_array(object, "entries")? {
            let entry_object = as_object(entry, "dict entry")?;
            if let Some(unpack) = entry_object.get("unpack") {
                let unpacked = self.eval_expression(unpack, scope, host)?;
                let VmValue::Dict(unpacked_entries) = unpacked.snapshot() else {
                    return Err(VmExecutionError::new(
                        "dict unpacking requires a dict value",
                    ));
                };
                for (key, value) in unpacked_entries {
                    crate::decimal_metering::comparison(
                        host,
                        &VmValue::Dict(entries.clone()),
                        &key,
                        false,
                    )?;
                    dict_set(&mut entries, key, value)?;
                }
            } else {
                let key =
                    self.eval_expression(required_value(entry_object, "key")?, scope, host)?;
                let value =
                    self.eval_expression(required_value(entry_object, "value")?, scope, host)?;
                crate::decimal_metering::comparison(
                    host,
                    &VmValue::Dict(entries.clone()),
                    &key,
                    false,
                )?;
                dict_set(&mut entries, key, value)?;
            }
        }
        Ok(VmValue::Dict(entries))
    }

    fn eval_subscript(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
        let slice = required_value(object, "slice")?;
        if let Some(slice_object) = slice.as_object() {
            if required_string(slice_object, "node")? == "slice" {
                return self.eval_slice_subscript(value, slice_object, scope, host);
            }
        }
        let index = self.eval_expression(slice, scope, host)?;
        self.read_subscript(value, &index, host)
    }

    fn eval_bin_op(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let left = self.eval_expression(required_value(object, "left")?, scope, host)?;
        let right = self.eval_expression(required_value(object, "right")?, scope, host)?;
        let operator = required_string(object, "operator")?;
        if matches!(operator, "bitand" | "bitor" | "bitxor" | "sub")
            && (mapping_views::is_set_view(&left) || mapping_views::is_set_view(&right))
        {
            return self.view_binary(operator, &left, &right, host);
        }
        let union_cost = mapping_views::union_work(operator, &left, &right);
        if union_cost > 0 {
            host.charge_execution_cost(union_cost)?;
        }
        support::set_kinds::charge_binary(operator, &left, &right, host)?;
        if matches!(left.snapshot(), VmValue::Set(_) | VmValue::FrozenSet(_))
            && matches!(operator, "bitand" | "bitor" | "bitxor" | "sub")
        {
            crate::decimal_metering::normalization(host, &[left.clone(), right.clone()])?;
        }
        host.charge_execution_cost(crate::raw_decimal::work_cost(operator, &left, &right))?;
        apply_binary_operator(operator, left, right)
    }

    fn eval_formatted_value(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
        let spec = match object.get("format_spec") {
            Some(spec) if !spec.is_null() => {
                self.eval_expression(spec, scope, host)?.as_string()?
            }
            _ => String::new(),
        };
        let conversion = optional_string(object, "conversion")
            .map(|text| match text {
                "s" => Ok('s'),
                "r" => Ok('r'),
                "a" => Ok('a'),
                _ => Err(VmExecutionError::new("invalid f-string conversion")),
            })
            .transpose()?;
        host.charge_execution_cost(super::value_formatting::format_work_cost(&value, "")?)?;
        let value = super::value_formatting::convert(&value, conversion)?;
        host.charge_execution_cost(super::value_formatting::format_work_cost(&value, &spec)?)?;
        Ok(VmValue::String(super::value_formatting::format_value(
            &value, &spec,
        )?))
    }
}
