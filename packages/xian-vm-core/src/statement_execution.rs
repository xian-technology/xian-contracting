//! Execute statements and apply assignments without re-evaluating target paths.
use super::*;

impl VmInstance {
    pub(super) fn execute_block(
        &mut self,
        statements: &[Value],
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        let _frame = self.heap.enter_execution_frame()?;
        for statement in statements {
            let flow = self.execute_statement(statement, scope, host)?;
            if flow != ControlFlow::Next {
                return Ok(flow);
            }
        }
        Ok(ControlFlow::Next)
    }

    pub(super) fn execute_statement(
        &mut self,
        statement: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        let object = as_object(statement, "statement")?;
        let node = required_string(object, "node")?;
        crate::work_meter::flush(host)?;
        host.charge_execution_cost(vm_statement_gas_cost(node, object)?)?;
        let trace_statements = vm_trace_enabled("XIAN_VM_TRACE_STATEMENTS");
        if trace_statements {
            diagnostics::emit("statement", &self.module.module_name, "-", node);
        }
        match node {
            "assign" => self.execute_assign(object, scope, host),
            "storage_set" => self.execute_storage_set(object, scope, host),
            "storage_mutate" => self.execute_storage_mutate(object, scope, host),
            "aug_assign" => self.execute_aug_assign(object, scope, host),
            "return" => self.execute_return(object, scope, host),
            "expr" => {
                self.eval_expression(required_value(object, "value")?, scope, host)?;
                Ok(ControlFlow::Next)
            }
            "if" => self.execute_if(object, scope, host),
            "while" => self.execute_while_loop(object, scope, host),
            "for" => self.execute_for_loop(object, scope, host),
            "assert" => self.execute_assert(object, scope, host),
            "raise" => self.execute_raise(object, scope, host),
            "break" => Ok(ControlFlow::Break),
            "continue" => Ok(ControlFlow::Continue),
            "pass" => Ok(ControlFlow::Next),
            other => Err(VmExecutionError::new(format!(
                "unsupported statement node '{other}'"
            ))),
        }
    }

    pub(super) fn execute_for_loop(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        let iter_value = self.eval_expression(required_value(object, "iter")?, scope, host)?;
        let iterator = crate::iteration::iter(&iter_value, &self.heap)?;
        let body = required_array(object, "body")?;
        let orelse = required_array(object, "orelse")?;

        let mut broke = false;
        while let Some(item) = self.next_item(&iterator, host)? {
            host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
            self.assign_target(required_value(object, "target")?, item, scope, host, false)?;
            match self.execute_block(body, scope, host)? {
                ControlFlow::Next => {}
                ControlFlow::Continue => continue,
                ControlFlow::Break => {
                    broke = true;
                    break;
                }
                ControlFlow::Return(value) => return Ok(ControlFlow::Return(value)),
            }
        }

        if !broke {
            self.execute_block(orelse, scope, host)
        } else {
            Ok(ControlFlow::Next)
        }
    }

    pub(super) fn execute_while_loop(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        let body = required_array(object, "body")?;
        let orelse = required_array(object, "orelse")?;

        let mut broke = false;
        while self
            .eval_expression(required_value(object, "test")?, scope, host)?
            .truthy()
        {
            host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
            match self.execute_block(body, scope, host)? {
                ControlFlow::Next => {}
                ControlFlow::Continue => continue,
                ControlFlow::Break => {
                    broke = true;
                    break;
                }
                ControlFlow::Return(value) => return Ok(ControlFlow::Return(value)),
            }
        }

        if !broke {
            self.execute_block(orelse, scope, host)
        } else {
            Ok(ControlFlow::Next)
        }
    }

    pub(super) fn assign_target(
        &mut self,
        target: &Value,
        value: VmValue,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
        module_scope: bool,
    ) -> Result<(), VmExecutionError> {
        let _frame = self.heap.enter_execution_frame()?;
        let object = as_object(target, "target")?;
        match required_string(object, "node")? {
            "name" => {
                let id = required_string(object, "id")?.to_owned();
                if module_scope {
                    self.globals.insert(id.clone(), value.clone());
                }
                scope.insert(id, value);
                Ok(())
            }
            "tuple_target" | "list_target" => self.unpack_target(
                required_array(object, "elements")?,
                value,
                scope,
                host,
                module_scope,
            ),
            "subscript" | "attribute" => {
                let (resolved, current) =
                    self.resolve_assignment_target(target, scope, host, false)?;
                debug_assert!(current.is_none());
                self.assign_resolved_target(resolved, value, scope, module_scope, host)
            }

            other => Err(VmExecutionError::new(format!(
                "unsupported assignment target '{other}'"
            ))),
        }
    }

    // Capture every container and index in an assignment path once. Mutable containers are
    // written back in place when shared; immutable paths are rebuilt without re-evaluation.
    pub(super) fn resolve_assignment_target(
        &mut self,
        target: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
        load_value: bool,
    ) -> Result<(ResolvedAssignmentTarget, Option<VmValue>), VmExecutionError> {
        let _frame = self.heap.enter_execution_frame()?;
        let object = as_object(target, "target")?;
        match required_string(object, "node")? {
            "name" => {
                let current = if load_value {
                    Some(self.eval_expression(target, scope, host)?)
                } else {
                    None
                };
                Ok((
                    ResolvedAssignmentTarget::Name(required_string(object, "id")?.to_owned()),
                    current,
                ))
            }
            "attribute" => {
                if load_value {
                    host.charge_execution_cost(vm_expression_gas_cost("attribute", object)?)?;
                }
                let receiver =
                    self.eval_expression(required_value(object, "value")?, scope, host)?;
                let name = required_string(object, "attr")?.to_owned();
                let current = if load_value {
                    Some(self.read_attribute(receiver.clone(), &name, host)?)
                } else {
                    None
                };
                Ok((
                    ResolvedAssignmentTarget::Attribute { receiver, name },
                    current,
                ))
            }
            "subscript" => {
                if load_value {
                    host.charge_execution_cost(vm_expression_gas_cost("subscript", object)?)?;
                }
                let value_expression = required_value(object, "value")?;
                let value_object = as_object(value_expression, "subscript target value")?;
                let value_node = required_string(value_object, "node")?;
                let (parent, container) =
                    if matches!(value_node, "name" | "subscript" | "attribute") {
                        let (parent, container) =
                            self.resolve_assignment_target(value_expression, scope, host, true)?;
                        let container = container.ok_or_else(|| {
                            VmExecutionError::new("subscript assignment container has no value")
                        })?;
                        (parent, container)
                    } else {
                        (
                            ResolvedAssignmentTarget::Unsupported(value_node.to_owned()),
                            self.eval_expression(value_expression, scope, host)?,
                        )
                    };
                let index = self.eval_expression(required_value(object, "slice")?, scope, host)?;
                let current = if load_value {
                    Some(self.read_subscript(container.clone(), &index, host)?)
                } else {
                    None
                };
                Ok((
                    ResolvedAssignmentTarget::Subscript {
                        parent: Box::new(parent),
                        container,
                        index,
                    },
                    current,
                ))
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported assignment target '{other}'"
            ))),
        }
    }

    pub(super) fn assign_resolved_target(
        &mut self,
        target: ResolvedAssignmentTarget,
        value: VmValue,
        scope: &mut HashMap<String, VmValue>,
        module_scope: bool,
        host: &mut dyn VmHost,
    ) -> Result<(), VmExecutionError> {
        let _frame = self.heap.enter_execution_frame()?;
        match target {
            ResolvedAssignmentTarget::Name(id) => {
                if module_scope {
                    self.globals.insert(id.clone(), value.clone());
                }
                scope.insert(id, value);
                Ok(())
            }
            ResolvedAssignmentTarget::Subscript {
                parent,
                container,
                index,
            } => {
                if matches!(container, VmValue::ForeignStorageRef(_)) {
                    return Err(VmExecutionError::new("cannot write to foreign storage"));
                }
                if resolves_to!(container, VmValue::Dict(_)) {
                    crate::decimal_metering::comparison(host, &container, &index, false)?;
                }
                if matches!(container, VmValue::Reference(_)) {
                    assign_subscript(container, &index, value)?;
                    return Ok(());
                }
                let updated = assign_subscript(container, &index, value)?;
                self.assign_resolved_target(*parent, updated, scope, module_scope, host)
            }
            ResolvedAssignmentTarget::Attribute { receiver, name } => {
                self.write_interface_attribute(receiver, &name, value)
            }
            ResolvedAssignmentTarget::Unsupported(node) => Err(VmExecutionError::new(format!(
                "unsupported assignment target '{node}'"
            ))),
        }
    }

    pub(super) fn eval_target_value(
        &mut self,
        target: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let object = as_object(target, "target")?;
        match required_string(object, "node")? {
            "name" | "attribute" | "subscript" => self.eval_expression(target, scope, host),
            other => Err(VmExecutionError::new(format!(
                "unsupported aug-assign target '{other}'"
            ))),
        }
    }

    fn execute_assign(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
        for target in required_array(object, "targets")? {
            self.assign_target(target, value.clone(), scope, host, false)?;
        }
        Ok(ControlFlow::Next)
    }

    fn execute_storage_set(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        if let Some(target) = self.lexical_storage_target(object)? {
            let statement =
                serde_json::json!({"targets": [target], "value": required_value(object, "value")?});
            return self.execute_assign(as_object(&statement, "assignment")?, scope, host);
        }
        let binding = required_string(object, "binding")?;
        let key = self.eval_expression(required_value(object, "key")?, scope, host)?;
        let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
        self.write_hash_value(binding, &key, value, host)?;
        Ok(ControlFlow::Next)
    }

    fn execute_storage_mutate(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        if let Some(target) = self.lexical_storage_target(object)? {
            let statement = serde_json::json!({"target": target, "value": required_value(object, "value")?, "operator": required_string(object, "operator")?});
            return self.execute_aug_assign(as_object(&statement, "assignment")?, scope, host);
        }
        let binding = required_string(object, "binding")?;
        let key = self.eval_expression(required_value(object, "key")?, scope, host)?;
        let current = self.hash_get(binding, &key, host)?;
        let operand = self.eval_expression(required_value(object, "value")?, scope, host)?;
        let operator = required_string(object, "operator")?;
        if numeric_v2::active() {
            host.charge_execution_cost(numeric_v2::op_cost(operator, &current, &operand))?;
        }
        let result = apply_binary_operator(operator, current, operand)?;
        self.write_hash_value(binding, &key, result, host)?;
        Ok(ControlFlow::Next)
    }

    fn execute_aug_assign(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        let target = required_value(object, "target")?;
        let target_object = as_object(target, "target")?;
        let target_node = required_string(target_object, "node")?;
        let (resolved, current) = if matches!(target_node, "name" | "subscript" | "attribute") {
            let (resolved, current) = self.resolve_assignment_target(target, scope, host, true)?;
            let current = current
                .ok_or_else(|| VmExecutionError::new("augmented assignment target has no value"))?;
            (Some(resolved), current)
        } else {
            (None, self.eval_target_value(target, scope, host)?)
        };
        let operand = self.eval_expression(required_value(object, "value")?, scope, host)?;
        let operator = required_string(object, "operator")?;
        if operator == "bitor" && resolves_to!(current, VmValue::MappingProxy(_)) {
            return Err(VmExecutionError::new(
                "mappingproxy does not support in-place union",
            ));
        }
        if numeric_v2::active() {
            host.charge_execution_cost(numeric_v2::op_cost(operator, &current, &operand))?;
        }
        let union_cost = mapping_views::union_work(operator, &current, &operand);
        if union_cost > 0 {
            host.charge_execution_cost(union_cost)?;
        }
        support::set_kinds::charge_binary(operator, &current, &operand, host)?;
        let result = if matches!(operator, "bitand" | "bitor" | "bitxor" | "sub")
            && (mapping_views::is_set_view(&current) || mapping_views::is_set_view(&operand))
        {
            self.view_binary(operator, &current, &operand, host)?
        } else if operator == "add" && resolves_to!(current, VmValue::List(_)) {
            self.extend_sequence(&current, &operand, host)?;
            current
        } else {
            apply_inplace_operator(operator, current, operand)?
        };
        if let Some(resolved) = resolved {
            self.assign_resolved_target(resolved, result, scope, false, host)
        } else {
            self.assign_target(target, result, scope, host, false)
        }?;
        Ok(ControlFlow::Next)
    }

    fn execute_return(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        let value = match object.get("value") {
            Some(Value::Null) | None => VmValue::None,
            Some(value) => self.eval_expression(value, scope, host)?,
        };
        Ok(ControlFlow::Return(value))
    }

    fn execute_if(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        let test = self.eval_expression(required_value(object, "test")?, scope, host)?;
        if test.truthy() {
            self.execute_block(required_array(object, "body")?, scope, host)
        } else {
            self.execute_block(required_array(object, "orelse")?, scope, host)
        }
    }

    fn execute_assert(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        let test = self.eval_expression(required_value(object, "test")?, scope, host)?;
        if !test.truthy() {
            let message = object
                .get("message")
                .filter(|value| !value.is_null())
                .map(|value| self.eval_expression(value, scope, host))
                .transpose()?;
            return Err(VmExecutionError::raised(
                "AssertionError",
                message.into_iter().collect(),
            ));
        }
        Ok(ControlFlow::Next)
    }

    fn execute_raise(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        if let Some(cause) = object.get("cause") {
            if !cause.is_null() {
                let _ = self.eval_expression(cause, scope, host)?;
            }
        }
        let message = |text: String| vec![VmValue::String(text)];
        Err(match object.get("exception") {
            None | Some(Value::Null) => VmExecutionError::raised(
                "RuntimeError",
                message("No active exception to reraise".to_owned()),
            ),
            Some(exception) => match self.eval_expression(exception, scope, host)?.snapshot() {
                VmValue::Exception(value) => VmExecutionError::raised(value.name, value.args),
                VmValue::Builtin(name)
                    if matches!(
                        name.as_str(),
                        "Exception" | "RuntimeError" | "ValueError" | "TypeError"
                    ) =>
                {
                    VmExecutionError::raised(name, Vec::new())
                }
                other => VmExecutionError::raised(
                    "TypeError",
                    message(format!(
                        "exceptions must derive from BaseException, got {}",
                        other.type_name()
                    )),
                ),
            },
        })
    }
    fn write_hash_value(
        &mut self,
        binding: &str,
        key: &VmValue,
        value: VmValue,
        host: &mut dyn VmHost,
    ) -> Result<(), VmExecutionError> {
        self.hash_set(binding, key, value.clone())?;
        let storage_key = hash_storage_key(&self.module.module_name, binding, key)?;
        host.record_storage_write(&storage_key, &value.detached()?)?;
        host.charge_storage_write(&storage_key, &value.detached()?)
    }
}
