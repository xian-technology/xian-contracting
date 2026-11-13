//! Lexical declarations are independent of whether their assignments have executed.
use super::*;

const MAX_SCOPE_NODES: usize = 131_072;
const MAX_SCOPE_DEPTH: usize = 128;

#[derive(Default)]
struct BindingAnalysis {
    names: HashSet<String>,
    visited: usize,
}

impl BindingAnalysis {
    fn visit(&mut self, depth: usize) -> Result<(), VmExecutionError> {
        self.visited += 1;
        if self.visited > MAX_SCOPE_NODES || depth > MAX_SCOPE_DEPTH {
            return Err(VmExecutionError::new(
                "lexical scope analysis exceeds limit",
            ));
        }
        Ok(())
    }

    fn target(&mut self, target: &Value) -> Result<(), VmExecutionError> {
        let mut pending = vec![(target, 0)];
        while let Some((target, depth)) = pending.pop() {
            self.visit(depth)?;
            pending.extend(
                self.target_children(target)?
                    .into_iter()
                    .map(|value| (value, depth + 1)),
            );
        }
        Ok(())
    }

    fn target_children<'a>(
        &mut self,
        target: &'a Value,
    ) -> Result<Vec<&'a Value>, VmExecutionError> {
        let object = as_object(target, "binding target")?;
        match required_string(object, "node")? {
            "name" => {
                self.names.insert(required_string(object, "id")?.to_owned());
                Ok(vec![])
            }
            "tuple_target" | "list_target" => {
                Ok(required_array(object, "elements")?.iter().collect())
            }
            "starred_target" => Ok(vec![required_value(object, "value")?]),
            _ => Ok(vec![]),
        }
    }

    fn assignment_targets(&mut self, object: &Map<String, Value>) -> Result<(), VmExecutionError> {
        for target in required_array(object, "targets")? {
            self.target(target)?;
        }
        Ok(())
    }

    fn statement(&mut self, object: &Map<String, Value>) -> Result<(), VmExecutionError> {
        match required_string(object, "node")? {
            "assign" => self.assignment_targets(object),
            "aug_assign" | "for" => self.target(required_value(object, "target")?),
            _ => Ok(()),
        }
    }
}

pub(super) fn function_bindings(
    function: &FunctionIr,
) -> Result<HashSet<String>, VmExecutionError> {
    let mut analysis = BindingAnalysis::default();
    analysis.names.extend(
        function
            .parameters
            .iter()
            .map(|parameter| parameter.name.clone()),
    );
    let mut pending = function
        .body
        .iter()
        .map(|statement| (statement, 0))
        .collect::<Vec<_>>();
    while let Some((statement, depth)) = pending.pop() {
        analysis.visit(depth)?;
        let object = as_object(statement, "lexical statement")?;
        analysis.statement(object)?;
        for field in ["body", "orelse"] {
            if let Some(body) = object.get(field).and_then(Value::as_array) {
                pending.extend(body.iter().map(|value| (value, depth + 1)));
            }
        }
    }
    Ok(analysis.names)
}

fn comprehension_bindings(generators: &[Value]) -> Result<HashSet<String>, VmExecutionError> {
    let mut analysis = BindingAnalysis::default();
    for generator in generators {
        let generator = as_object(generator, "comprehension generator")?;
        analysis.target(required_value(generator, "target")?)?;
    }
    Ok(analysis.names)
}

impl VmInstance {
    pub(super) fn lexical_value(
        &self,
        name: &str,
        scope: &HashMap<String, VmValue>,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        if !self.lexical_bindings.contains(name) {
            return Ok(None);
        }
        scope.get(name).cloned().map(Some).ok_or_else(|| {
            VmExecutionError::new(format!(
                "cannot access local variable '{name}' where it is not associated with a value"
            ))
        })
    }

    fn comprehension_scope(
        &self,
        scope: &HashMap<String, VmValue>,
        targets: HashSet<String>,
    ) -> (HashMap<String, VmValue>, function_table::LexicalBindings) {
        let mut nested = scope.clone();
        let mut bindings = (*self.lexical_bindings).clone();
        for name in targets {
            nested.remove(&name);
            bindings.insert(name);
        }
        (nested, std::sync::Arc::new(bindings))
    }

    pub(super) fn prepare_comprehension(
        &mut self,
        generators: &[Value],
        scope: &HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<
        (
            HashMap<String, VmValue>,
            function_table::LexicalBindings,
            VmValue,
        ),
        VmExecutionError,
    > {
        let first = generators
            .first()
            .ok_or_else(|| VmExecutionError::new("missing comprehension generator"))?;
        let first = as_object(first, "comprehension generator")?;
        let value =
            self.eval_expression(required_value(first, "iter")?, &mut scope.clone(), host)?;
        let iterator = crate::iteration::iter(&value, &self.heap)?;
        let (nested, bindings) =
            self.comprehension_scope(scope, comprehension_bindings(generators)?);
        Ok((nested, bindings, iterator))
    }

    pub(super) fn lexical_storage_target(
        &self,
        object: &Map<String, Value>,
    ) -> Result<Option<Value>, VmExecutionError> {
        let binding = required_string(object, "binding")?;
        if !self.lexical_bindings.contains(binding) {
            return Ok(None);
        }
        Ok(Some(
            serde_json::json!({"node": "subscript", "value": {"node": "name", "id": binding}, "slice": required_value(object, "key")?}),
        ))
    }

    pub(super) fn optimized_call_is_local(&self, func: &Value) -> Result<bool, VmExecutionError> {
        Ok(ir_root_name(func)?.is_some_and(|name| self.lexical_bindings.contains(name)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn name(id: &str) -> Value {
        json!({"node": "name", "id": id})
    }
    fn integer(value: i64) -> Value {
        json!({"node": "constant", "value_type": "int", "value": value})
    }
    fn assign(id: &str, value: Value) -> Value {
        json!({"node": "assign", "targets": [name(id)], "value": value})
    }
    fn returned(value: Value) -> Value {
        json!({"node": "return", "value": value})
    }
    fn function(id: &str, body: Vec<Value>) -> FunctionIr {
        FunctionIr {
            node: "function".into(),
            span: crate::Span {
                line: 1,
                col: 0,
                end_line: 1,
                end_col: 1,
            },
            name: id.into(),
            visibility: "private".into(),
            decorator: None,
            docstring: None,
            parameters: vec![],
            returns: None,
            body,
        }
    }
    fn instance(functions: Vec<FunctionIr>) -> VmInstance {
        let module = ModuleIr {
            ir_version: crate::XIAN_IR_V1.into(),
            vm_profile: crate::XIAN_VM_V1_PROFILE.into(),
            host_catalog_version: crate::XIAN_VM_HOST_CATALOG_V1.into(),
            module_name: "con_scopes".into(),
            source_hash: "0".repeat(64),
            docstring: None,
            imports: vec![],
            global_declarations: vec![],
            functions: vec![],
            module_body: vec![],
            host_dependencies: vec![],
        };
        let mut instance = VmInstance::new(module, VmExecutionContext::default()).unwrap();
        for function in functions {
            instance
                .define_function(function.into(), &mut NoopHost {})
                .unwrap();
        }
        instance
    }
    fn invalid_argument() -> Value {
        json!({"node":"bin_op", "operator":"div", "left":integer(1), "right":integer(0)})
    }
    fn call(value: Value, args: Vec<Value>) -> Value {
        json!({"node":"call", "func":value, "args":args, "keywords":[]})
    }
    fn run(instance: &mut VmInstance, id: &str) -> Result<VmValue, VmExecutionError> {
        instance.call_named_function(&mut NoopHost {}, id, vec![], vec![])
    }

    #[test]
    fn lexical_unbound_function_frames_restore_after_failure_and_nested_calls() {
        let bad = function(
            "bad",
            vec![returned(name("value")), assign("value", integer(7))],
        );
        let good = function("good", vec![returned(name("value"))]);
        let outer = function(
            "outer",
            vec![
                assign("value", integer(3)),
                returned(call(name("good"), vec![])),
            ],
        );
        let mut vm = instance(vec![bad, good, outer]);
        vm.globals.insert("value".into(), VmValue::Int(41.into()));
        assert!(run(&mut vm, "bad")
            .unwrap_err()
            .to_string()
            .contains("local variable 'value'"));
        assert_eq!(
            run(&mut vm, "good").unwrap().snapshot(),
            VmValue::Int(41.into())
        );
        assert_eq!(
            run(&mut vm, "outer").unwrap().snapshot(),
            VmValue::Int(41.into())
        );
        assert!(vm.lexical_bindings.is_empty());
    }

    #[test]
    fn lexical_legacy_host_call_checks_receiver_before_arguments() {
        let expression = json!({"node":"call", "func":{"node":"attribute","value":name("hashlib"),"attr":"sha3","host_binding_id":"hash.sha3_256_legacy"}, "syscall_id":"hash.sha3_256_legacy", "args":[invalid_argument()],"keywords":[]});
        let mut vm = instance(vec![function(
            "probe",
            vec![returned(expression), assign("hashlib", integer(7))],
        )]);
        let error = run(&mut vm, "probe").unwrap_err().to_string();
        assert!(error.contains("local variable 'hashlib'"), "{error}");
    }

    #[test]
    fn lexical_legacy_storage_access_respects_unbound_and_bound_local_values() {
        let get = json!({"node":"storage_get","binding":"h","key":integer(0)});
        let dict = json!({"node":"dict","entries":[{"key":integer(0),"value":integer(7)}]});
        let mut vm = instance(vec![
            function(
                "bad",
                vec![returned(get.clone()), assign("h", dict.clone())],
            ),
            function("good", vec![assign("h", dict), returned(get)]),
        ]);
        assert!(run(&mut vm, "bad")
            .unwrap_err()
            .to_string()
            .contains("local variable 'h'"));
        assert_eq!(
            run(&mut vm, "good").unwrap().snapshot(),
            VmValue::Int(7.into())
        );
    }

    #[test]
    fn lexical_comprehension_reserves_all_targets_but_not_outer_iterable() {
        let comp = json!({"node":"list_comp", "element":name("value"), "generators":[{"target":name("value"),"iter":name("value"),"ifs":[]}]});
        let mut vm = instance(vec![function(
            "good",
            vec![
                assign("value", json!({"node":"list","elements":[integer(3)]})),
                returned(comp),
            ],
        )]);
        assert_eq!(
            run(&mut vm, "good").unwrap().detached().unwrap(),
            VmValue::List(vec![VmValue::Int(3.into())])
        );
        let comp = json!({"node":"list_comp", "element":name("x"), "generators":[{"target":name("x"),"iter":{"node":"list","elements":[integer(1)]},"ifs":[name("value")]},{"target":name("value"),"iter":{"node":"list","elements":[integer(2)]},"ifs":[]}]});
        vm.define_function(
            function("bad", vec![assign("value", integer(1)), returned(comp)]).into(),
            &mut NoopHost {},
        )
        .unwrap();
        vm.globals.insert("value".into(), VmValue::Bool(true));
        assert!(run(&mut vm, "bad")
            .unwrap_err()
            .to_string()
            .contains("local variable 'value'"));
        assert!(vm.lexical_bindings.is_empty());
    }

    #[test]
    fn lexical_binding_analysis_ignores_subscript_bases_and_comprehension_targets() {
        let body = vec![
            assign("a", integer(1)),
            json!({"node":"if","body":[{"node":"for","target":{"node":"tuple_target","elements":[name("b"),{"node":"starred_target","value":name("c")}]},"body":[],"orelse":[]}],"orelse":[{"node":"aug_assign","target":name("d") }]}),
            json!({"node":"assign","targets":[{"node":"subscript","value":name("outer"),"slice":integer(0)}]}),
            returned(json!({"node":"list_comp","generators":[{"target":name("inner")}]})),
        ];
        assert_eq!(
            function_bindings(&function("probe", body)).unwrap(),
            HashSet::from(["a".into(), "b".into(), "c".into(), "d".into()])
        );
    }
    fn nested_target(depth: usize) -> Value {
        let mut target = name("local");
        for _ in 0..depth {
            target = json!({"node":"starred_target","value":target});
        }
        target
    }

    #[test]
    fn lexical_analysis_accepts_exact_depth_and_rejects_one_more() {
        let mut accepted = BindingAnalysis::default();
        accepted.target(&nested_target(128)).unwrap();
        assert!(accepted.names.contains("local"));
        assert!(BindingAnalysis::default()
            .target(&nested_target(129))
            .is_err());
        let mut statement = json!({"node":"pass"});
        for _ in 0..128 {
            statement = json!({"node":"if","body":[statement],"orelse":[]});
        }
        assert!(function_bindings(&function("limit", vec![statement.clone()])).is_ok());
        let extra = json!({"node":"if","body":[statement],"orelse":[]});
        assert!(function_bindings(&function("limit", vec![extra])).is_err());
    }

    #[test]
    fn lexical_analysis_counts_all_targets_against_one_node_budget() {
        let targets = json!({"node":"tuple_target","elements":vec![name("local");131_071]});
        let mut accepted = BindingAnalysis::default();
        accepted.target(&targets).unwrap();
        assert_eq!(accepted.names, HashSet::from(["local".into()]));
        assert!(accepted.target(&name("extra")).is_err());
        let statement = json!({"node":"assign","targets":[targets]});
        assert!(function_bindings(&function("aggregate", vec![statement])).is_err());
        let body = vec![json!({"node":"pass"}); 131_072];
        assert!(function_bindings(&function("limit", body.clone())).is_ok());
        let mut excessive = body;
        excessive.push(json!({"node":"pass"}));
        assert!(function_bindings(&function("limit", excessive)).is_err());
    }

    #[test]
    fn lexical_legacy_storage_writes_use_local_dictionary_and_order() {
        let dictionary = json!({"node":"dict","entries":[{"key":integer(0),"value":integer(1)}]});
        let set = json!({"node":"storage_set","binding":"h","key":integer(0),"value":integer(7)});
        let mutate = json!({"node":"storage_mutate","binding":"h","key":integer(0),"value":integer(2),"operator":"add"});
        let get = json!({"node":"storage_get","binding":"h","key":integer(0)});
        let mut vm = instance(vec![function(
            "good",
            vec![assign("h", dictionary.clone()), set, mutate, returned(get)],
        )]);
        assert_eq!(
            run(&mut vm, "good").unwrap().snapshot(),
            VmValue::Int(9.into())
        );
        let mutate = json!({"node":"storage_mutate","binding":"h","key":invalid_argument(),"value":integer(2),"operator":"add"});
        vm.define_function(
            function("bad", vec![mutate, assign("h", dictionary)]).into(),
            &mut NoopHost {},
        )
        .unwrap();
        assert!(run(&mut vm, "bad")
            .unwrap_err()
            .to_string()
            .contains("local variable 'h'"));
    }

    #[test]
    fn lexical_comprehension_bindings_do_not_leak_into_enclosing_function() {
        let comp = json!({"node":"list_comp", "element":name("value"), "generators":[{"target":name("value"),"iter":{"node":"list","elements":[integer(1)]},"ifs":[]}]});
        let mut vm = instance(vec![function(
            "probe",
            vec![assign("result", comp), returned(name("value"))],
        )]);
        vm.globals.insert("value".into(), VmValue::Int(41.into()));
        assert_eq!(
            run(&mut vm, "probe").unwrap().snapshot(),
            VmValue::Int(41.into())
        );
    }
}
