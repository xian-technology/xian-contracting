//! A validated module's functions as its instances call them.
//!
//! What an instance needs to call a function depends only on that function's
//! IR: its entry charge and its lexical bindings. Both are derived once, when
//! the module is validated, and every instance shares them together with the
//! IR itself instead of cloning or re-deriving them per instantiation or call.
//! Charges stay exactly those of [`function_entry_gas_cost`].
use super::*;
use std::sync::Arc;

/// The names a function binds lexically, shared by every call of it.
pub(crate) type LexicalBindings = Arc<HashSet<String>>;

/// What one function's IR alone determines about calling it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FunctionFacts {
    entry_cost: u64,
    /// `None` when the analysis failed; defining the function then repeats the
    /// analysis to raise its error at the same point as before.
    locals: Option<LexicalBindings>,
}

impl FunctionFacts {
    pub(crate) fn of(function: &FunctionIr) -> Self {
        Self {
            entry_cost: function_entry_gas_cost(function),
            locals: lexical_scopes::function_bindings(function)
                .ok()
                .map(Arc::new),
        }
    }
}

/// One function of a validated module. Cloning it shares the module's IR.
#[derive(Debug, Clone)]
pub(crate) struct DefinedFunction {
    module: crate::ValidatedModuleIr,
    index: usize,
}

impl DefinedFunction {
    pub(crate) fn new(module: &crate::ValidatedModuleIr, index: usize) -> Self {
        Self {
            module: module.clone(),
            index,
        }
    }

    pub(crate) fn entry_cost(&self) -> u64 {
        self.module.function_facts(self.index).entry_cost
    }

    pub(crate) fn locals(&self) -> Result<LexicalBindings, VmExecutionError> {
        match &self.module.function_facts(self.index).locals {
            Some(locals) => Ok(Arc::clone(locals)),
            None => lexical_scopes::function_bindings(self).map(Arc::new),
        }
    }

    #[cfg(test)]
    pub(crate) fn shares_ir_with(&self, other: &Self) -> bool {
        std::ptr::eq::<FunctionIr>(&**self, &**other)
    }
}

impl std::ops::Deref for DefinedFunction {
    type Target = FunctionIr;

    fn deref(&self) -> &FunctionIr {
        &self.module.functions[self.index]
    }
}

/// A hand-built function, alone in an unvalidated module (test fixtures only).
#[cfg(test)]
impl From<FunctionIr> for DefinedFunction {
    fn from(function: FunctionIr) -> Self {
        let module = ModuleIr {
            ir_version: crate::XIAN_IR_V1.into(),
            vm_profile: crate::XIAN_VM_V1_PROFILE.into(),
            host_catalog_version: crate::XIAN_VM_HOST_CATALOG_V1.into(),
            module_name: "con_fixture".into(),
            source_hash: "0".repeat(64),
            docstring: None,
            imports: vec![],
            global_declarations: vec![],
            functions: vec![function],
            module_body: vec![],
            host_dependencies: vec![],
        };
        Self::new(&crate::ValidatedModuleIr::unchecked(module), 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct ChargeLog(Vec<u64>);

    impl VmHost for ChargeLog {
        fn charge_execution_cost(&mut self, cost: u64) -> Result<(), VmExecutionError> {
            self.0.push(cost);
            Ok(())
        }
    }

    fn name(id: &str) -> Value {
        json!({"node": "name", "id": id})
    }

    fn integer(value: i64) -> Value {
        json!({"node": "constant", "value_type": "int", "value": value.to_string()})
    }

    fn statement(index: i64) -> Value {
        json!({"node": "assign", "targets": [name("x")], "value": {
            "node": "bin_op", "operator": "add", "left": name("x"), "right": integer(index)}})
    }

    /// A function long enough that entering it is charged, and one that calls it.
    fn module() -> crate::ValidatedModuleIr {
        let function = |id: &str, body: Vec<Value>| FunctionIr {
            node: "function".into(),
            span: crate::Span {
                line: 1,
                col: 0,
                end_line: 1,
                end_col: 1,
            },
            name: id.into(),
            visibility: "export".into(),
            decorator: None,
            docstring: None,
            parameters: vec![],
            returns: None,
            body,
        };
        let mut long = vec![json!({"node": "assign", "targets": [name("x")], "value": integer(0)})];
        long.extend((0..200).map(statement));
        long.push(json!({"node": "return", "value": name("x")}));
        let caller = vec![json!({"node": "return", "value": {
            "node": "call", "func": name("long"), "args": [], "keywords": []}})];
        crate::ValidatedModuleIr::unchecked(ModuleIr {
            ir_version: crate::XIAN_IR_V1.into(),
            vm_profile: crate::XIAN_VM_V1_PROFILE.into(),
            host_catalog_version: crate::XIAN_VM_HOST_CATALOG_V1.into(),
            module_name: "con_functions".into(),
            source_hash: "0".repeat(64),
            docstring: None,
            imports: vec![],
            global_declarations: vec![],
            functions: vec![function("long", long), function("caller", caller)],
            module_body: vec![],
            host_dependencies: vec![],
        })
    }

    fn instance(module: &crate::ValidatedModuleIr) -> VmInstance {
        VmInstance::new_with_heap(
            module,
            VmExecutionContext::default(),
            &mut ChargeLog(vec![]),
            crate::heap::VmHeap::default(),
        )
        .unwrap()
    }

    fn call(vm: &mut VmInstance, id: &str) -> Vec<u64> {
        let mut host = ChargeLog(vec![]);
        vm.call_named_function(&mut host, id, vec![], vec![])
            .unwrap();
        host.0
    }

    #[test]
    fn every_call_pays_the_entry_charge_of_the_function_ir() {
        let module = module();
        let expected = function_entry_gas_cost(&module.functions[0]);
        assert!(
            expected > 0,
            "fixture must exceed the free complexity floor"
        );
        let mut first = instance(&module);
        let mut second = instance(&module);
        for vm in [&mut first, &mut second] {
            for _ in 0..2 {
                assert_eq!(call(vm, "long")[0], expected);
                let nested = call(vm, "caller");
                assert_eq!(
                    nested.iter().filter(|&&charge| charge == expected).count(),
                    1
                );
            }
        }
    }

    #[test]
    fn instances_of_one_module_share_its_function_ir() {
        let module = module();
        let first = instance(&module);
        let second = instance(&module);
        for id in ["long", "caller"] {
            assert!(first.functions[id].shares_ir_with(&second.functions[id]));
        }
    }

    #[test]
    fn a_failed_lexical_analysis_still_fails_when_the_function_is_defined() {
        let mut body = json!({"node": "pass"});
        for _ in 0..200 {
            body = json!({"node": "if", "test": integer(1), "body": [body], "orelse": []});
        }
        let mut too_deep = (*module()).clone();
        too_deep.functions[0].body = vec![body];
        let module = crate::ValidatedModuleIr::unchecked(too_deep);
        let error = VmInstance::new_with_heap(
            &module,
            VmExecutionContext::default(),
            &mut ChargeLog(vec![]),
            crate::heap::VmHeap::default(),
        )
        .err()
        .expect("analysis limit must reject the function");
        assert_eq!(error.to_string(), "lexical scope analysis exceeds limit");
    }
}
