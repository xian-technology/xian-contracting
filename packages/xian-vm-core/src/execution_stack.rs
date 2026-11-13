//! One deterministic depth bound spans recursive evaluation and transaction reentry.
use crate::VmExecutionError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub const MAX_EXECUTION_DEPTH: usize = 128;

#[derive(Clone, Debug, Default)]
pub(crate) struct ExecutionStack(Arc<AtomicUsize>);

impl PartialEq for ExecutionStack {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

pub(crate) struct ExecutionFrame {
    stack: ExecutionStack,
}

impl ExecutionStack {
    pub(crate) fn enter(&self) -> Result<ExecutionFrame, VmExecutionError> {
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |depth| {
                (depth < MAX_EXECUTION_DEPTH).then_some(depth + 1)
            })
            .map_err(|_| {
                VmExecutionError::new(format!(
                    "VM execution depth limit exceeded ({MAX_EXECUTION_DEPTH})"
                ))
            })?;
        Ok(ExecutionFrame {
            stack: self.clone(),
        })
    }
}

impl Drop for ExecutionFrame {
    fn drop(&mut self) {
        self.stack.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FunctionIr, ModuleIr, Span, VmExecutionContext, VmHost, VmInstance, VmValue};
    use serde_json::json;

    struct Host;
    impl VmHost for Host {}

    fn recursive_module() -> ModuleIr {
        let span = json!({"line": 1, "col": 0, "end_line": 2, "end_col": 20});
        let function = FunctionIr {
            node: "function".into(),
            span: Span {
                line: 1,
                col: 0,
                end_line: 2,
                end_col: 20,
            },
            name: "recurse".into(),
            visibility: "private".into(),
            decorator: None,
            docstring: None,
            parameters: vec![],
            returns: None,
            body: vec![json!({
                "node": "return",
                "span": span,
                "value": {"node": "call", "span": span, "func": {"node": "name", "id": "recurse", "span": span}, "args": [], "keywords": []}
            })],
        };
        let mut safe = function.clone();
        safe.name = "safe".into();
        safe.body = vec![];
        ModuleIr {
            ir_version: crate::XIAN_IR_V1.into(),
            vm_profile: crate::XIAN_VM_V2_PROFILE.into(),
            host_catalog_version: crate::XIAN_VM_HOST_CATALOG_V1.into(),
            module_name: "con_recursion".into(),
            source_hash: "0".repeat(64),
            docstring: None,
            imports: vec![],
            global_declarations: vec![],
            functions: vec![function, safe],
            module_body: vec![],
            host_dependencies: vec![],
        }
    }

    #[test]
    fn local_recursion_returns_error_and_releases_frames() {
        let mut vm = VmInstance::new(recursive_module(), VmExecutionContext::default()).unwrap();
        for _ in 0..2 {
            let error = vm
                .call_function(&mut Host, "recurse", vec![], vec![])
                .unwrap_err();
            assert!(error
                .to_string()
                .contains("VM execution depth limit exceeded"));
            assert_eq!(
                vm.call_function(&mut Host, "safe", vec![], vec![]).unwrap(),
                VmValue::None
            );
        }
    }

    #[test]
    fn constructor_heaps_share_the_transaction_stack() {
        let budget = crate::VmBudget::new(0, crate::XIAN_VM_V2_PROFILE);
        let caller = crate::heap::VmHeap::with_execution_stack(budget.execution_stack.clone());
        let constructor = crate::heap::VmHeap::with_execution_stack(budget.clone().execution_stack);
        let mut frames = Vec::new();
        for _ in 0..MAX_EXECUTION_DEPTH {
            frames.push(caller.enter_execution_frame().unwrap());
        }
        assert!(constructor.enter_execution_frame().is_err());
        drop(frames);
        assert!(constructor.enter_execution_frame().is_ok());
    }

    #[test]
    fn shared_stack_enforces_boundary_and_unwinds() {
        let stack = ExecutionStack::default();
        let mut frames = Vec::new();
        for _ in 0..MAX_EXECUTION_DEPTH {
            frames.push(stack.clone().enter().unwrap());
        }
        assert!(stack.enter().is_err());
        frames.pop();
        frames.push(stack.enter().unwrap());
        drop(frames);
        assert_eq!(stack.0.load(Ordering::Relaxed), 0);
        assert!(stack.enter().is_ok());
        assert_eq!(stack.0.load(Ordering::Relaxed), 0);
    }
}
