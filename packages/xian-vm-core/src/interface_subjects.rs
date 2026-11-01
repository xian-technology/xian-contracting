//! Immutable interface inspection data; never a foreign callable or storage reference.
use super::*;

#[derive(Clone, Debug, PartialEq)]
pub struct VmInterfaceSubject {
    pub kind: VmInterfaceKind,
    pub name: String,
    pub args: VmValue,
    pub storage_type: Option<String>,
}
impl VmInterfaceSubject {
    pub(crate) fn allocation_bytes(&self) -> usize {
        self.name.len() + self.storage_type.as_ref().map_or(0, String::len)
    }
    pub(super) fn matching_work(&self) -> u64 {
        self.allocation_bytes() as u64 + parameter_work(&self.args)
    }
}
fn parameter_work(value: &VmValue) -> u64 {
    if let VmValue::Reference(reference) = value {
        return reference.with_value(parameter_tuple_work);
    }
    parameter_tuple_work(value)
}
fn parameter_tuple_work(value: &VmValue) -> u64 {
    let VmValue::Tuple(values) = value else {
        return 1;
    };
    values.iter().fold(1u64, |work, value| {
        work.saturating_add(match value {
            VmValue::String(value) => value.len() as u64 + 1,
            VmValue::Reference(reference) => reference.with_value(|value| match value {
                VmValue::String(value) => value.len() as u64 + 1,
                _ => 1,
            }),
            _ => 1,
        })
    })
}
pub(super) fn attribute(value: &VmValue, name: &str) -> Option<Result<VmValue, VmExecutionError>> {
    let VmValue::InterfaceSubject(subject) = value.snapshot() else {
        return None;
    };
    Some(match name {
        "kind" => Ok(VmValue::String(
            if subject.kind == VmInterfaceKind::Func {
                "function"
            } else {
                "storage"
            }
            .into(),
        )),
        "name" => Ok(VmValue::String(subject.name)),
        "args" => Ok(subject.args),
        "storage_type" => Ok(subject
            .storage_type
            .map(VmValue::String)
            .unwrap_or(VmValue::None)),
        _ => Err(VmExecutionError::new(format!(
            "InterfaceSubject has no attribute '{name}'"
        ))),
    })
}
impl VmInstance {
    pub(super) fn call_interface_predicate(
        &mut self,
        callback: VmValue,
        subject: VmValue,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if let Some(name) = self.local_export_predicate(&callback)? {
            // A self-module export is a local call, just like Python's same-context
            // export wrapper. Preserve the normal bound-export dispatch charge.
            host.charge_execution_cost(VM_GAS_CALL_DISPATCH)?;
            return self.call_named_function(host, &name, vec![subject], vec![]);
        }
        self.call_callable_value(host, callback, vec![subject], vec![])
    }
    fn local_export_predicate(
        &self,
        callback: &VmValue,
    ) -> Result<Option<String>, VmExecutionError> {
        let VmValue::BoundMethod(bound) = callback.snapshot() else {
            return Ok(None);
        };
        let VmValue::ContractHandle(handle) = bound.receiver.snapshot() else {
            return Ok(None);
        };
        if handle.module != self.module.module_name {
            return Ok(None);
        }
        if !self
            .functions
            .get(&bound.method)
            .is_some_and(|function| function.visibility == "export")
        {
            return Err(VmExecutionError::new(
                "interface callback is not a canonical export",
            ));
        }
        Ok(Some(bound.method))
    }
    pub(super) fn interface_subject(
        &self,
        name: &str,
        member: VmInterfaceMember,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        host.charge_execution_cost(
            member
                .inspection_work()
                .saturating_add(name.len() as u64)
                .saturating_add(4),
        )?;
        let subject = match member {
            VmInterfaceMember::Function { name, args } => VmInterfaceSubject {
                kind: VmInterfaceKind::Func,
                name,
                args: VmValue::Tuple(args.into_iter().map(VmValue::String).collect()),
                storage_type: None,
            },
            VmInterfaceMember::Datum(storage_type) => VmInterfaceSubject {
                kind: VmInterfaceKind::Var,
                name: name.into(),
                args: VmValue::None,
                storage_type: Some(storage_type),
            },
            _ => {
                return Err(VmExecutionError::new(
                    "interface subject requires function or storage metadata",
                ))
            }
        };
        self.heap
            .capture(VmValue::InterfaceSubject(Box::new(subject)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn instance() -> VmInstance {
        VmInstance::new(
            ModuleIr {
                ir_version: crate::XIAN_IR_V1.into(),
                vm_profile: crate::XIAN_VM_V1_PROFILE.into(),
                host_catalog_version: crate::XIAN_VM_HOST_CATALOG_V1.into(),
                module_name: "con_subject".into(),
                source_hash: "0".repeat(64),
                docstring: None,
                imports: vec![],
                global_declarations: vec![],
                functions: vec![],
                module_body: vec![],
                host_dependencies: vec![],
            },
            VmExecutionContext::default(),
        )
        .unwrap()
    }
    #[derive(Default)]
    struct Budget {
        limit: Option<u64>,
        charges: Vec<u64>,
    }
    impl VmHost for Budget {
        fn charge_execution_cost(&mut self, cost: u64) -> Result<(), VmExecutionError> {
            self.charges.push(cost);
            if self
                .limit
                .is_some_and(|limit| self.charges.iter().sum::<u64>() > limit)
            {
                return Err(VmExecutionError::new("Out of chi."));
            }
            Ok(())
        }
    }
    fn function() -> VmInterfaceMember {
        VmInterfaceMember::Function {
            name: "transfer".into(),
            args: vec!["amount".into(), "to".into()],
        }
    }
    #[test]
    fn subject_allocation_is_precharged_and_parameter_tuple_remains_shared() {
        let vm = instance();
        let mut budget = Budget {
            limit: Some(27),
            ..Budget::default()
        };
        assert!(vm
            .interface_subject("alias", function(), &mut budget)
            .unwrap_err()
            .to_string()
            .contains("Out of chi"));
        // transfer(8) + metadata tag(1) + amount(6)+tag(1) + to(2)+tag(1)
        // + inspected alias(5) + four exposed fields = 28 units.
        assert_eq!(budget.charges, vec![28]);
        let subject = vm
            .interface_subject("alias", function(), &mut Budget::default())
            .unwrap();
        let first = attribute(&subject, "args").unwrap().unwrap();
        let second = attribute(&subject, "args").unwrap().unwrap();
        assert!(first.identical(&second));
        assert_eq!(
            first.detached().unwrap(),
            VmValue::Tuple(vec![
                VmValue::String("amount".into()),
                VmValue::String("to".into())
            ])
        );
        let VmValue::InterfaceSubject(subject) = subject.snapshot() else {
            panic!("expected subject")
        };
        assert_eq!(subject.matching_work(), 19);
    }
    #[test]
    fn subject_identity_does_not_depend_on_equal_metadata() {
        let vm = instance();
        let mut host = Budget::default();
        let first = vm
            .interface_subject("alias", function(), &mut host)
            .unwrap();
        let second = vm
            .interface_subject("alias", function(), &mut host)
            .unwrap();
        assert!(vm_values_equal(&first, &first).unwrap());
        assert!(!first.identical(&second));
        assert!(!vm_values_equal(&first, &second).unwrap());
        let mut keys = Vec::new();
        dict_set(&mut keys, first, vm_int(1)).unwrap();
        dict_set(&mut keys, second, vm_int(2)).unwrap();
        assert_eq!(keys.len(), 2);
    }
    #[test]
    fn storage_subject_has_no_callable_class_or_foreign_value() {
        let vm = instance();
        let mut host = Budget::default();
        let subject = vm
            .interface_subject(
                "__balance",
                VmInterfaceMember::Datum("Variable".into()),
                &mut host,
            )
            .unwrap();
        assert_eq!(host.charges, vec![22]);
        assert_eq!(
            attribute(&subject, "kind").unwrap().unwrap(),
            VmValue::String("storage".into())
        );
        let VmValue::InterfaceSubject(metadata) = subject.snapshot() else {
            panic!("expected subject")
        };
        assert_eq!(metadata.matching_work(), 18);
        assert_eq!(
            attribute(&subject, "name").unwrap().unwrap(),
            VmValue::String("__balance".into())
        );
        assert_eq!(
            attribute(&subject, "storage_type").unwrap().unwrap(),
            VmValue::String("Variable".into())
        );
        assert_eq!(attribute(&subject, "args").unwrap().unwrap(), VmValue::None);
        assert!(attribute(&subject, "get").unwrap().is_err());
        assert!(
            interface_descriptors::write_attribute(subject.clone(), "name", VmValue::None)
                .unwrap_err()
                .to_string()
                .contains("read-only")
        );
        for value in [
            subject.clone(),
            VmValue::List(vec![subject.clone()]),
            VmValue::Dict(vec![(subject, VmValue::None)]),
        ] {
            assert!(value
                .external_value()
                .unwrap_err()
                .to_string()
                .contains("interface subjects cannot cross"));
            assert!(
                crate::heap::validate_contract_values(std::iter::once(&value))
                    .unwrap_err()
                    .to_string()
                    .contains("interface subjects cannot cross")
            );
        }
    }
    #[test]
    fn local_export_predicate_keeps_dispatch_fee_and_rejects_private_or_foreign_targets() {
        let mut vm = instance();
        let span = crate::Span {
            line: 1,
            col: 0,
            end_line: 1,
            end_col: 1,
        };
        let function = FunctionIr {
            node: "function".into(),
            span: span.clone(),
            name: "check".into(),
            visibility: "export".into(),
            decorator: None,
            docstring: None,
            parameters: vec![crate::ParameterIr {
                name: "subject".into(),
                kind: "positional_or_keyword".into(),
                annotation: None,
                default: None,
                span,
            }],
            returns: None,
            body: vec![],
        };
        vm.define_function(function.clone(), &mut Budget::default())
            .unwrap();
        vm.define_function(
            FunctionIr {
                name: "hidden".into(),
                visibility: "private".into(),
                ..function
            },
            &mut Budget::default(),
        )
        .unwrap();
        let subject = vm
            .interface_subject("alias", function_member_for_test(), &mut Budget::default())
            .unwrap();
        let callback = |module: &str, name: &str| {
            VmValue::BoundMethod(Box::new(VmBoundMethod {
                receiver: VmValue::ContractHandle(VmContractHandle {
                    module: module.into(),
                    origin: "dynamic_import".into(),
                }),
                method: name.into(),
            }))
        };
        let mut host = Budget::default();
        assert_eq!(
            vm.call_interface_predicate(
                callback("con_subject", "check"),
                subject.clone(),
                &mut host
            )
            .unwrap(),
            VmValue::None
        );
        assert_eq!(host.charges, vec![5000, 0]);
        for name in ["hidden", "invented"] {
            let mut host = Budget::default();
            assert!(vm
                .call_interface_predicate(callback("con_subject", name), subject.clone(), &mut host)
                .unwrap_err()
                .to_string()
                .contains("canonical export"));
            assert!(host.charges.is_empty());
        }
        let mut host = Budget::default();
        assert!(vm
            .call_interface_predicate(callback("other", "check"), subject, &mut host)
            .unwrap_err()
            .to_string()
            .contains("interface subjects cannot cross"));
        assert_eq!(host.charges, vec![5000]);
    }
    fn function_member_for_test() -> VmInterfaceMember {
        function()
    }
}
