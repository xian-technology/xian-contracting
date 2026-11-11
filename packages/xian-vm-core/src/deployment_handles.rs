//! Execution-local deployment helpers use the existing submission syscall gate.
use super::*;

pub(super) fn constructor(
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Result<VmValue, VmExecutionError> {
    if args.len() > 1 || kwargs.len() > 1 || (!args.is_empty() && !kwargs.is_empty()) {
        return Err(VmExecutionError::new(
            "Contract() accepts only an optional None driver",
        ));
    }
    if kwargs.iter().any(|(name, _)| name != "driver") {
        return Err(VmExecutionError::new(
            "Contract() got an unexpected keyword",
        ));
    }
    if args
        .iter()
        .chain(kwargs.iter().map(|(_, value)| value))
        .any(|value| !resolves_to!(value, VmValue::None))
    {
        return Err(VmExecutionError::new(
            "Contract() cannot receive a driver during contract execution",
        ));
    }
    Ok(VmValue::DeploymentHandle)
}

pub(super) fn is_class(value: &VmValue) -> bool {
    resolves_to!(value, VmValue::Builtin(ref name) if name == "Contract")
}

pub(super) fn is_instance(value: &VmValue) -> bool {
    resolves_to!(value, VmValue::DeploymentHandle)
}

impl VmInstance {
    pub(super) fn call_deployment_method(
        &mut self,
        receiver: &VmValue,
        method: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if method != "submit" {
            let callable = VmHostCallable::named(&format!("Contract.{method}"))
                .ok_or_else(|| VmExecutionError::new("unknown Contract method"))?;
            return self.call_host_callable(callable, args, kwargs, host);
        }
        let unbound = is_class(receiver);
        let mut args = method_signatures::bind_deployment_submit(args, kwargs, unbound)?;
        if unbound && !is_instance(&args.remove(0)) {
            return Err(VmExecutionError::new(
                "Contract.submit requires a Contract receiver",
            ));
        }
        let names = [
            "name",
            "code",
            "owner",
            "constructor_args",
            "developer",
            "deployer",
            "initiator",
        ];
        let kwargs = names
            .into_iter()
            .zip(args)
            .map(|(name, value)| (name.into(), value))
            .collect();
        self.dispatch_host_syscall("contract.deploy", vec![], kwargs, host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_accepts_only_omitted_or_none_driver() {
        for (args, kwargs) in [
            (vec![], vec![]),
            (vec![VmValue::None], vec![]),
            (vec![], vec![("driver".into(), VmValue::None)]),
        ] {
            assert!(matches!(
                constructor(&args, &kwargs).unwrap(),
                VmValue::DeploymentHandle
            ));
        }
        for (args, kwargs) in [
            (vec![vm_int(1)], vec![]),
            (vec![VmValue::None, VmValue::None], vec![]),
            (vec![VmValue::None], vec![("driver".into(), VmValue::None)]),
            (vec![], vec![("driver".into(), vm_int(1))]),
            (vec![], vec![("unexpected".into(), VmValue::None)]),
            (
                vec![],
                vec![
                    ("driver".into(), VmValue::None),
                    ("other".into(), VmValue::None),
                ],
            ),
        ] {
            assert!(constructor(&args, &kwargs).is_err());
        }
    }

    #[derive(Default)]
    struct Host {
        calls: Vec<(String, Vec<VmValue>, Vec<(String, VmValue)>)>,
    }
    impl VmHost for Host {
        fn handle_syscall(
            &mut self,
            name: &str,
            args: Vec<VmValue>,
            kwargs: Vec<(String, VmValue)>,
        ) -> Result<VmValue, VmExecutionError> {
            self.calls.push((name.into(), args, kwargs));
            Ok(VmValue::None)
        }
    }
    fn instance() -> VmInstance {
        let module = ModuleIr {
            ir_version: crate::XIAN_IR_V1.into(),
            vm_profile: crate::XIAN_VM_V1_PROFILE.into(),
            host_catalog_version: crate::XIAN_VM_HOST_CATALOG_V1.into(),
            module_name: "submission".into(),
            source_hash: "0".repeat(64),
            docstring: None,
            imports: vec![],
            global_declarations: vec![],
            functions: vec![],
            module_body: vec![],
            host_dependencies: vec![],
        };
        let mut context = VmExecutionContext::default();
        context.this = Some("submission".into());
        VmInstance::new(module, context).unwrap()
    }

    #[test]
    fn bound_and_unbound_submit_share_the_guarded_syscall() {
        let mut vm = instance();
        let mut host = Host::default();
        let args = vec![
            VmValue::String("con_child".into()),
            VmValue::String("source".into()),
        ];
        let handle = vm.heap.capture(VmValue::DeploymentHandle).unwrap();
        vm.call_deployment_method(&handle, "submit", args.clone(), vec![], &mut host)
            .unwrap();
        let mut unbound = vec![handle.clone()];
        unbound.extend(args.clone());
        vm.call_deployment_method(
            &VmValue::Builtin("Contract".into()),
            "submit",
            unbound,
            vec![],
            &mut host,
        )
        .unwrap();
        assert_eq!(host.calls[0], host.calls[1]);
        assert_eq!(host.calls[0].0, "contract.deploy");
        assert_eq!(
            host.calls[0].2,
            vec![
                ("name".into(), args[0].clone()),
                ("code".into(), args[1].clone())
            ]
        );
        vm.call_deployment_method(
            &handle,
            "get_info",
            vec![args[0].clone()],
            vec![],
            &mut host,
        )
        .unwrap();
        assert_eq!(host.calls[2].0, "contract.info");
        assert!(vm
            .call_deployment_method(&handle, "missing", vec![], vec![], &mut host)
            .is_err());
        let mut wrong = vec![VmValue::None];
        wrong.extend(args.clone());
        assert!(vm
            .call_deployment_method(
                &VmValue::Builtin("Contract".into()),
                "submit",
                wrong,
                vec![],
                &mut host
            )
            .is_err());
        vm.context.this = Some("con_constructor".into());
        assert!(vm
            .call_deployment_method(&handle, "submit", args, vec![], &mut host)
            .unwrap_err()
            .to_string()
            .contains("restricted to submission"));
        assert_eq!(host.calls.len(), 3);
    }
}
