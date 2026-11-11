//! Builtin view-produced sets share deterministic storage, but not wrapper type semantics.
use super::*;

pub(super) fn binary(
    operator: &str,
    left: &[VmValue],
    right: &[VmValue],
) -> Result<VmValue, VmExecutionError> {
    binary_with_limit(operator, left, right, MAX_SEQUENCE_LENGTH)
}
fn binary_with_limit(
    operator: &str,
    left: &[VmValue],
    right: &[VmValue],
    limit: usize,
) -> Result<VmValue, VmExecutionError> {
    let items = match operator {
        "bitor" => set_union_values(left, right),
        "bitand" => set_intersection_values(left, right)?,
        "sub" => set_difference_values(left, right)?,
        "bitxor" => set_symmetric_difference_values(left, right)?,
        _ => return Err(VmExecutionError::new("unsupported builtin set operator")),
    };
    normalized(items, limit)
}

pub(in crate::interpreter) fn normalized(
    items: Vec<VmValue>,
    limit: usize,
) -> Result<VmValue, VmExecutionError> {
    let items = builtin_set_keys::normalize(items)?;
    if items.len() > limit {
        return Err(VmExecutionError::new("set allocation limit exceeded"));
    }
    Ok(VmValue::BuiltinSet(items))
}

/// Pay for member scans, canonical-key comparisons and result normalization
/// before binary operators can allocate or mutate an aliased receiver.
pub(in crate::interpreter) fn charge_binary(
    operator: &str,
    left: &VmValue,
    right: &VmValue,
    host: &mut dyn VmHost,
) -> Result<(), VmExecutionError> {
    if !matches!(operator, "bitor" | "bitand" | "sub" | "bitxor") {
        return Ok(());
    }
    let (Some(left_len), Some(right_len)) = (builtin_len(left), builtin_len(right)) else {
        return Ok(());
    };
    let members = left_len.saturating_add(right_len) as u64;
    let payload =
        mapping_views::set_items_work(left).saturating_add(mapping_views::set_items_work(right));
    host.charge_execution_cost(
        payload
            .saturating_add(1)
            .saturating_mul(members.max(1))
            .saturating_mul(32),
    )?;
    crate::decimal_metering::normalization(host, &[left.clone(), right.clone()])
}
fn builtin_len(value: &VmValue) -> Option<usize> {
    match value {
        VmValue::Reference(reference) => reference.with_value(builtin_len),
        VmValue::BuiltinSet(items) => Some(items.len()),
        _ => None,
    }
}

pub(in crate::interpreter) fn method(
    values: Vec<VmValue>,
    method: &str,
    args: Vec<VmValue>,
    collect: &mut dyn FnMut(&VmValue) -> Result<Vec<VmValue>, VmExecutionError>,
) -> Result<NativeMethodResult, VmExecutionError> {
    if matches!(method, "remove" | "discard") {
        if let Some(needle) = args.first() {
            if resolves_to!(needle, VmValue::BuiltinSet(_)) {
                return if method == "discard" {
                    Ok(NativeMethodResult::Value(VmValue::None))
                } else {
                    Err(VmExecutionError::new("set.remove(): value not found"))
                };
            }
            builtin_set_keys::ensure_hashable(needle)?;
        }
    }
    Ok(
        match native_methods::call_set_method(values, method, args, collect)? {
            NativeMethodResult::Value(value) => NativeMethodResult::Value(retag(value)),
            NativeMethodResult::Mutated { receiver, value } => NativeMethodResult::Mutated {
                receiver: retag(receiver),
                value,
            },
        },
    )
}
fn retag(value: VmValue) -> VmValue {
    match value {
        VmValue::Set(items) => VmValue::BuiltinSet(items),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn instance() -> VmInstance {
        VmInstance::new(
            ModuleIr {
                ir_version: crate::XIAN_IR_V1.into(),
                vm_profile: crate::XIAN_VM_V1_PROFILE.into(),
                host_catalog_version: crate::XIAN_VM_HOST_CATALOG_V1.into(),
                module_name: "con_set_resources".into(),
                source_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .into(),
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
    struct Budget(u64);
    impl VmHost for Budget {
        fn charge_execution_cost(&mut self, cost: u64) -> Result<(), VmExecutionError> {
            self.0 = self
                .0
                .checked_sub(cost)
                .ok_or_else(|| VmExecutionError::new("budget exceeded"))?;
            Ok(())
        }
    }
    fn name(id: &str) -> Value {
        json!({"node":"name", "id":id, "span":{"line":1,"col":0,"end_line":1,"end_col":1}, "host_binding_id":null})
    }
    #[test]
    fn operators_precharge_before_execution_or_inplace_mutation() {
        for operator in ["bitor", "bitand", "sub", "bitxor"] {
            for augmented in [false, true] {
                let mut vm = instance();
                let left = vm
                    .heap
                    .capture(VmValue::BuiltinSet(vec![VmValue::String("x".repeat(4096))]))
                    .unwrap();
                let right = vm
                    .heap
                    .capture(VmValue::BuiltinSet(vec![VmValue::String("y".repeat(4096))]))
                    .unwrap();
                let original = left.snapshot();
                let mut scope = HashMap::from([
                    ("left".to_owned(), left.clone()),
                    ("right".to_owned(), right),
                ]);
                let mut budget = Budget(1000);
                let result = if augmented {
                    vm.execute_statement(&json!({"node":"aug_assign","operator":operator,"target":name("left"),"value":name("right")}), &mut scope, &mut budget).map(|_| VmValue::None)
                } else {
                    vm.eval_expression(&json!({"node":"bin_op","operator":operator,"left":name("left"),"right":name("right")}), &mut scope, &mut budget)
                };
                assert!(result.is_err(), "{operator}, augmented={augmented}");
                assert_eq!(left.snapshot(), original, "mutation before resource check");
            }
        }
    }
    #[test]
    fn algebra_limits_apply_after_deduplication() {
        let left = vec![vm_int(1), vm_int(2)];
        assert!(binary_with_limit("bitor", &left, &[vm_int(3)], 2).is_err());
        assert!(binary_with_limit("bitxor", &left, &[vm_int(3)], 2).is_err());
        assert_eq!(
            binary_with_limit("bitor", &left, &left, 2).unwrap(),
            VmValue::BuiltinSet(left.clone())
        );
        assert!(binary_with_limit("bitand", &left, &left, 2).is_ok());
        assert!(binary_with_limit("sub", &left, &left, 0).is_ok());
    }
}
