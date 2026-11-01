//! Methods on the genuine builtin sets produced by dictionary-view operations.
use super::*;

type Result<T> = std::result::Result<T, VmExecutionError>;

impl VmInstance {
    pub(super) fn call_builtin_set_method(
        &mut self,
        receiver: VmValue,
        method: &str,
        args: Vec<VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue> {
        match method {
            "add" => add_set(&receiver, args[0].clone(), host),
            "union" | "difference" | "update" | "difference_update" => {
                self.merge_builtin_sets(&receiver, method, &args, host)
            }
            "intersection" | "intersection_update" => {
                self.intersection_builtin_sets(&receiver, method, &args, host)
            }
            "issubset" => self.builtin_set_subset(&receiver, &args[0], host),
            "issuperset" | "isdisjoint" => {
                self.builtin_set_predicate(&receiver, &args[0], method == "isdisjoint", host)
            }
            "symmetric_difference" | "symmetric_difference_update" => {
                self.symmetric_builtin_set(&receiver, &args[0], method.ends_with("_update"), host)
            }
            _ => self.basic_builtin_set_method(&receiver, method, args, host),
        }
    }

    fn merge_builtin_sets(
        &mut self,
        receiver: &VmValue,
        method: &str,
        args: &[VmValue],
        host: &mut dyn VmHost,
    ) -> Result<VmValue> {
        let mutate = matches!(method, "update" | "difference_update");
        let result = if mutate {
            receiver.clone()
        } else {
            self.copy_builtin_set(receiver, host)?
        };
        self.update_builtin_set(&result, args, matches!(method, "union" | "update"), host)?;
        Ok(if mutate { VmValue::None } else { result })
    }

    fn intersection_builtin_sets(
        &mut self,
        receiver: &VmValue,
        method: &str,
        args: &[VmValue],
        host: &mut dyn VmHost,
    ) -> Result<VmValue> {
        let mut result = receiver.clone();
        for source in args {
            result = self.intersect_builtin_set(&result, source, host)?;
        }
        if method == "intersection_update" {
            replace_set(receiver, set_items(&result))?;
            Ok(VmValue::None)
        } else {
            self.copy_builtin_set(&result, host)
        }
    }

    fn builtin_set_subset(
        &mut self,
        receiver: &VmValue,
        source: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<VmValue> {
        let result = self.intersect_builtin_set(receiver, source, host)?;
        Ok(VmValue::Bool(set_len(&result) == set_len(receiver)))
    }

    fn copy_builtin_set(&self, receiver: &VmValue, host: &mut dyn VmHost) -> Result<VmValue> {
        host.charge_execution_cost(VM_GAS_LOOP_ITERATION + set_len(receiver) as u64)?;
        self.heap.capture(VmValue::BuiltinSet(set_items(receiver)))
    }

    /// Iterators are pulled one element at a time: callbacks see every published
    /// mutation and predicate/intersection exits leave the tail untouched.
    fn visit_set_operand(
        &mut self,
        source: &VmValue,
        host: &mut dyn VmHost,
        mut visit: impl FnMut(&mut Self, VmValue, &mut dyn VmHost) -> Result<bool>,
    ) -> Result<()> {
        let iterator = crate::iteration::iter(source, &self.heap)?;
        let mut consumed = 0;
        loop {
            host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
            let Some(item) = self.next_item(&iterator, host)? else {
                break;
            };
            consumed += 1;
            if consumed > MAX_SEQUENCE_LENGTH {
                return Err(VmExecutionError::new("set iterable limit exceeded"));
            }
            charge_hashable(&item, host)?;
            if !visit(self, item, host)? {
                break;
            }
        }
        Ok(())
    }

    fn update_builtin_set(
        &mut self,
        receiver: &VmValue,
        sources: &[VmValue],
        insert: bool,
        host: &mut dyn VmHost,
    ) -> Result<()> {
        for source in sources {
            // Genuine set self-update is a no-op/self-clear, not iteration over
            // a container whose size is changed by each removal.
            if receiver.identical(source) {
                if !insert {
                    replace_set(receiver, vec![])?;
                }
                continue;
            }
            self.visit_set_operand(source, host, |_, item, host| {
                edit_set(receiver, item, insert, host)?;
                Ok(true)
            })?;
        }
        Ok(())
    }

    fn intersect_builtin_set(
        &mut self,
        receiver: &VmValue,
        source: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<VmValue> {
        if receiver.identical(source) {
            return self.copy_builtin_set(receiver, host);
        }
        let result = self.heap.capture(VmValue::BuiltinSet(vec![]))?;
        self.visit_set_operand(source, host, |_, item, host| {
            if contains_set(receiver, &item, host)? {
                edit_set(&result, item, true, host)?;
                // Check only after a match. Even an empty receiver must consume
                // and hash-check its iterable, as historical CPython does.
                return Ok(set_len(&result) < set_len(receiver));
            }
            Ok(true)
        })?;
        Ok(result)
    }

    fn builtin_set_predicate(
        &mut self,
        receiver: &VmValue,
        source: &VmValue,
        disjoint: bool,
        host: &mut dyn VmHost,
    ) -> Result<VmValue> {
        let mut result = true;
        self.visit_set_operand(source, host, |_, item, host| {
            if contains_set(receiver, &item, host)? == disjoint {
                result = false;
            }
            Ok(result)
        })?;
        Ok(VmValue::Bool(result))
    }

    fn symmetric_builtin_set(
        &mut self,
        receiver: &VmValue,
        source: &VmValue,
        mutate: bool,
        host: &mut dyn VmHost,
    ) -> Result<VmValue> {
        let other = self.heap.capture(VmValue::BuiltinSet(vec![]))?;
        self.update_builtin_set(&other, std::slice::from_ref(source), true, host)?;
        // Materialize before copying: iterator callbacks can mutate receiver.
        let result = self.copy_builtin_set(receiver, host)?;
        for item in set_items(&other) {
            let insert = !contains_set(&result, &item, host)?;
            edit_set(&result, item, insert, host)?;
        }
        if mutate {
            replace_set(receiver, set_items(&result))?;
            Ok(VmValue::None)
        } else {
            Ok(result)
        }
    }

    fn basic_builtin_set_method(
        &mut self,
        receiver: &VmValue,
        method: &str,
        args: Vec<VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue> {
        host.charge_execution_cost(VM_GAS_LOOP_ITERATION + set_len(receiver) as u64)?;
        if let Some(item) = args.first() {
            charge_scan(receiver, item, host)?;
        }
        crate::decimal_metering::normalization(host, &set_items(receiver))?;
        let result =
            support::set_kinds::method(set_items(receiver), method, args, &mut |source| {
                self.collect_iterable(source, host)
            })?;
        match result {
            NativeMethodResult::Value(value) => Ok(value),
            NativeMethodResult::Mutated {
                receiver: updated,
                value,
            } => {
                replace_set(receiver, set_items(&updated))?;
                Ok(value)
            }
        }
    }
}

fn set_items(receiver: &VmValue) -> Vec<VmValue> {
    let VmValue::BuiltinSet(items) = receiver.snapshot() else {
        unreachable!("builtin set receiver")
    };
    items
}
fn set_len(receiver: &VmValue) -> usize {
    if let VmValue::Reference(reference) = receiver {
        reference.with_value(|value| match value {
            VmValue::BuiltinSet(items) => items.len(),
            _ => unreachable!(),
        })
    } else {
        match receiver {
            VmValue::BuiltinSet(items) => items.len(),
            _ => unreachable!(),
        }
    }
}
fn replace_set(receiver: &VmValue, items: Vec<VmValue>) -> Result<()> {
    let VmValue::Reference(reference) = receiver else {
        return Err(VmExecutionError::new(
            "mutable set requires a heap reference",
        ));
    };
    reference.replace(VmValue::BuiltinSet(items))
}
fn charge_hashable(item: &VmValue, host: &mut dyn VmHost) -> Result<()> {
    host.charge_execution_cost(mapping_views::value_work(item).saturating_mul(32))?;
    support::builtin_set_keys::ensure_hashable(item)
}
fn add_set(receiver: &VmValue, item: VmValue, host: &mut dyn VmHost) -> Result<VmValue> {
    edit_set(receiver, item, true, host)?;
    Ok(VmValue::None)
}
fn charge_scan(receiver: &VmValue, item: &VmValue, host: &mut dyn VmHost) -> Result<()> {
    // Canonical-key construction and equality scan string/byte/tuple payloads.
    // Member count alone would allow long common prefixes to evade the budget.
    let payload = mapping_views::set_items_work(receiver).saturating_add(
        mapping_views::value_work(item).saturating_mul(set_len(receiver) as u64 + 1),
    );
    host.charge_execution_cost(VM_GAS_LOOP_ITERATION.saturating_add(payload.saturating_mul(32)))?;
    crate::decimal_metering::comparison(host, receiver, item, false)
}
fn contains_set(receiver: &VmValue, item: &VmValue, host: &mut dyn VmHost) -> Result<bool> {
    charge_scan(receiver, item, host)?;
    set_contains_value(&set_items(receiver), item)
}
fn edit_set(receiver: &VmValue, item: VmValue, insert: bool, host: &mut dyn VmHost) -> Result<()> {
    charge_scan(receiver, &item, host)?;
    let mut items = set_items(receiver);
    if insert {
        support::builtin_set_keys::insert(&mut items, item)?;
    } else {
        items = set_difference_values(&items, &[item])?;
    }
    replace_set(receiver, items)
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
                module_name: "con_builtin_sets".into(),
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
    fn receiver(vm: &VmInstance, items: &[i64]) -> VmValue {
        vm.heap
            .capture(VmValue::BuiltinSet(
                items.iter().copied().map(vm_int).collect(),
            ))
            .unwrap()
    }
    fn assert_items(value: &VmValue, expected: &[i64]) {
        let VmValue::BuiltinSet(items) = value.snapshot() else {
            panic!("lost builtin set kind")
        };
        assert_eq!(
            items.iter().map(VmValue::snapshot).collect::<Vec<_>>(),
            expected.iter().copied().map(vm_int).collect::<Vec<_>>()
        );
    }
    fn invoke(
        vm: &mut VmInstance,
        receiver: &VmValue,
        method: &str,
        args: Vec<VmValue>,
    ) -> Result<VmValue> {
        vm.call_builtin_set_method(receiver.clone(), method, args, &mut NoopHost)
    }

    #[test]
    fn intersection_and_subset_stop_after_unique_matches() {
        for method in ["intersection", "issubset", "intersection_update"] {
            let mut vm = instance();
            let target = receiver(&vm, &[1, 2]);
            let source =
                VmValue::List(vec![vm_int(2), vm_int(2), vm_int(1), VmValue::List(vec![])]);
            let iter = crate::iteration::iter(&source, &vm.heap).unwrap();
            let result = invoke(&mut vm, &target, method, vec![iter.clone()]).unwrap();
            match method {
                "issubset" => assert_eq!(result, VmValue::Bool(true)),
                "intersection_update" => {
                    assert_eq!(result, VmValue::None);
                    assert_items(&target, &[1, 2]);
                }
                _ => assert_items(&result, &[1, 2]),
            }
            assert!(matches!(
                vm.next_item(&iter, &mut NoopHost)
                    .unwrap()
                    .unwrap()
                    .snapshot(),
                VmValue::List(_)
            ));
        }
    }

    #[test]
    fn boolean_predicates_leave_iterator_tail_unconsumed() {
        for (method, first) in [("isdisjoint", 1), ("issuperset", 3)] {
            let mut vm = instance();
            let target = receiver(&vm, &[1, 2]);
            let iter =
                crate::iteration::iter(&VmValue::List(vec![vm_int(first), vm_int(9)]), &vm.heap)
                    .unwrap();
            assert_eq!(
                invoke(&mut vm, &target, method, vec![iter.clone()]).unwrap(),
                VmValue::Bool(false)
            );
            assert_eq!(
                vm.next_item(&iter, &mut NoopHost)
                    .unwrap()
                    .map(|v| v.snapshot()),
                Some(vm_int(9))
            );
        }
    }

    #[test]
    fn nonmatching_prefix_is_skipped_and_predicates_can_succeed() {
        let mut vm = instance();
        let target = receiver(&vm, &[1, 2]);
        let result = invoke(
            &mut vm,
            &target,
            "intersection",
            vec![VmValue::List(vec![vm_int(9), vm_int(2)])],
        )
        .unwrap();
        assert_items(&result, &[2]);
        for (method, items) in [("issuperset", vec![1, 2]), ("isdisjoint", vec![3, 4])] {
            let source = VmValue::List(items.into_iter().map(vm_int).collect());
            assert_eq!(
                invoke(&mut vm, &target, method, vec![source]).unwrap(),
                VmValue::Bool(true)
            );
        }
    }

    #[test]
    fn incremental_updates_publish_before_later_unhashable_error() {
        for (method, first, expected) in [
            ("update", 3, vec![1, 2, 3]),
            ("difference_update", 2, vec![1]),
        ] {
            let mut vm = instance();
            let target = receiver(&vm, &[1, 2]);
            let alias = target.clone();
            let source = VmValue::List(vec![vm_int(first), VmValue::List(vec![])]);
            let error = invoke(&mut vm, &target, method, vec![source]).unwrap_err();
            assert!(error.to_string().contains("unhashable"));
            assert_items(&alias, &expected);
        }
    }

    #[test]
    fn temporary_updates_do_not_publish_on_failure() {
        for method in ["intersection_update", "symmetric_difference_update"] {
            let mut vm = instance();
            let target = receiver(&vm, &[1, 2]);
            let source = VmValue::List(vec![vm_int(2), VmValue::List(vec![])]);
            assert!(invoke(&mut vm, &target, method, vec![source]).is_err());
            assert_items(&target, &[1, 2]);
        }
    }

    #[test]
    fn symmetric_difference_deduplicates_operand_and_preserves_result_kind() {
        let mut vm = instance();
        let target = receiver(&vm, &[1, 2]);
        let source = VmValue::List(vec![vm_int(2), vm_int(2), vm_int(3), vm_int(3)]);
        let result = invoke(
            &mut vm,
            &target,
            "symmetric_difference",
            vec![source.clone()],
        )
        .unwrap();
        assert_items(&result, &[1, 3]);
        assert_items(&target, &[1, 2]);
        assert_eq!(
            invoke(
                &mut vm,
                &target,
                "symmetric_difference_update",
                vec![source]
            )
            .unwrap(),
            VmValue::None
        );
        assert_items(&target, &[1, 3]);
    }

    #[test]
    fn self_alias_updates_and_empty_receiver_hash_checks() {
        for method in [
            "update",
            "difference_update",
            "intersection_update",
            "symmetric_difference_update",
        ] {
            let mut vm = instance();
            let target = receiver(&vm, &[1, 2]);
            invoke(&mut vm, &target, method, vec![target.clone()]).unwrap();
            assert_items(
                &target,
                if matches!(method, "update" | "intersection_update") {
                    &[1, 2]
                } else {
                    &[]
                },
            );
        }
        for method in [
            "intersection",
            "issubset",
            "issuperset",
            "isdisjoint",
            "difference_update",
        ] {
            let mut vm = instance();
            let target = receiver(&vm, &[]);
            assert!(invoke(
                &mut vm,
                &target,
                method,
                vec![VmValue::List(vec![VmValue::List(vec![])])]
            )
            .is_err());
        }
    }

    #[test]
    fn insertion_preserves_canonical_representatives_and_nan_identity() {
        let mut vm = instance();
        let target = receiver(&vm, &[2]);
        let nan = vm.heap.capture(VmValue::Float(f64::NAN)).unwrap();
        let other_nan = vm.heap.capture(VmValue::Float(f64::NAN)).unwrap();
        let source = VmValue::List(vec![
            vm_int(2),
            vm_int(1),
            VmValue::Bool(true),
            nan.clone(),
            nan.clone(),
            other_nan.clone(),
        ]);
        invoke(&mut vm, &target, "update", vec![source]).unwrap();
        let items = set_items(&target);
        assert_eq!(items.len(), 4);
        assert_eq!(items[0].snapshot(), VmValue::Bool(true));
        assert_eq!(items[1].snapshot(), vm_int(2));
        assert!(items[2].identical(&nan));
        assert!(items[3].identical(&other_nan));
    }

    #[test]
    fn basic_methods_keep_builtin_kind_and_mutate_aliases() {
        let mut vm = instance();
        let target = receiver(&vm, &[1, 2]);
        let copied = invoke(&mut vm, &target, "copy", vec![]).unwrap();
        assert_items(&copied, &[1, 2]);
        assert!(!copied.identical(&target));
        invoke(&mut vm, &target, "add", vec![vm_int(3)]).unwrap();
        invoke(&mut vm, &target, "remove", vec![vm_int(1)]).unwrap();
        invoke(&mut vm, &target, "discard", vec![vm_int(99)]).unwrap();
        assert_items(&target, &[2, 3]);
        assert_eq!(
            invoke(&mut vm, &target, "pop", vec![]).unwrap().snapshot(),
            vm_int(2)
        );
        assert_items(&copied, &[1, 2]);
        invoke(&mut vm, &target, "clear", vec![]).unwrap();
        assert_items(&target, &[]);
        assert!(invoke(&mut vm, &target, "pop", vec![]).is_err());
    }

    #[test]
    fn multi_operand_difference_consumes_tail_and_intersection_is_atomic() {
        let mut vm = instance();
        let target = receiver(&vm, &[1, 2, 3]);
        let result = invoke(
            &mut vm,
            &target,
            "difference",
            vec![
                VmValue::List(vec![vm_int(1)]),
                VmValue::List(vec![vm_int(2)]),
            ],
        )
        .unwrap();
        assert_items(&result, &[3]);
        assert_items(&target, &[1, 2, 3]);
        let result = invoke(
            &mut vm,
            &target,
            "union",
            vec![
                VmValue::List(vec![vm_int(4)]),
                VmValue::List(vec![vm_int(5)]),
            ],
        )
        .unwrap();
        assert_items(&result, &[1, 2, 3, 4, 5]);
        assert!(invoke(
            &mut vm,
            &target,
            "intersection_update",
            vec![
                VmValue::List(vec![vm_int(1)]),
                VmValue::List(vec![VmValue::List(vec![])])
            ]
        )
        .is_err());
        assert_items(&target, &[1, 2, 3]);
        assert!(invoke(
            &mut vm,
            &target,
            "difference",
            vec![VmValue::List(vec![
                vm_int(1),
                vm_int(2),
                vm_int(3),
                VmValue::List(vec![])
            ])]
        )
        .is_err());
        assert_items(&target, &[1, 2, 3]);
    }

    #[test]
    fn iterable_limit_accepts_boundary_and_rejects_next_item() {
        for (length, succeeds) in [
            (MAX_SEQUENCE_LENGTH, true),
            (MAX_SEQUENCE_LENGTH + 1, false),
        ] {
            let mut vm = instance();
            let target = receiver(&vm, &[]);
            let source = VmValue::Range(crate::VmRange {
                start: 0.into(),
                stop: length.into(),
                step: 1.into(),
            });
            let result = invoke(&mut vm, &target, "difference_update", vec![source]);
            assert_eq!(result.is_ok(), succeeds);
            if let Err(error) = result {
                assert!(error.to_string().contains("set iterable limit"));
            }
            assert_items(&target, &[]);
        }
    }

    #[test]
    fn payload_scan_budget_rejects_long_keys_before_mutation() {
        struct Budget(u64);
        impl VmHost for Budget {
            fn charge_execution_cost(&mut self, cost: u64) -> Result<()> {
                self.0 = self
                    .0
                    .checked_sub(cost)
                    .ok_or_else(|| VmExecutionError::new("budget exceeded"))?;
                Ok(())
            }
        }
        let keys = [
            VmValue::String("x".repeat(20_000)),
            VmValue::Bytes(vec![120; 20_000]),
            VmValue::Tuple((0..1024).map(vm_int).collect()),
        ];
        for key in keys {
            for method in ["add", "update", "remove", "discard", "issuperset"] {
                let mut vm = instance();
                let target = vm
                    .heap
                    .capture(VmValue::BuiltinSet(vec![key.clone()]))
                    .unwrap();
                let argument = if matches!(method, "update" | "issuperset") {
                    VmValue::List(vec![key.clone()])
                } else {
                    key.clone()
                };
                let result = vm.call_builtin_set_method(
                    target.clone(),
                    method,
                    vec![argument],
                    &mut Budget(4096),
                );
                assert!(result.is_err(), "{method} failed to precharge key payload");
                assert_eq!(set_len(&target), 1);
            }
        }
    }

    #[test]
    fn add_at_capacity_keeps_duplicate_but_rejects_new_member() {
        struct LinearBudget;
        impl VmHost for LinearBudget {
            fn charge_execution_cost(&mut self, cost: u64) -> Result<()> {
                if cost > 1_000_000_000 {
                    return Err(VmExecutionError::new("quadratic work exceeds budget"));
                }
                Ok(())
            }
        }
        let mut vm = instance();
        let target = receiver(&vm, &[]);
        // Publish a canonical maximum-sized set without a quadratic constructor.
        let items = (0..MAX_SEQUENCE_LENGTH)
            .map(|n| vm.heap.capture(vm_int(n)).unwrap())
            .collect();
        replace_set(&target, items).unwrap();
        vm.call_builtin_set_method(target.clone(), "add", vec![vm_int(0)], &mut LinearBudget)
            .unwrap();
        assert_eq!(set_len(&target), MAX_SEQUENCE_LENGTH);
        let error = vm
            .call_builtin_set_method(
                target.clone(),
                "add",
                vec![vm_int(MAX_SEQUENCE_LENGTH)],
                &mut LinearBudget,
            )
            .unwrap_err();
        assert!(error.to_string().contains("set allocation limit exceeded"));
        assert_eq!(set_len(&target), MAX_SEQUENCE_LENGTH);
    }

    #[test]
    fn low_budget_rejects_before_first_mutation() {
        struct Reject;
        impl VmHost for Reject {
            fn charge_execution_cost(&mut self, _: u64) -> Result<()> {
                Err(VmExecutionError::new("budget exceeded"))
            }
        }
        let mut vm = instance();
        let target = receiver(&vm, &[1]);
        assert!(vm
            .call_builtin_set_method(
                target.clone(),
                "update",
                vec![VmValue::List(vec![vm_int(2)])],
                &mut Reject
            )
            .is_err());
        assert_items(&target, &[1]);
    }
}
