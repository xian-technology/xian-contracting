//! Live dictionary-view protocols. Only keys/items participate in set operations.
use super::*;
use crate::iteration::ViewMode;

pub(super) fn is_set_view(value: &VmValue) -> bool {
    matches!(value.snapshot(), VmValue::View(view) if !matches!(view.mode, ViewMode::Values))
}

fn is_builtin_setlike(value: &VmValue) -> bool {
    matches!(value.snapshot(), VmValue::BuiltinSet(_)) || is_set_view(value)
}

pub(super) fn contains(
    view: &crate::VmDictView,
    needle: &VmValue,
) -> Result<bool, VmExecutionError> {
    let VmValue::Dict(entries) = view.source.snapshot() else {
        return Err(VmExecutionError::new("invalid dictionary view source"));
    };
    match view.mode {
        ViewMode::Keys => Ok(dict_get(&entries, needle)?.is_some()),
        ViewMode::Items => {
            let VmValue::Tuple(pair) = needle.snapshot() else {
                return Ok(false);
            };
            if pair.len() != 2 {
                return Ok(false);
            }
            let Some(value) = dict_get(&entries, &pair[0])? else {
                return Ok(false);
            };
            vm_values_equal(&value, &pair[1])
        }
        ViewMode::Values => {
            for (_, value) in &entries {
                if vm_values_equal(value, needle)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn set_values(value: &VmValue) -> Option<Vec<VmValue>> {
    match value.snapshot() {
        VmValue::BuiltinSet(values) => Some(values),
        VmValue::View(view) if !matches!(view.mode, ViewMode::Values) => {
            let VmValue::Dict(entries) = view.source.snapshot() else {
                return None;
            };
            Some(
                entries
                    .into_iter()
                    .map(|(key, value)| match view.mode {
                        ViewMode::Keys => key,
                        _ => VmValue::Tuple(vec![key, value]),
                    })
                    .collect(),
            )
        }
        _ => None,
    }
}

pub(super) fn comparison_work(left: &VmValue, right: &VmValue) -> u64 {
    if !is_builtin_setlike(left) && !is_builtin_setlike(right) {
        return 0;
    }
    pair_work(left, right)
}

pub(super) fn compare(
    operator: &str,
    left: &VmValue,
    right: &VmValue,
) -> Option<Result<bool, VmExecutionError>> {
    if !matches!(operator, "eq" | "not_eq" | "lt" | "lt_e" | "gt" | "gt_e")
        || (!is_builtin_setlike(left) && !is_builtin_setlike(right))
    {
        return None;
    }
    // Contracting's public set/frozenset classes are iterable wrappers, not
    // Python builtin sets, and do not participate in view rich comparison.
    if !is_builtin_setlike(left) || !is_builtin_setlike(right) {
        return Some(match operator {
            "eq" => Ok(false),
            "not_eq" => Ok(true),
            _ => Err(VmExecutionError::new(
                "dictionary views can only compare with set-like values",
            )),
        });
    }
    let (Some(left), Some(right)) = (set_values(left), set_values(right)) else {
        return Some(match operator {
            "eq" => Ok(false),
            "not_eq" => Ok(true),
            _ => Err(VmExecutionError::new(
                "dictionary views can only compare with set-like values",
            )),
        });
    };
    Some(compare_items(operator, &left, &right))
}

fn subset(left: &[VmValue], right: &[VmValue]) -> Result<bool, VmExecutionError> {
    for item in left {
        let mut found = false;
        for candidate in right {
            if vm_values_equal(item, candidate)? {
                found = true;
                break;
            }
        }
        if !found {
            return Ok(false);
        }
    }
    Ok(true)
}

fn compare_items(
    operator: &str,
    left: &[VmValue],
    right: &[VmValue],
) -> Result<bool, VmExecutionError> {
    Ok(match operator {
        "eq" => left.len() == right.len() && subset(left, right)?,
        "not_eq" => left.len() != right.len() || !subset(left, right)?,
        "lt" => left.len() < right.len() && subset(left, right)?,
        "lt_e" => left.len() <= right.len() && subset(left, right)?,
        "gt" => left.len() > right.len() && subset(right, left)?,
        _ => left.len() >= right.len() && subset(right, left)?,
    })
}

impl VmInstance {
    pub(super) fn view_isdisjoint(
        &mut self,
        receiver: &VmValue,
        other: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let VmValue::View(view) = receiver.snapshot() else {
            return Err(VmExecutionError::new("expected dictionary view"));
        };
        if matches!(view.mode, ViewMode::Values) {
            return Err(VmExecutionError::new(
                "values view has no isdisjoint method",
            ));
        }
        let iterator = crate::iteration::iter(other, &self.heap)?;
        while let Some(item) = self.next_item(&iterator, host)? {
            host.charge_execution_cost(pair_work(&view.source, &item))?;
            crate::decimal_metering::comparison(host, &view.source, &item, false)?;
            if contains(&view, &item)? {
                return Ok(VmValue::Bool(false));
            }
        }
        Ok(VmValue::Bool(true))
    }

    pub(super) fn view_binary(
        &mut self,
        operator: &str,
        left: &VmValue,
        right: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if operator == "bitxor" && is_items_view(left) && is_items_view(right) {
            return self.items_symmetric_difference(left, right, host);
        }
        if operator == "bitand" {
            let (view, other) = if is_set_view(left) {
                (left, right)
            } else {
                (right, left)
            };
            let VmValue::View(view) = view.snapshot() else {
                unreachable!()
            };
            let iterator = crate::iteration::iter(other, &self.heap)?;
            let mut matches = Vec::new();
            while let Some(item) = self.next_item(&iterator, host)? {
                host.charge_execution_cost(pair_work(&view.source, &item))?;
                crate::decimal_metering::comparison(host, &view.source, &item, false)?;
                if contains(&view, &item)? {
                    if matches.len() >= MAX_SEQUENCE_LENGTH {
                        return Err(VmExecutionError::new(
                            "view operation exceeds allocation limit",
                        ));
                    }
                    matches.push(item);
                }
            }
            return self.normalized_view_set(matches, host);
        }
        let left_items = self.collect_iterable(left, host)?;
        let left = self.normalized_view_set(left_items, host)?;
        let right_items = self.collect_iterable(right, host)?;
        let right = self.normalized_view_set(right_items, host)?;
        let left_len = set_values(&left).map_or(0, |v| v.len() as u64);
        let right_len = set_values(&right).map_or(0, |v| v.len() as u64);
        host.charge_execution_cost(
            pair_work(&left, &right)
                .saturating_add(value_work(&left).saturating_mul(left_len))
                .saturating_add(value_work(&right).saturating_mul(right_len)),
        )?;
        crate::decimal_metering::normalization(host, &[left.clone(), right.clone()])?;
        apply_binary_operator(operator, left, right)
    }

    fn items_symmetric_difference(
        &mut self,
        left: &VmValue,
        right: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        host.charge_execution_cost(comparison_work(left, right).saturating_mul(2))?;
        crate::decimal_metering::comparison(host, left, right, false)?;
        let left = set_values(left).expect("items view");
        let right = set_values(right).expect("items view");
        let mut output = Vec::new();
        for (source, other) in [(&left, &right), (&right, &left)] {
            for item in source {
                if !subset(std::slice::from_ref(item), other)? {
                    output.push(item.clone());
                }
            }
        }
        // CPython cancels equal items before hashing the result. Equal lists in
        // both views therefore cancel even though lists cannot enter a set.
        self.normalized_view_set(output, host)
    }

    fn normalized_view_set(
        &mut self,
        values: Vec<VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let value = VmValue::List(values);
        let VmValue::List(values) = &value else {
            unreachable!()
        };
        host.charge_execution_cost(
            value_work(&value)
                .saturating_mul(values.len() as u64)
                .saturating_mul(32),
        )?;
        crate::decimal_metering::normalization(host, &[value.clone()])?;
        support::set_kinds::normalized(values.clone(), MAX_SEQUENCE_LENGTH)
    }
}

pub(super) fn unwrap_mapping(value: VmValue) -> VmValue {
    match value {
        VmValue::MappingProxy(mapping) => mapping.snapshot(),
        other => other,
    }
}

pub(super) fn union_work(operator: &str, left: &VmValue, right: &VmValue) -> u64 {
    if operator != "bitor" {
        return 0;
    }
    let left = unwrap_mapping(left.snapshot());
    let right = unwrap_mapping(right.snapshot());
    if !matches!((&left, &right), (VmValue::Dict(_), VmValue::Dict(_))) {
        return 0;
    }
    pair_work(&left, &right)
}

fn is_items_view(value: &VmValue) -> bool {
    matches!(value.snapshot(), VmValue::View(view) if matches!(view.mode, ViewMode::Items))
}

// Comparison scans must account for payload length, not just item count. Borrow
// heap nodes and memoize aliases so profiling itself remains bounded.
pub(super) fn value_work(value: &VmValue) -> u64 {
    let mut walker = WorkWalker::default();
    walker.value(value, 0)
}

/// Payload work of the members, without the top-level set comparison factor.
/// Nested structural values retain their own comparison work and shared nodes
/// are profiled once. Saturation makes excessive graphs reject at precharge.
pub(super) fn set_items_work(value: &VmValue) -> u64 {
    fn visit(value: &VmValue, walker: &mut WorkWalker) -> u64 {
        match value {
            VmValue::Reference(reference) => reference.with_value(|value| visit(value, walker)),
            VmValue::Set(items) | VmValue::BuiltinSet(items) | VmValue::FrozenSet(items) => {
                walker.items(items, 0)
            }
            _ => walker.value(value, 0),
        }
    }
    visit(value, &mut WorkWalker::default())
}

#[derive(Default)]
struct WorkWalker {
    memo: std::collections::HashMap<usize, u64>,
    active: std::collections::HashSet<usize>,
    visited: usize,
}
impl WorkWalker {
    fn value(&mut self, value: &VmValue, depth: usize) -> u64 {
        self.visited += 1;
        if depth > 128 || self.visited > 1024 * 1024 {
            return u64::MAX;
        }
        if let VmValue::Reference(reference) = value {
            let id = reference.id();
            if let Some(cost) = self.memo.get(&id) {
                return *cost;
            }
            if !self.active.insert(id) {
                return u64::MAX;
            }
            let cost = reference.with_value(|value| self.value(value, depth + 1));
            self.active.remove(&id);
            self.memo.insert(id, cost);
            return cost;
        }
        self.content(value, depth).saturating_add(1)
    }
    fn content(&mut self, value: &VmValue, depth: usize) -> u64 {
        match value {
            VmValue::String(text) => text.len() as u64,
            VmValue::Bytes(bytes) | VmValue::ByteArray(bytes) => bytes.len() as u64,
            VmValue::Int(number) => number.bits().div_ceil(8),
            VmValue::Decimal(number) => number.scaled.bits().div_ceil(8),
            VmValue::RawDecimal(number) => number.coefficient.bits().div_ceil(8),
            VmValue::List(items) | VmValue::Tuple(items) => self.items(items, depth),
            VmValue::Set(items) | VmValue::BuiltinSet(items) | VmValue::FrozenSet(items) => {
                self.items(items, depth).saturating_mul(items.len() as u64)
            }
            VmValue::Dict(items) => items
                .iter()
                .fold(0_u64, |cost, (key, value)| {
                    cost.saturating_add(self.value(key, depth + 1))
                        .saturating_add(self.value(value, depth + 1))
                })
                .saturating_mul(items.len() as u64),
            VmValue::View(view) => self.value(&view.source, depth + 1),
            VmValue::MappingProxy(mapping) => self.value(mapping, depth + 1),
            _ => 16,
        }
    }
    fn items(&mut self, items: &[VmValue], depth: usize) -> u64 {
        items.iter().fold(0_u64, |cost, item| {
            cost.saturating_add(self.value(item, depth + 1))
        })
    }
}
fn collection_len(value: &VmValue) -> u64 {
    match value {
        VmValue::Reference(reference) => reference.with_value(collection_len),
        VmValue::View(view) => view.len() as u64,
        VmValue::MappingProxy(mapping) => collection_len(mapping),
        VmValue::Dict(items) => items.len() as u64,
        VmValue::Set(items)
        | VmValue::BuiltinSet(items)
        | VmValue::FrozenSet(items)
        | VmValue::List(items) => items.len() as u64,
        _ => 1,
    }
}
fn pair_work(left: &VmValue, right: &VmValue) -> u64 {
    value_work(left)
        .saturating_mul(collection_len(right).max(1))
        .saturating_add(value_work(right).saturating_mul(collection_len(left).max(1)))
        .saturating_mul(32)
}
