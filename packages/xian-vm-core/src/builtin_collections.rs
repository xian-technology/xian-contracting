//! Collection consumers with Python signatures, stable ordering and shared values.
use super::*;
use std::cmp::Ordering;

#[derive(Default)]
struct Options {
    key: Option<VmValue>,
    default: Option<VmValue>,
    reverse: bool,
}

fn options(kwargs: Vec<(String, VmValue)>, allowed: &[&str]) -> Result<Options, VmExecutionError> {
    let mut result = Options::default();
    let mut seen = HashSet::new();
    for (name, value) in kwargs {
        if !allowed.contains(&name.as_str()) || !seen.insert(name.clone()) {
            return Err(VmExecutionError::new(format!(
                "unexpected or duplicate keyword '{name}'"
            )));
        }
        match name.as_str() {
            "key" => result.key = Some(value),
            "default" => result.default = Some(value),
            "reverse" => result.reverse = value.truthy(),
            _ => unreachable!(),
        }
    }
    Ok(result)
}

impl VmInstance {
    pub(super) fn collection_builtin(
        &mut self,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        match name {
            "sum" => self.sum_values(args, kwargs, host),
            "sorted" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new(
                        "sorted() expects one positional argument",
                    ));
                }
                let options = options(kwargs, &["key", "reverse"])?;
                let values = self.collect_iterable(&args[0], host)?;
                Ok(VmValue::List(self.order_values(values, options, host)?))
            }
            _ => self.extreme_value(name, args, kwargs, host),
        }
    }

    fn keyed(
        &mut self,
        value: &VmValue,
        key: &Option<VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        match key {
            None | Some(VmValue::None) => Ok(value.clone()),
            Some(function) => {
                self.call_callable_value(host, function.clone(), vec![value.clone()], vec![])
            }
        }
    }

    fn extreme_value(
        &mut self,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let options = options(kwargs, &["key", "default"])?;
        if args.is_empty() || (args.len() > 1 && options.default.is_some()) {
            return Err(VmExecutionError::new(
                "min/max require values; default requires one iterable",
            ));
        }
        let source = if args.len() == 1 {
            args[0].clone()
        } else {
            self.heap.capture(VmValue::Tuple(args))?
        };
        let iterator = crate::iteration::iter(&source, &self.heap)?;
        self.select_extreme(
            if name == "min" {
                Ordering::Less
            } else {
                Ordering::Greater
            },
            &iterator,
            options,
            host,
        )
    }

    fn select_extreme(
        &mut self,
        wanted: Ordering,
        iterator: &VmValue,
        options: Options,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let Some(mut best) = self.next_item(iterator, host)? else {
            return options
                .default
                .ok_or_else(|| VmExecutionError::new("min/max received an empty iterable"));
        };
        let mut best_key = self.keyed(&best, &options.key, host)?;
        while let Some(candidate) = self.next_item(&iterator, host)? {
            host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
            let key = self.keyed(&candidate, &options.key, host)?;
            if compare_vm_values(&key, &best_key)? == wanted {
                best = candidate;
                best_key = key;
            }
        }
        Ok(best)
    }

    fn sum_values(
        &mut self,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let mut total = sum_start(&args, kwargs)?;
        if matches!(
            total.snapshot(),
            VmValue::String(_) | VmValue::Bytes(_) | VmValue::ByteArray(_)
        ) {
            return Err(VmExecutionError::new("sum() cannot sum strings or bytes"));
        }
        let iterator = crate::iteration::iter(&args[0], &self.heap)?;
        while let Some(value) = self.next_item(&iterator, host)? {
            host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
            total = apply_binary_operator("add", total, value)?;
        }
        Ok(total)
    }

    fn order_values(
        &mut self,
        values: Vec<VmValue>,
        options: Options,
        host: &mut dyn VmHost,
    ) -> Result<Vec<VmValue>, VmExecutionError> {
        let mut decorated = Vec::with_capacity(values.len());
        for value in values {
            decorated.push((self.keyed(&value, &options.key, host)?, value));
        }
        stable_order(&mut decorated, options.reverse, host)?;
        Ok(decorated.into_iter().map(|(_, value)| value).collect())
    }

    pub(super) fn sort_list(
        &mut self,
        receiver: VmValue,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if !args.is_empty() {
            return Err(VmExecutionError::new(
                "list.sort() accepts keyword arguments only",
            ));
        }
        let options = options(kwargs, &["key", "reverse"])?;
        let VmValue::Reference(reference) = receiver else {
            return Err(VmExecutionError::new("invalid list receiver"));
        };
        let VmValue::List(values) = reference.value() else {
            return Err(VmExecutionError::new("sort() requires a list"));
        };
        // Python hides the list while computing keys, and rejects mutation.
        reference.replace(VmValue::List(vec![]))?;
        let version = reference.version();
        let values = self.order_values(values, options, host)?;
        if version != reference.version() {
            return Err(VmExecutionError::new("list modified during sort"));
        }
        reference.replace(VmValue::List(values))?;
        Ok(VmValue::None)
    }
}

fn sum_start(
    args: &[VmValue],
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    if args.is_empty() || args.len() > 2 || kwargs.len() > 1 {
        return Err(VmExecutionError::new("invalid sum() arguments"));
    }
    let mut total = args.get(1).cloned().unwrap_or_else(|| vm_int(0));
    if let Some((name, value)) = kwargs.into_iter().next() {
        if name != "start" || args.len() == 2 {
            return Err(VmExecutionError::new("invalid or duplicate sum() start"));
        }
        total = value;
    }
    Ok(total)
}

fn stable_order(
    values: &mut Vec<(VmValue, VmValue)>,
    reverse: bool,
    host: &mut dyn VmHost,
) -> Result<(), VmExecutionError> {
    let mut width = 1;
    while width < values.len() {
        let mut merged = Vec::with_capacity(values.len());
        for start in (0..values.len()).step_by(width * 2) {
            let middle = (start + width).min(values.len());
            let end = (middle + width).min(values.len());
            merge_runs(
                &values[start..middle],
                &values[middle..end],
                &mut merged,
                reverse,
                host,
            )?;
        }
        *values = merged;
        width *= 2;
    }
    Ok(())
}

fn merge_runs(
    left: &[(VmValue, VmValue)],
    right: &[(VmValue, VmValue)],
    output: &mut Vec<(VmValue, VmValue)>,
    reverse: bool,
    host: &mut dyn VmHost,
) -> Result<(), VmExecutionError> {
    let (mut a, mut b) = (0, 0);
    while a < left.len() && b < right.len() {
        host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
        let ordering = compare_vm_values(&left[a].0, &right[b].0)?;
        let ordering = if reverse {
            ordering.reverse()
        } else {
            ordering
        };
        if ordering != Ordering::Greater {
            output.push(left[a].clone());
            a += 1;
        } else {
            output.push(right[b].clone());
            b += 1;
        }
    }
    output.extend_from_slice(&left[a..]);
    output.extend_from_slice(&right[b..]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_stable_in_both_directions() {
        let input = vec![
            (vm_int(1), VmValue::String("a".into())),
            (vm_int(2), VmValue::String("b".into())),
            (vm_int(1), VmValue::String("c".into())),
        ];
        for (reverse, expected) in [(false, ["a", "c", "b"]), (true, ["b", "a", "c"])] {
            let mut values = input.clone();
            stable_order(&mut values, reverse, &mut NoopHost).unwrap();
            assert_eq!(
                values
                    .iter()
                    .map(|(_, value)| value.as_string().unwrap())
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }
}
