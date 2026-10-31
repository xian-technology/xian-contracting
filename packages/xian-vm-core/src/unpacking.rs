//! Bounded iterable expansion for calls, literals and assignment targets.
use super::*;

impl VmInstance {
    pub(super) fn expand_values(
        &mut self,
        expressions: &[Value],
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<Vec<VmValue>, VmExecutionError> {
        let mut values = Vec::new();
        for expression in expressions {
            let object = as_object(expression, "expanded expression")?;
            if required_string(object, "node")? == "starred" {
                let source = self.eval_expression(required_value(object, "value")?, scope, host)?;
                let iterator = crate::iteration::iter(&source, &self.heap)?;
                while let Some(value) = self.next_item(&iterator, host)? {
                    host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
                    push(&mut values, value)?;
                }
            } else {
                push(&mut values, self.eval_expression(expression, scope, host)?)?;
            }
        }
        Ok(values)
    }

    pub(super) fn unpack_target(
        &mut self,
        elements: &[Value],
        source: VmValue,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
        module_scope: bool,
    ) -> Result<(), VmExecutionError> {
        let star = elements.iter().position(|target| {
            target.get("node").and_then(Value::as_str) == Some("starred_target")
        });
        let iterator = crate::iteration::iter(&source, &self.heap)?;
        let mut items = Vec::new();
        while let Some(item) = self.next_item(&iterator, host)? {
            host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
            // Ordinary unpacking consumes at most N+1 values, even on failure.
            if star.is_none() && items.len() == elements.len() {
                return Err(VmExecutionError::new("too many values to unpack"));
            }
            push(&mut items, item)?;
        }
        let minimum = elements.len() - usize::from(star.is_some());
        if items.len() < minimum {
            return Err(VmExecutionError::new("not enough values to unpack"));
        }
        let tail_start = star.map(|index| items.len() - (elements.len() - index - 1));
        let mut items = items.into_iter();
        for (index, target) in elements.iter().enumerate() {
            if Some(index) == star {
                let rest = items.by_ref().take(tail_start.unwrap() - index).collect();
                let value = self.heap.capture(VmValue::List(rest))?;
                self.assign_target(
                    required_value(as_object(target, "starred target")?, "value")?,
                    value,
                    scope,
                    host,
                    module_scope,
                )?;
            } else {
                self.assign_target(target, items.next().unwrap(), scope, host, module_scope)?;
            }
        }
        Ok(())
    }
}

fn push(values: &mut Vec<VmValue>, value: VmValue) -> Result<(), VmExecutionError> {
    if values.len() >= MAX_SEQUENCE_LENGTH {
        return Err(VmExecutionError::new(
            "iterable expansion allocation limit exceeded",
        ));
    }
    values.push(value);
    Ok(())
}

pub(super) fn duplicate_keyword(function: Option<&str>, key: &str) -> VmExecutionError {
    let label = function
        .map(|name| format!("__{name}()"))
        .unwrap_or_else(|| "call".to_owned());
    let message = format!("{label} got multiple values for keyword argument '{key}'");
    VmExecutionError::new(format!("TypeError({message:?})"))
}
