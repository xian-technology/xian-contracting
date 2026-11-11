//! All public event call forms share schema checks, payload validation and charging.
use super::*;

pub(super) fn indexed(
    mut args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
    host: &mut dyn VmHost,
) -> Result<VmValue, VmExecutionError> {
    if args.is_empty() || !kwargs.is_empty() {
        return Err(VmExecutionError::new(
            "indexed() requires at least one positional argument and no keywords",
        ));
    }
    host.charge_execution_cost((args.len() as u64).saturating_mul(32))?;
    if args.len() == 1 {
        if let Some(types) = indexed_tuple_members(&args[0], host)? {
            args = types;
        }
    }
    let types = if args.len() == 1 {
        args.remove(0)
    } else {
        VmValue::Tuple(args)
    };
    Ok(VmValue::Dict(vec![
        (VmValue::String("type".into()), types),
        (VmValue::String("idx".into()), VmValue::Bool(true)),
    ]))
}

fn indexed_tuple_members(
    value: &VmValue,
    host: &mut dyn VmHost,
) -> Result<Option<Vec<VmValue>>, VmExecutionError> {
    match value {
        VmValue::Reference(reference) => {
            reference.with_value(|value| indexed_tuple_members(value, host))
        }
        VmValue::Tuple(values) => {
            host.charge_execution_cost((values.len() as u64).saturating_mul(32))?;
            Ok(Some(values.clone()))
        }
        _ => Ok(None),
    }
}

pub(super) fn work_cost(schema: &VmValue, payload: Option<&VmValue>) -> u64 {
    mapping_views::value_work(schema)
        .saturating_add(payload.map(mapping_views::value_work).unwrap_or(0))
        .saturating_mul(event_field_count(schema))
        .saturating_mul(32)
}

pub(super) fn declaration_schema(
    name: &str,
    schema: &VmValue,
) -> Result<VmValue, VmExecutionError> {
    validate_schema(name, schema)?;
    schema.detached()
}

pub(super) fn validate_schema(name: &str, schema: &VmValue) -> Result<(), VmExecutionError> {
    if name.chars().all(support::unicode_whitespace) {
        return Err(VmExecutionError::new("event name must not be empty"));
    }
    let VmValue::Dict(entries) = schema.snapshot() else {
        return Err(VmExecutionError::new(
            "event schema must be a nonempty dict",
        ));
    };
    if entries.is_empty() {
        return Err(VmExecutionError::new(
            "event schema must be a nonempty dict",
        ));
    }
    let mut indexed = 0;
    for (key, spec) in &entries {
        let VmValue::String(key) = key.snapshot() else {
            return Err(VmExecutionError::new(
                "event argument names must be strings",
            ));
        };
        if key.chars().all(support::unicode_whitespace) {
            return Err(VmExecutionError::new(
                "event argument name must not be empty",
            ));
        }
        let (types, is_indexed) = parameter(spec)?;
        validate_types(&types)?;
        indexed += usize::from(is_indexed);
    }
    if indexed > 3 {
        return Err(VmExecutionError::new(
            "event schema allows at most three indexed arguments",
        ));
    }
    Ok(())
}

fn parameter(spec: &VmValue) -> Result<(VmValue, bool), VmExecutionError> {
    let VmValue::Dict(entries) = spec.snapshot() else {
        return Ok((spec.clone(), false));
    };
    if entries.iter().any(
        |(key, _)| !resolves_to!(key, VmValue::String(name) if name == "type" || name == "idx"),
    ) {
        return Err(VmExecutionError::new("unsupported event schema key"));
    }
    let types = dict_get(&entries, &VmValue::String("type".into()))?
        .ok_or_else(|| VmExecutionError::new("event parameter must declare a type"))?;
    let indexed =
        match dict_get(&entries, &VmValue::String("idx".into()))?.map(|value| value.snapshot()) {
            None | Some(VmValue::Bool(false)) => false,
            Some(VmValue::Bool(true)) => true,
            _ => return Err(VmExecutionError::new("event idx must be a boolean")),
        };
    Ok((types, indexed))
}

fn valid_type(value: &VmValue) -> bool {
    resolves_to!(value, VmValue::Builtin(name) | VmValue::TypeMarker(name)
        if matches!(name.as_str(), "str" | "int" | "float" | "bool" | "bytes" | "bytearray" | "set" | "frozenset" | "decimal"))
}
fn validate_types(types: &VmValue) -> Result<(), VmExecutionError> {
    let valid = match types.snapshot() {
        VmValue::Tuple(types) => !types.is_empty() && types.iter().all(valid_type),
        other => valid_type(&other),
    };
    if valid {
        Ok(())
    } else {
        Err(VmExecutionError::new("invalid event parameter type"))
    }
}

fn validate_payload(schema: &VmValue, payload: &VmValue) -> Result<(), VmExecutionError> {
    let VmValue::Dict(schema) = schema.snapshot() else {
        unreachable!()
    };
    let VmValue::Dict(payload) = payload.snapshot() else {
        return Err(VmExecutionError::new("event payload must be a dict"));
    };
    if schema.len() != payload.len() {
        return Err(VmExecutionError::new("event payload has incorrect keys"));
    }
    for (key, spec) in schema {
        let value = dict_get(&payload, &key)?
            .ok_or_else(|| VmExecutionError::new("event payload is missing key"))?;
        if !type_matches(&value, &parameter(&spec)?.0) {
            return Err(VmExecutionError::new(format!(
                "event argument {} has wrong type",
                key.python_repr()
            )));
        }
        if crate::rendering::render(&value)?.len() > 1024 {
            return Err(VmExecutionError::new(format!(
                "event argument {} exceeds 1024 bytes",
                key.python_repr()
            )));
        }
    }
    Ok(())
}

fn event_field_count(schema: &VmValue) -> u64 {
    match schema {
        VmValue::Reference(reference) => reference.with_value(event_field_count),
        VmValue::Dict(entries) => entries.len().max(1) as u64,
        _ => 1,
    }
}

fn charge_event_fields(
    host: &mut dyn VmHost,
    indexed: &[(String, VmValue)],
    data: &[(String, VmValue)],
) -> Result<(), VmExecutionError> {
    for (key, value) in indexed.iter().chain(data.iter()) {
        host.charge_storage_write(key, value)?;
    }
    Ok(())
}

impl VmInstance {
    pub(super) fn call_event(
        &mut self,
        event: &VmEventDefinition,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let payload = method_signatures::bind_one("data", args, kwargs)?;
        self.emit_declared_event(event, payload, host)
    }

    fn require_own_event(&self, event: &VmEventDefinition) -> Result<(), VmExecutionError> {
        // Resolve only a declaration in this instance. Event capabilities remain
        // forbidden across contract boundaries and methods cannot construct them.
        if matches!(self.globals.get(&event.binding), Some(VmValue::EventRef(own)) if own.as_ref() == event)
        {
            Ok(())
        } else {
            Err(VmExecutionError::new(
                "event does not belong to the current contract",
            ))
        }
    }

    pub(super) fn emit_declared_event(
        &mut self,
        event: &VmEventDefinition,
        payload: VmValue,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        host.charge_execution_cost(VM_GAS_EVENT_EMIT)?;
        host.charge_execution_cost(work_cost(&event.params, Some(&payload)))?;
        self.require_own_event(event)?;
        validate_schema(&event.event_name, &event.params)?;
        validate_payload(&event.params, &payload)?;
        let (data_indexed, data) = normalize_event_payload(&event.params, payload)?;
        charge_event_fields(host, &data_indexed, &data)?;
        host.emit_event(VmEvent {
            contract: self.module.module_name.clone(),
            event: event.event_name.clone(),
            signer: option_string_value(&self.context.signer),
            caller: option_string_value(&self.context.caller),
            data_indexed,
            data,
        })?;
        Ok(VmValue::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn indexed(
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        super::indexed(args, kwargs, &mut NoopHost)
    }
    #[derive(Default)]
    struct BudgetHost {
        cost: u64,
        limit: u64,
    }
    impl VmHost for BudgetHost {
        fn charge_execution_cost(&mut self, cost: u64) -> Result<(), VmExecutionError> {
            self.cost += cost;
            if self.cost > self.limit {
                Err(VmExecutionError::new("test budget exhausted"))
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn indexed_precharges_large_tuple_copy_before_allocation() {
        let heap = crate::heap::VmHeap::default();
        let tuple = heap
            .capture(VmValue::Tuple(vec![VmValue::Builtin("int".into()); 4096]))
            .unwrap();
        let mut large = BudgetHost {
            cost: 0,
            limit: u64::MAX,
        };
        super::indexed(vec![tuple.clone()], vec![], &mut large).unwrap();
        assert!(large.cost >= 4096 * 32);
        let mut small = BudgetHost {
            cost: 0,
            limit: u64::MAX,
        };
        super::indexed(
            vec![VmValue::Tuple(vec![VmValue::Builtin("int".into()); 2048])],
            vec![],
            &mut small,
        )
        .unwrap();
        assert!(large.cost > small.cost);
        assert!(large.cost <= small.cost * 2);
        let mut limited = BudgetHost {
            cost: 0,
            limit: 4096 * 32 - 1,
        };
        assert!(super::indexed(vec![tuple], vec![], &mut limited).is_err());
    }

    fn schema(value: VmValue) -> VmValue {
        VmValue::Dict(vec![(VmValue::String("value".into()), value)])
    }
    fn marker(name: &str) -> VmValue {
        VmValue::TypeMarker(name.into())
    }

    #[test]
    fn indexed_flattens_one_tuple_and_preserves_member_identity() {
        assert!(indexed(vec![], vec![]).is_err());
        let key = VmValue::String("type".into());
        let class = VmValue::Builtin("int".into());
        let result = indexed(vec![VmValue::Tuple(vec![class.clone()])], vec![]).unwrap();
        let VmValue::Dict(entries) = result else {
            panic!("expected indexed metadata")
        };
        assert!(dict_get(&entries, &key).unwrap().unwrap().identical(&class));
        let result = indexed(vec![VmValue::Tuple(vec![])], vec![]).unwrap();
        let VmValue::Dict(entries) = result else {
            panic!("expected indexed metadata")
        };
        assert_eq!(
            dict_get(&entries, &key).unwrap(),
            Some(VmValue::Tuple(vec![]))
        );
        let heap = crate::heap::VmHeap::default();
        let list = heap.capture(VmValue::List(vec![])).unwrap();
        let result = indexed(vec![list.clone()], vec![]).unwrap();
        let VmValue::Dict(entries) = result else {
            panic!("expected indexed metadata")
        };
        assert!(dict_get(&entries, &key).unwrap().unwrap().identical(&list));
    }

    #[test]
    fn schema_requires_admitted_types_and_boolean_index_flags() {
        assert!(validate_schema("E", &schema(marker("str"))).is_ok());
        assert!(validate_schema(
            "E",
            &schema(VmValue::Tuple(vec![marker("bytes"), marker("bytearray")]))
        )
        .is_ok());
        assert!(validate_schema("E", &schema(marker("list"))).is_err());
        assert!(validate_schema("E", &schema(VmValue::Tuple(vec![]))).is_err());
        assert!(validate_schema(
            "E",
            &schema(VmValue::Dict(vec![
                (VmValue::String("type".into()), marker("int")),
                (VmValue::String("idx".into()), vm_int(1)),
            ]))
        )
        .is_err());
    }

    #[test]
    fn declaration_freezes_schema_and_nested_parameter_aliases() {
        let heap = crate::heap::VmHeap::default();
        let outer = heap.capture(schema(marker("int"))).unwrap();
        let saved = declaration_schema("E", &outer).unwrap();
        let VmValue::Reference(reference) = outer else {
            panic!("expected captured schema")
        };
        reference.replace(schema(marker("str"))).unwrap();
        assert!(validate_payload(&saved, &schema(vm_int(7))).is_ok());

        let spec = heap
            .capture(VmValue::Dict(vec![
                (VmValue::String("type".into()), marker("int")),
                (VmValue::String("idx".into()), VmValue::Bool(true)),
            ]))
            .unwrap();
        let saved = declaration_schema("E", &schema(spec.clone())).unwrap();
        let VmValue::Reference(reference) = spec else {
            panic!("expected captured parameter")
        };
        reference
            .replace(VmValue::Dict(vec![
                (VmValue::String("type".into()), marker("int")),
                (VmValue::String("idx".into()), VmValue::Bool(false)),
            ]))
            .unwrap();
        let (indexed, data) = normalize_event_payload(&saved, schema(vm_int(7))).unwrap();
        assert_eq!(indexed.len(), 1);
        assert!(data.is_empty());
    }

    #[test]
    fn declaration_schema_accepts_heap_captured_names_and_parameter_dicts() {
        let heap = crate::heap::VmHeap::default();
        let schema = heap
            .capture(schema(VmValue::Dict(vec![
                (VmValue::String("type".into()), marker("int")),
                (VmValue::String("idx".into()), VmValue::Bool(true)),
            ])))
            .unwrap();
        assert!(validate_schema("E", &schema).is_ok());
        let payload = heap
            .capture(VmValue::Dict(vec![(
                VmValue::String("value".into()),
                vm_int(7),
            )]))
            .unwrap();
        assert!(validate_payload(&schema, &payload).is_ok());
    }

    #[test]
    fn schema_allows_exactly_three_indexed_fields() {
        let indexed = VmValue::Dict(vec![
            (VmValue::String("type".into()), marker("int")),
            (VmValue::String("idx".into()), VmValue::Bool(true)),
        ]);
        let fields = (0..3)
            .map(|i| (VmValue::String(i.to_string()), indexed.clone()))
            .collect::<Vec<_>>();
        assert!(validate_schema("E", &VmValue::Dict(fields.clone())).is_ok());
        let mut too_many = fields;
        too_many.push((VmValue::String("extra".into()), indexed));
        assert!(validate_schema("E", &VmValue::Dict(too_many)).is_err());
        assert!(validate_schema("\u{1c}", &schema(marker("str"))).is_err());
        assert_eq!(parameter(&marker("str")).unwrap().1, false);
        assert_eq!(
            parameter(&VmValue::Dict(vec![
                (VmValue::String("type".into()), marker("int")),
                (VmValue::String("idx".into()), VmValue::Bool(true)),
            ]))
            .unwrap()
            .1,
            true
        );
    }

    #[test]
    fn event_payload_checks_utf8_size_and_actual_type() {
        let text = schema(marker("str"));
        assert!(validate_payload(&text, &schema(VmValue::String("é".repeat(512)))).is_ok());
        assert!(validate_payload(&text, &schema(VmValue::String("é".repeat(513)))).is_err());
        assert!(validate_payload(&text, &schema(vm_int(1))).is_err());
        assert!(validate_payload(&schema(marker("int")), &schema(VmValue::Bool(true))).is_ok());
        assert!(validate_payload(&schema(marker("bool")), &schema(vm_int(1))).is_err());
    }

    #[test]
    fn event_binder_rejects_duplicates_extras_and_unexpected_keywords() {
        let value = schema(vm_int(1));
        assert!(method_signatures::bind_one("data", vec![value.clone()], vec![]).is_ok());
        assert!(
            method_signatures::bind_one("data", vec![], vec![("data".into(), value.clone())])
                .is_ok()
        );
        assert!(
            method_signatures::bind_one("data", vec![value.clone(), value.clone()], vec![])
                .is_err()
        );
        assert!(method_signatures::bind_one(
            "data",
            vec![value.clone()],
            vec![("data".into(), value.clone())]
        )
        .is_err());
        assert!(
            method_signatures::bind_one("data", vec![], vec![("value".into(), value)]).is_err()
        );
    }
}
