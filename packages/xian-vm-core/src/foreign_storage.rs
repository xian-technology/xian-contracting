//! Dynamic foreign references use the same host reads and byte charges as static storage.
//! They contain no cached values or writable bindings and cannot cross the host boundary.
use super::*;

pub(super) fn new_reference(
    kind: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    // The first two parameters are the local ORM identity in the Python harness;
    // the native reference only needs the foreign target. Authored calls normally
    // supply foreign_contract and foreign_name as keywords.
    let names = ["contract", "name", "foreign_contract", "foreign_name"];
    if args.len() > names.len() {
        return Err(VmExecutionError::new(format!(
            "{kind}() expects at most four positional arguments"
        )));
    }
    let mut parameters = HashMap::new();
    for (name, value) in names.iter().zip(args) {
        parameters.insert((*name).to_owned(), value);
    }
    for (name, value) in kwargs {
        if !names.contains(&name.as_str()) || parameters.insert(name.clone(), value).is_some() {
            return Err(VmExecutionError::new(format!(
                "invalid or duplicate {kind}() argument '{name}'"
            )));
        }
    }
    let mut target = |name: &str| -> Result<String, VmExecutionError> {
        let value = parameters
            .remove(name)
            .ok_or_else(|| VmExecutionError::new(format!("{kind}() requires {name}")))?
            .as_string()?;
        // A target is one contract/variable identifier, never a composed storage
        // key. In particular, separators must not escape the requested namespace.
        let mut chars = value.chars();
        if !chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(VmExecutionError::new(format!("invalid {name} identifier")));
        }
        Ok(value)
    };
    Ok(VmValue::ForeignStorageRef(VmForeignStorageRef {
        contract: target("foreign_contract")?,
        binding: target("foreign_name")?,
        is_hash: kind == "ForeignHash",
    }))
}

pub(super) fn read_hash(
    reference: &VmForeignStorageRef,
    key: &VmValue,
    host: &mut dyn VmHost,
) -> Result<VmValue, VmExecutionError> {
    if !reference.is_hash {
        return Err(VmExecutionError::new(
            "ForeignVariable is not subscriptable",
        ));
    }
    host.charge_execution_cost(VM_GAS_EXPR_STORAGE_GET)?;
    let storage_key = hash_storage_key(&reference.contract, &reference.binding, key)?;
    let value = host
        .read_hash(&reference.contract, &reference.binding, key)?
        .unwrap_or(VmValue::None);
    charge_storage_read(host, &storage_key, &value)?;
    Ok(value)
}

pub(super) fn call_method(
    reference: &VmForeignStorageRef,
    method: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
    host: &mut dyn VmHost,
) -> Result<VmValue, VmExecutionError> {
    if !kwargs.is_empty() {
        return Err(VmExecutionError::new(
            "foreign storage reads do not accept keyword arguments",
        ));
    }
    match (reference.is_hash, method) {
        (false, "get") if args.is_empty() => {
            host.charge_execution_cost(VM_GAS_VARIABLE_GET)?;
            let key = variable_storage_key(&reference.contract, &reference.binding);
            let value = host
                .read_variable(&reference.contract, &reference.binding)?
                .unwrap_or(VmValue::None);
            charge_storage_read(host, &key, &value)?;
            Ok(value)
        }
        (true, "all") => {
            host.charge_execution_cost(VM_GAS_HASH_SCAN)?;
            let prefix = normalize_hash_prefix(&args)?;
            let entries =
                host.scan_hash_entries(&reference.contract, &reference.binding, &prefix)?;
            let mut values = Vec::new();
            for (suffix, value) in entries {
                if matches!(value, VmValue::None) {
                    continue;
                }
                let key = hash_storage_key_from_normalized(
                    &reference.contract,
                    &reference.binding,
                    &suffix,
                );
                charge_storage_read(host, &key, &value)?;
                values.push(value);
            }
            Ok(VmValue::List(values))
        }
        (
            _,
            "set" | "clear" | "clone_from" | "append" | "extend" | "pop" | "update" | "setdefault",
        ) => Err(VmExecutionError::new("cannot write to foreign storage")),
        _ => Err(VmExecutionError::new(format!(
            "unsupported foreign storage method '{method}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct ReadHost {
        costs: Vec<u64>,
        reads: Vec<String>,
    }
    impl VmHost for ReadHost {
        fn charge_execution_cost(&mut self, cost: u64) -> Result<(), VmExecutionError> {
            self.costs.push(cost);
            Ok(())
        }
        fn charge_storage_read(&mut self, key: &str, _: &VmValue) -> Result<(), VmExecutionError> {
            self.reads.push(key.to_owned());
            Ok(())
        }
        fn read_hash(
            &mut self,
            _: &str,
            _: &str,
            _: &VmValue,
        ) -> Result<Option<VmValue>, VmExecutionError> {
            Ok(Some(VmValue::String("XSC-0005".to_owned())))
        }
        fn scan_hash_entries(
            &mut self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
            Ok(vec![("group:a".to_owned(), VmValue::Bool(true))])
        }
    }

    #[test]
    fn each_read_charges_the_target_key_and_existing_storage_operation_cost() {
        let mut host = ReadHost::default();
        let mut reference = VmForeignStorageRef {
            contract: "con_nft".to_owned(),
            binding: "metadata".to_owned(),
            is_hash: true,
        };
        let key = VmValue::String("standard".to_owned());
        for _ in 0..2 {
            read_hash(&reference, &key, &mut host).unwrap();
        }
        call_method(&reference, "all", vec![], vec![], &mut host).unwrap();
        reference.is_hash = false;
        assert_eq!(
            call_method(&reference, "get", vec![], vec![], &mut host).unwrap(),
            VmValue::None
        );
        assert_eq!(
            host.costs,
            vec![
                VM_GAS_EXPR_STORAGE_GET,
                VM_GAS_EXPR_STORAGE_GET,
                VM_GAS_HASH_SCAN,
                VM_GAS_VARIABLE_GET
            ]
        );
        assert_eq!(
            host.reads,
            vec![
                "con_nft.metadata:standard",
                "con_nft.metadata:standard",
                "con_nft.metadata:group:a",
                "con_nft.metadata"
            ]
        );
    }

    #[test]
    fn constructor_rejects_invalid_and_ambiguous_targets() {
        let valid = vec![
            (
                "foreign_contract".to_owned(),
                VmValue::String("con_nft".to_owned()),
            ),
            (
                "foreign_name".to_owned(),
                VmValue::String("metadata".to_owned()),
            ),
        ];
        assert!(new_reference("ForeignHash", vec![], valid.clone()).is_ok());
        assert!(new_reference("ForeignVariable", vec![], valid.clone()).is_ok());
        assert!(new_reference("ForeignHash", vec![], vec![]).is_err());
        for field in 0..2 {
            for value in [
                VmValue::String("metadata:secret".to_owned()),
                VmValue::String("con_nft.metadata".to_owned()),
                VmValue::None,
                VmValue::Bool(true),
            ] {
                let mut kwargs = valid.clone();
                kwargs[field].1 = value;
                assert!(new_reference("ForeignHash", vec![], kwargs).is_err());
            }
        }
        let mut duplicates = valid.clone();
        duplicates.push(valid[0].clone());
        assert!(new_reference("ForeignHash", vec![], duplicates).is_err());
        let mut extra = valid;
        extra.push(("driver".to_owned(), VmValue::None));
        assert!(new_reference("ForeignHash", vec![], extra).is_err());
    }
}
