//! Bulk Hash operations share the bounded, metered scan and transaction overlay.
use super::*;

impl VmInstance {
    pub(super) fn hash_bulk_method(
        &mut self,
        target: &VmStorageRef,
        method: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if target.storage_type != "Hash" {
            return Err(VmExecutionError::new("bulk writes require a local Hash"));
        }
        match method {
            "clear" => {
                if !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "Hash.clear() accepts positional prefix arguments only",
                    ));
                }
                self.hash_clear(&target.binding, &args, host)?;
            }
            "clone_from" => {
                let source = match (args.as_slice(), kwargs.as_slice()) {
                    ([source], []) => source,
                    ([], [(name, source)]) if name == "source" => source,
                    _ => {
                        return Err(VmExecutionError::new(
                            "Hash.clone_from() requires one source",
                        ))
                    }
                };
                // Read before deleting: self-cloning and overlapping foreign sources
                // must copy the original snapshot, including pending nested writes.
                let snapshot = self.hash_source_entries(source, host)?;
                self.hash_clear(&target.binding, &[], host)?;
                for (key, value) in snapshot {
                    self.hash_write_normalized(&target.binding, &key, value, host)?;
                }
            }
            _ => unreachable!(),
        }
        Ok(VmValue::None)
    }

    fn hash_source_entries(
        &mut self,
        source: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        host.charge_execution_cost(VM_GAS_HASH_SCAN)?;
        match source {
            VmValue::StorageRef(reference)
                if matches!(reference.storage_type.as_str(), "Hash" | "ForeignHash") =>
            {
                self.hash_entries(&reference.binding, &[], host)
            }
            VmValue::ForeignStorageRef(reference) if reference.is_hash => Ok(host
                .scan_hash_entries_metered(&reference.contract, &reference.binding, "")?
                .into_iter()
                .filter(|(_, value)| !matches!(value, VmValue::None))
                .collect()),
            _ => Err(VmExecutionError::new(
                "Hash.clone_from() requires a Hash or ForeignHash source",
            )),
        }
    }

    fn hash_clear(
        &mut self,
        binding: &str,
        prefix: &[VmValue],
        host: &mut dyn VmHost,
    ) -> Result<(), VmExecutionError> {
        host.charge_execution_cost(VM_GAS_HASH_SCAN)?;
        let entries = self.hash_entries(binding, prefix, host)?;
        for (key, _) in entries {
            self.hash_write_normalized(binding, &key, VmValue::None, host)?;
        }
        Ok(())
    }

    fn hash_write_normalized(
        &mut self,
        binding: &str,
        key: &str,
        value: VmValue,
        host: &mut dyn VmHost,
    ) -> Result<(), VmExecutionError> {
        host.charge_execution_cost(VM_GAS_STMT_STORAGE_SET)?;
        let value = value.detached()?;
        let state = self
            .hashes
            .get_mut(binding)
            .ok_or_else(|| VmExecutionError::new("unknown hash binding"))?;
        if state.foreign_key.is_some() {
            return Err(VmExecutionError::new("cannot write to foreign storage"));
        }
        state.entries.insert(key.to_owned(), value.clone());
        state.dirty_entries.insert(key.to_owned());
        let full_key = hash_storage_key_from_normalized(&self.module.module_name, binding, key);
        record_storage_write(host, &full_key, &value)?;
        Ok(())
    }
}
