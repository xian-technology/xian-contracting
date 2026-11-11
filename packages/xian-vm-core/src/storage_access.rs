//! Access storage-backed values and synchronize host reads with local state.
use super::*;

impl VmInstance {
    pub(super) fn variable_get(
        &mut self,
        binding: &str,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let module_name = self.module.module_name.clone();
        let (foreign_key, default_value, current_value) = {
            let state = self.variables.get(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown variable binding '{binding}'"))
            })?;
            (
                state.foreign_key.clone(),
                state.default_value.clone(),
                state.value.clone(),
            )
        };
        if let Some(foreign_key) = foreign_key {
            let (foreign_contract, foreign_binding) = split_foreign_storage_key(&foreign_key)?;
            let loaded = host.read_variable(&foreign_contract, &foreign_binding)?;
            let foreign = self
                .variables
                .entry(foreign_key)
                .or_insert_with(|| VariableState {
                    value_type: None,
                    default_value: VmValue::None,
                    value: None,
                    foreign_key: None,
                    snapshot_local: false,
                    dirty: false,
                });
            if loaded.is_some() {
                foreign.value = loaded;
            }
            let value = foreign
                .value
                .clone()
                .unwrap_or_else(|| foreign.default_value.clone());
            charge_storage_read(
                host,
                &variable_storage_key(&foreign_contract, &foreign_binding),
                &value,
            )?;
            return Ok(value);
        }
        let storage_key = variable_storage_key(&module_name, binding);
        if let Some(value) = host.read_recorded_storage_write(&storage_key)? {
            let state = self.variables.get_mut(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown variable binding '{binding}'"))
            })?;
            state.value = Some(value.clone());
            charge_storage_read(host, &storage_key, &value)?;
            return Ok(value);
        }
        if current_value.is_none() {
            let loaded = host.read_variable(&module_name, binding)?;
            let state = self.variables.get_mut(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown variable binding '{binding}'"))
            })?;
            if state.value.is_none() {
                state.value = loaded;
            }
            let value = state
                .value
                .clone()
                .unwrap_or_else(|| state.default_value.clone());
            charge_storage_read(host, &storage_key, &value)?;
            return Ok(value);
        }
        let value = current_value.unwrap_or(default_value);
        charge_storage_read(host, &storage_key, &value)?;
        Ok(value)
    }

    pub(super) fn variable_set(
        &mut self,
        binding: &str,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        let state = self.variables.get_mut(binding).ok_or_else(|| {
            VmExecutionError::new(format!("unknown variable binding '{binding}'"))
        })?;
        if state.foreign_key.is_some() {
            return Err(VmExecutionError::new(format!(
                "cannot set foreign variable '{binding}'"
            )));
        }
        if !resolves_to!(value, VmValue::None) {
            if let Some(marker) = &state.value_type {
                if !type_matches(&value, marker)
                    || matches!(marker, VmValue::TypeMarker(name) if name == "Any")
                {
                    return Err(VmExecutionError::new("wrong type passed to Variable"));
                }
            }
        }
        state.value = Some(value.storage_value()?);
        state.dirty = true;
        Ok(())
    }

    pub(super) fn hash_get(
        &mut self,
        binding: &str,
        key: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let storage_key = normalize_hash_key(key)?;
        let module_name = self.module.module_name.clone();
        let (foreign_key, default_value, current_entry) = {
            let state = self.hashes.get(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown hash binding '{binding}'"))
            })?;
            (
                state.foreign_key.clone(),
                state.default_value.clone(),
                state.entries.get(&storage_key).cloned(),
            )
        };
        if let Some(foreign_key) = foreign_key {
            let (foreign_contract, foreign_binding) = split_foreign_storage_key(&foreign_key)?;
            let loaded = host.read_hash(&foreign_contract, &foreign_binding, &key.detached()?)?;
            let foreign = self.hashes.entry(foreign_key).or_insert_with(|| HashState {
                default_value: VmValue::None,
                entries: HashMap::new(),
                foreign_key: None,
                snapshot_local: false,
                dirty_entries: HashSet::new(),
            });
            if let Some(value) = loaded {
                foreign.entries.insert(storage_key.clone(), value);
            }
            let value = foreign
                .entries
                .get(&storage_key)
                .cloned()
                .unwrap_or_else(|| foreign.default_value.clone());
            charge_storage_read(
                host,
                &hash_storage_key(&foreign_contract, &foreign_binding, key)?,
                &value,
            )?;
            return Ok(value);
        }
        let full_storage_key = hash_storage_key(&module_name, binding, key)?;
        if let Some(value) = host.read_recorded_storage_write(&full_storage_key)? {
            let state = self.hashes.get_mut(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown hash binding '{binding}'"))
            })?;
            state.entries.insert(storage_key.clone(), value.clone());
            let value = if matches!(value, VmValue::None) {
                default_value
            } else {
                value
            };
            charge_storage_read(host, &full_storage_key, &value)?;
            return Ok(value);
        }
        if current_entry.is_none() {
            let loaded = host.read_hash(&module_name, binding, &key.detached()?)?;
            let state = self.hashes.get_mut(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown hash binding '{binding}'"))
            })?;
            if let Some(value) = loaded {
                state
                    .entries
                    .insert(storage_key.clone(), value.storage_value()?);
            }
            let value = state
                .entries
                .get(&storage_key)
                .filter(|value| !matches!(value, VmValue::None))
                .cloned()
                .unwrap_or_else(|| state.default_value.clone());
            charge_storage_read(host, &full_storage_key, &value)?;
            return Ok(value);
        }
        let value = current_entry
            .filter(|value| !matches!(value, VmValue::None))
            .unwrap_or(default_value);
        charge_storage_read(host, &full_storage_key, &value)?;
        Ok(value)
    }

    pub(super) fn hash_all(
        &mut self,
        binding: &str,
        prefix_args: &[VmValue],
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        Ok(VmValue::List(
            self.hash_entries(binding, prefix_args, host)?
                .into_iter()
                .map(|(_, value)| value)
                .collect(),
        ))
    }

    pub(super) fn hash_entries(
        &mut self,
        binding: &str,
        prefix_args: &[VmValue],
        host: &mut dyn VmHost,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        let module_name = self.module.module_name.clone();
        let prefix = hash_scan_prefix(prefix_args)?;
        let (scan_contract, scan_binding, state_key) = {
            let state = self.hashes.get(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown hash binding '{binding}'"))
            })?;
            if let Some(foreign_key) = &state.foreign_key {
                let (foreign_contract, foreign_binding) = split_foreign_storage_key(foreign_key)?;
                (foreign_contract, foreign_binding, foreign_key.clone())
            } else {
                (module_name.clone(), binding.to_owned(), binding.to_owned())
            }
        };

        let scanned = host.scan_hash_entries_metered(&scan_contract, &scan_binding, &prefix)?;
        let state = self.hashes.entry(state_key).or_insert_with(|| HashState {
            default_value: VmValue::None,
            entries: HashMap::new(),
            foreign_key: None,
            snapshot_local: false,
            dirty_entries: HashSet::new(),
        });
        let mut ordered = scanned
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>();
        // Only snapshot-local/dirty values can supplement the host. Cached reads
        // must not resurrect a tombstone written by a nested contract call.
        for (key, value) in &state.entries {
            if key.starts_with(&prefix)
                && (state.snapshot_local || state.dirty_entries.contains(key))
                && !ordered.contains_key(key)
                && !matches!(value, VmValue::None)
            {
                charge_storage_read(
                    host,
                    &hash_storage_key_from_normalized(&scan_contract, &scan_binding, key),
                    value,
                )?;
                ordered.insert(key.clone(), value.clone());
            }
        }
        let mut budget = crate::storage_scan::ScanBudget::default();
        let mut values = Vec::new();
        for (key, value) in ordered {
            if matches!(value, VmValue::None) {
                continue;
            }
            budget.observe(&key, &value)?;
            state.entries.insert(key.clone(), value.clone());
            values.push((key, value));
        }

        Ok(values)
    }

    pub(super) fn hash_set(
        &mut self,
        binding: &str,
        key: &VmValue,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        let storage_key = normalize_hash_key(key)?;
        let state = self
            .hashes
            .get_mut(binding)
            .ok_or_else(|| VmExecutionError::new(format!("unknown hash binding '{binding}'")))?;
        if state.foreign_key.is_some() {
            return Err(VmExecutionError::new(format!(
                "cannot set foreign hash '{binding}'"
            )));
        }
        state
            .entries
            .insert(storage_key.clone(), value.storage_value()?);
        state.dirty_entries.insert(storage_key);
        Ok(())
    }
}
