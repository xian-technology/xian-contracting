//! Logical insertion slots for live dictionary cursors. Payloads stay compact;
//! only slot numbers retain deletion holes. Growth compacts slots as in the
//! pinned historical compact dictionary, without depending on randomized hashes.
use crate::VmValue;

#[derive(Clone, Debug)]
pub(crate) struct DictSlots {
    pub positions: Vec<usize>,
    pub end: usize,
    table_size: usize,
    unicode_only: bool,
}

impl DictSlots {
    pub fn new(entries: &[(VmValue, VmValue)]) -> Self {
        let length = entries.len();
        Self {
            positions: (0..length).collect(),
            end: length,
            table_size: ((length * 3).div_ceil(2)).next_power_of_two().max(8),
            unicode_only: entries.iter().all(|(key, _)| is_string(key)),
        }
    }

    pub fn updated(&self, old: &[(VmValue, VmValue)], new: &[(VmValue, VmValue)]) -> Self {
        let mut result = Self {
            positions: Vec::with_capacity(new.len()),
            ..self.clone()
        };
        let mut old_index = 0;
        for (key, _) in new {
            // Mutations preserve existing key objects and their relative order.
            // Removed entries are skipped; new keys are always appended.
            while old_index < old.len() && old[old_index].0 != *key {
                old_index += 1;
            }
            if old_index < old.len() {
                result.positions.push(self.positions[old_index]);
                old_index += 1;
            } else {
                result.append(key);
            }
        }
        result
    }

    fn append(&mut self, key: &VmValue) {
        let generalize = self.unicode_only && !is_string(key);
        if self.end >= self.table_size * 2 / 3 || generalize {
            self.compact();
        }
        self.unicode_only &= !generalize;
        self.positions.push(self.end);
        self.end += 1;
    }

    fn compact(&mut self) {
        let used = self.positions.len();
        self.positions = (0..used).collect();
        self.end = used;
        self.table_size = (used * 3).next_power_of_two().max(8);
    }
}

fn is_string(value: &VmValue) -> bool {
    match value {
        VmValue::Reference(reference) => reference.with_value(|v| matches!(v, VmValue::String(_))),
        value => matches!(value, VmValue::String(_)),
    }
}
