//! Allocation bounds shared by native and embedded storage scan hosts.
use crate::{VmExecutionError, VmValue};

#[derive(Default)]
pub(crate) struct ScanBudget {
    bytes: usize,
    entries: usize,
}

impl ScanBudget {
    pub(crate) fn observe(&mut self, key: &str, value: &VmValue) -> Result<(), VmExecutionError> {
        self.bytes = self
            .bytes
            .saturating_add(key.len())
            .saturating_add(crate::metering::encode_vm_value(value)?.len());
        self.entries += 1;
        if self.bytes > crate::interpreter::MAX_BINARY_ALLOCATION_BYTES
            || self.entries > crate::interpreter::MAX_SEQUENCE_LENGTH
        {
            return Err(VmExecutionError::new(
                "hash scan result exceeds allocation limit",
            ));
        }
        Ok(())
    }
}
