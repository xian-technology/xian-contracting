use crate::constants::{validate_profile, DEFAULT_VM_PROFILE};
use crate::error::{ensure_non_empty, ValidationError};
use crate::hashing::sha256_hex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceUnit {
    module_name: String,
    source: String,
    vm_profile: String,
}

impl SourceUnit {
    pub fn new(
        module_name: impl Into<String>,
        source: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        Self::with_profile(module_name, source, DEFAULT_VM_PROFILE)
    }

    pub fn with_profile(
        module_name: impl Into<String>,
        source: impl Into<String>,
        vm_profile: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        let module_name = module_name.into();
        let source = source.into();
        let vm_profile = vm_profile.into();
        ensure_non_empty("module_name", &module_name)?;
        ensure_non_empty("source", &source)?;
        validate_profile(&vm_profile)?;
        Ok(Self {
            module_name,
            source,
            vm_profile,
        })
    }

    pub fn module_name(&self) -> &str {
        &self.module_name
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn vm_profile(&self) -> &str {
        &self.vm_profile
    }

    pub fn source_sha256(&self) -> String {
        sha256_hex(&self.source)
    }
}
