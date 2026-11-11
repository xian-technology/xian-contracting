pub const COMPILER_FIXTURE_SCHEMA_V1: &str = "xian.compiler_fixture.v1";
pub const CONTRACT_ARTIFACT_FORMAT_V1: &str = "xian_contract_artifact_v1";
pub const XIAN_IR_V1: &str = "xian_ir_v1";
pub const XIAN_VM_HOST_CATALOG_V1: &str = "xian_vm_v1_host_v1";
pub const XIAN_VM_V1_PROFILE: &str = "xian_vm_v1";
pub const XIAN_VM_V2_PROFILE: &str = "xian_vm_v2";

pub const DEFAULT_VM_PROFILE: &str = XIAN_VM_V2_PROFILE;

pub(crate) fn validate_profile(profile: &str) -> Result<(), crate::ValidationError> {
    match profile {
        XIAN_VM_V1_PROFILE | XIAN_VM_V2_PROFILE => Ok(()),
        _ => Err(crate::ValidationError::field("vm_profile", format!("unsupported profile '{profile}'"))),
    }
}
