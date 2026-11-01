//! Public attribute access shared by authored expressions and format fields.
use super::*;

#[derive(Debug, Clone, PartialEq)]
pub struct VmBoundMethod {
    pub receiver: VmValue,
    pub method: String,
}

impl VmInstance {
    pub(super) fn read_attribute(
        &mut self,
        value: VmValue,
        name: &str,
        _host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if name.starts_with('_') {
            return Err(VmExecutionError::new(
                "private attributes are not available to contracts",
            ));
        }
        if let Some(result) = self.host_callable_attribute(&value, name, _host) {
            return result;
        }
        if method_signatures::supports(&value, name) {
            return Ok(VmValue::BoundMethod(Box::new(VmBoundMethod {
                receiver: value,
                method: name.to_owned(),
            })));
        }
        if let Some(result) = crate::scalar_methods::attribute(&value, name) {
            return result;
        }
        match value.snapshot() {
            VmValue::Exception(exception) if name == "args" => Ok(VmValue::Tuple(exception.args)),
            VmValue::View(view) if name == "mapping" => {
                Ok(VmValue::MappingProxy(Box::new(view.source)))
            }
            _ => native_attribute_value(&value, name),
        }
    }
}
