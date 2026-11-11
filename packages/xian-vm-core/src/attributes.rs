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
        if deployment_handles::is_class(&value) && name == "submit" {
            return self.static_method("Contract", name);
        }
        if deployment_handles::is_instance(&value) {
            if name == "submit" {
                return self.bound_public_method(value, name);
            }
            if let Some(callable) = VmHostCallable::named(&format!("Contract.{name}")) {
                return Ok(callable.value());
            }
        }
        if name.starts_with('_') {
            return Err(VmExecutionError::new(
                "private attributes are not available to contracts",
            ));
        }
        if let Some(result) = self.interface_attribute(&value, name) {
            return result;
        }
        if let Some(result) = self.host_callable_attribute(&value, name, _host) {
            return result;
        }
        if method_signatures::supports(&value, name) {
            return self.bound_public_method(value, name);
        }
        if let Some(result) = crate::scalar_methods::attribute(&value, name) {
            return result;
        }
        let special = value.with_resolved(|resolved| match resolved {
            VmValue::Exception(exception) if name == "args" => {
                Some(VmValue::Tuple(exception.args.clone()))
            }
            VmValue::View(view) if name == "mapping" => {
                Some(VmValue::MappingProxy(Box::new(view.source.clone())))
            }
            _ => None,
        });
        match special {
            Some(special) => Ok(special),
            None => native_attribute_value(&value, name),
        }
    }
    fn interface_attribute(
        &mut self,
        value: &VmValue,
        name: &str,
    ) -> Option<Result<VmValue, VmExecutionError>> {
        if let Some(class) = orm_methods::class_method(value, name) {
            return Some(self.static_method(class, name));
        }
        if name == "is_of" {
            let class = value.with_resolved(|resolved| {
                interface_descriptors::descriptor_class(resolved).map(str::to_owned)
            });
            if let Some(class) = class {
                return Some(self.static_method(&class, name));
            }
        }
        if let Some(class) =
            value.with_resolved(|resolved| method_signatures::wrapper_class(resolved, name))
        {
            return Some(self.static_method(class, name));
        }
        interface_subjects::attribute(value, name)
            .or_else(|| interface_descriptors::attribute(value, name))
    }
    fn bound_public_method(
        &mut self,
        value: VmValue,
        name: &str,
    ) -> Result<VmValue, VmExecutionError> {
        if let Some(class) = static_factory_class(&value, name) {
            return self.static_method(&class, name);
        }
        if let Some(class) = method_signatures::unbound_class(&value, name) {
            return self.static_method(class, name);
        }
        Ok(VmValue::BoundMethod(Box::new(VmBoundMethod {
            receiver: method_receiver(value, name),
            method: name.into(),
        })))
    }
    pub(super) fn static_method(
        &mut self,
        class: &str,
        method: &str,
    ) -> Result<VmValue, VmExecutionError> {
        let key = format!("{class}.{method}");
        if let Some(value) = self.static_methods.get(&key) {
            return Ok(value.clone());
        }
        let value = self
            .heap
            .capture(VmValue::BoundMethod(Box::new(VmBoundMethod {
                receiver: VmValue::Builtin(class.into()),
                method: method.into(),
            })))?;
        self.static_methods.insert(key, value.clone());
        Ok(value)
    }
}

fn method_receiver(value: VmValue, name: &str) -> VmValue {
    if name == "strptime" && resolves_to!(value, VmValue::DateTime(_)) {
        return VmValue::TypeMarker("datetime.datetime".into());
    }
    normalized_class(&value, name)
        .map(|class| VmValue::Builtin(class.into()))
        .unwrap_or(value)
}

fn normalized_class(value: &VmValue, method: &str) -> Option<&'static str> {
    match method {
        "from_bytes" => integer_class(value),
        "fromhex" => binary_or_float_class(value),
        "fromkeys" if resolves_to!(value, VmValue::Dict(_)) => Some("dict"),
        _ => None,
    }
}
fn integer_class(value: &VmValue) -> Option<&'static str> {
    value.with_resolved(|resolved| match resolved {
        VmValue::Bool(_) => Some("bool"),
        VmValue::Int(_) => Some("builtins.int"),
        _ => None,
    })
}
fn binary_or_float_class(value: &VmValue) -> Option<&'static str> {
    value.with_resolved(|resolved| match resolved {
        VmValue::Bytes(_) => Some("builtins.bytes"),
        VmValue::ByteArray(_) => Some("builtins.bytearray"),
        VmValue::Float(_) => Some("float"),
        _ => None,
    })
}
fn static_factory_class(value: &VmValue, method: &str) -> Option<String> {
    value.with_resolved(|resolved| match (resolved, method) {
        (VmValue::String(_), "maketrans") => Some("str".into()),
        (VmValue::Bytes(_), "maketrans") => Some("builtins.bytes".into()),
        (VmValue::ByteArray(_), "maketrans") => Some("builtins.bytearray".into()),
        (VmValue::Builtin(name) | VmValue::TypeMarker(name), "maketrans")
            if matches!(name.as_str(), "str" | "bytes" | "bytearray") =>
        {
            Some(name.clone())
        }
        (VmValue::Builtin(name) | VmValue::TypeMarker(name), "fromhex")
            if matches!(name.as_str(), "bytes" | "bytearray") =>
        {
            Some(name.clone())
        }
        _ => None,
    })
}

/// Guarded exported classes and builtin literal classes have distinct method
/// identities, while invocation uses the same validated implementation.
pub(super) fn invocation_receiver(receiver: VmValue) -> VmValue {
    let VmValue::Builtin(name) = &receiver else {
        return receiver;
    };
    match name.as_str() {
        "builtins.int" => VmValue::Builtin("int".into()),
        "builtins.bytes" => VmValue::Builtin("bytes".into()),
        "builtins.bytearray" => VmValue::Builtin("bytearray".into()),
        _ => receiver,
    }
}
