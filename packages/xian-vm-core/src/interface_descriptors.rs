//! Mutable, execution-local importlib interface descriptors.
use super::builtin_dispatch::type_checks;
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmInterfaceKind {
    Func,
    Var,
}

/// Inspection metadata contains no callable or storage capabilities.
#[derive(Clone, Debug, PartialEq)]
pub enum VmInterfaceMember {
    Missing,
    Function { name: String, args: Vec<String> },
    FunctionReference { contract: String, name: String },
    Datum(String),
    Other,
}

impl VmInterfaceMember {
    pub fn inspection_work(&self) -> u64 {
        match self {
            Self::Function { name, args } => {
                args.iter().fold(name.len() as u64 + 1, |cost, arg| {
                    cost.saturating_add(arg.len() as u64 + 1)
                })
            }
            Self::FunctionReference { contract, name } => (contract.len() as u64)
                .saturating_add(name.len() as u64)
                .saturating_add(1),
            Self::Datum(name) => name.len() as u64 + 1,
            _ => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VmInterfaceDescriptor {
    pub kind: VmInterfaceKind,
    pub attributes: BTreeMap<String, VmValue>,
}

impl VmInterfaceDescriptor {
    pub(crate) fn class_name(&self) -> &'static str {
        match self.kind {
            VmInterfaceKind::Func => "importlib.Func",
            VmInterfaceKind::Var => "importlib.Var",
        }
    }
    pub(crate) fn allocation_bytes(&self) -> usize {
        self.attributes
            .keys()
            .map(|name| {
                name.len()
                    + std::mem::size_of::<(String, VmValue)>()
                    + 3 * std::mem::size_of::<usize>()
            })
            .sum()
    }
    fn field(&self, name: &str) -> Result<VmValue, VmExecutionError> {
        self.attributes.get(name).cloned().ok_or_else(|| {
            VmExecutionError::new(format!("{} has no attribute '{name}'", self.class_name()))
        })
    }
    pub(crate) fn safe_storage_type(&self, name: &str, value: &VmValue) -> bool {
        self.kind == VmInterfaceKind::Var && name == "type" && is_storage_class(value)
    }
}

pub(crate) fn is_storage_class(value: &VmValue) -> bool {
    matches!(value.snapshot(), VmValue::TypeMarker(name) if matches!(name.as_str(), "Variable" | "Hash" | "ForeignVariable" | "ForeignHash" | "LogEvent"))
}

fn prefixed_name(value: &VmValue) -> Result<VmValue, VmExecutionError> {
    let VmValue::String(name) = value.snapshot() else {
        return Err(VmExecutionError::new(
            "interface private name must be a string",
        ));
    };
    if name.len() > MAX_BINARY_ALLOCATION_BYTES - 2 {
        return Err(VmExecutionError::new(
            "interface name exceeds allocation limit",
        ));
    }
    Ok(VmValue::String(format!("__{name}")))
}

pub(super) fn construct(
    syscall: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Result<VmValue, VmExecutionError> {
    let name = args
        .first()
        .cloned()
        .ok_or_else(|| VmExecutionError::new("interface descriptor requires a name"))?;
    let (kind, attributes) = match syscall {
        "contract.interface.func" => {
            let private = kwargs
                .iter()
                .find(|(name, _)| name == "private")
                .is_some_and(|(_, value)| value.truthy());
            let name = if private { prefixed_name(&name)? } else { name };
            (
                VmInterfaceKind::Func,
                BTreeMap::from([
                    ("name".into(), name),
                    (
                        "args".into(),
                        args.get(1)
                            .cloned()
                            .unwrap_or_else(|| VmValue::Tuple(vec![])),
                    ),
                ]),
            )
        }
        "contract.interface.var" => {
            let name = prefixed_name(&name)?;
            let kind = args
                .get(1)
                .filter(|value| is_storage_class(value))
                .cloned()
                .ok_or_else(|| {
                    VmExecutionError::new("importlib.Var() requires a storage class descriptor")
                })?;
            (
                VmInterfaceKind::Var,
                BTreeMap::from([("name".into(), name), ("type".into(), kind)]),
            )
        }
        _ => {
            return Err(VmExecutionError::new(
                "unknown interface descriptor constructor",
            ))
        }
    };
    Ok(VmValue::InterfaceDescriptor(Box::new(
        VmInterfaceDescriptor { kind, attributes },
    )))
}

pub(super) fn attribute(
    receiver: &VmValue,
    name: &str,
) -> Option<Result<VmValue, VmExecutionError>> {
    let VmValue::InterfaceDescriptor(descriptor) = receiver.snapshot() else {
        return None;
    };
    if let Some(value) = descriptor.attributes.get(name) {
        return Some(Ok(value.clone()));
    }
    if name == "is_of" {
        return Some(Ok(VmValue::BoundMethod(Box::new(VmBoundMethod {
            receiver: receiver.clone(),
            method: name.into(),
        }))));
    }
    Some(Err(VmExecutionError::new(format!(
        "{} has no attribute '{name}'",
        descriptor.class_name()
    ))))
}

pub(super) fn write_attribute(
    receiver: VmValue,
    name: &str,
    value: VmValue,
) -> Result<(), VmExecutionError> {
    if matches!(receiver.snapshot(), VmValue::InterfaceSubject(_)) {
        return Err(VmExecutionError::new("InterfaceSubject is read-only"));
    }
    if name.starts_with('_') {
        return Err(VmExecutionError::new(
            "private attributes are not available to contracts",
        ));
    }
    let VmValue::Reference(reference) = receiver else {
        return Err(VmExecutionError::new(
            "attribute assignment requires an interface descriptor",
        ));
    };
    let VmValue::InterfaceDescriptor(mut descriptor) = reference.value() else {
        return Err(VmExecutionError::new(
            "attribute assignment requires an interface descriptor",
        ));
    };
    if descriptor.attributes.len() >= MAX_SEQUENCE_LENGTH
        && !descriptor.attributes.contains_key(name)
    {
        return Err(VmExecutionError::new("interface attribute limit exceeded"));
    }
    descriptor.attributes.insert(name.into(), value);
    reference.replace(VmValue::InterfaceDescriptor(descriptor))
}

fn function_name(function: &FunctionIr) -> String {
    if function.visibility == "export" {
        function.name.clone()
    } else {
        format!("__{}", function.name)
    }
}
fn positional_names(function: &FunctionIr) -> VmValue {
    VmValue::Tuple(
        function
            .parameters
            .iter()
            .filter(|parameter| {
                matches!(
                    parameter.kind.as_str(),
                    "positional_or_keyword" | "positional_only"
                )
            })
            .map(|parameter| VmValue::String(parameter.name.clone()))
            .collect(),
    )
}
fn matches_function(
    descriptor: &VmInterfaceDescriptor,
    function: &FunctionIr,
) -> Result<bool, VmExecutionError> {
    Ok(vm_values_equal(
        &descriptor.field("name")?,
        &VmValue::String(function_name(function)),
    )? && vm_values_equal(&descriptor.field("args")?, &positional_names(function))?)
}

impl VmInstance {
    pub fn interface_metadata_work(&self) -> u64 {
        let globals = self.globals.iter().fold(0u64, |work, (name, value)| {
            work.saturating_add(name.len() as u64 + 1)
                .saturating_add(self.interface_value_work(value))
        });
        let functions = self.functions.values().fold(0u64, |work, function| {
            function.parameters.iter().fold(
                work.saturating_add(function.name.len() as u64 + 1),
                |work, parameter| work.saturating_add(parameter.name.len() as u64 + 1),
            )
        });
        let declarations = self
            .module
            .global_declarations
            .iter()
            .fold(0u64, |work, value| {
                work.saturating_add(
                    value
                        .get("name")
                        .and_then(Value::as_str)
                        .map_or(1, |name| name.len() as u64 + 1),
                )
            });
        let count = self
            .globals
            .len()
            .saturating_add(self.functions.len())
            .saturating_add(self.module.global_declarations.len())
            .saturating_add(1);
        globals
            .saturating_add(functions)
            .saturating_add(declarations)
            .saturating_add(1)
            .saturating_mul(count.ilog2() as u64 + 1)
    }

    fn interface_value_work(&self, value: &VmValue) -> u64 {
        if let VmValue::Reference(reference) = value {
            return reference.with_value(|value| self.interface_value_work(value));
        }
        if let VmValue::FunctionRef(name) = value {
            return self.functions.get(name).map_or(1, |function| {
                function
                    .parameters
                    .iter()
                    .fold(function.name.len() as u64 + 1, |cost, arg| {
                        cost.saturating_add(arg.name.len() as u64 + 1)
                    })
            });
        }
        host_introspection::metadata(value)
            .filter(|code| code.function)
            .map_or(0, |code| code.work())
    }

    pub fn interface_members(
        &self,
    ) -> Result<BTreeMap<String, VmInterfaceMember>, VmExecutionError> {
        let private = self.private_interface_bindings();
        let mut members = BTreeMap::new();
        for function in self.functions.values() {
            members.insert(function_name(function), function_member(function));
        }
        for (binding, value) in &self.globals {
            let member = self.classify_interface_value(value)?;
            let name = if private.contains(binding.as_str()) {
                format!("__{binding}")
            } else {
                binding.clone()
            };
            members.insert(name, member);
        }
        Ok(members)
    }

    fn private_interface_bindings(&self) -> HashSet<&str> {
        let mut private = self
            .functions
            .values()
            .filter(|function| function.visibility != "export")
            .map(|function| function.name.as_str())
            .collect::<HashSet<_>>();
        for declaration in &self.module.global_declarations {
            if matches!(
                declaration.get("node").and_then(Value::as_str),
                Some("storage_decl" | "event_decl")
            ) {
                if let Some(name) = declaration.get("name").and_then(Value::as_str) {
                    private.insert(name);
                }
            }
        }
        private
    }

    fn classify_interface_value(
        &self,
        value: &VmValue,
    ) -> Result<VmInterfaceMember, VmExecutionError> {
        if let Some(code) = host_introspection::metadata(value).filter(|code| code.function) {
            return Ok(code.member());
        }
        self.classify_native_member(value)
    }
    fn classify_native_member(
        &self,
        value: &VmValue,
    ) -> Result<VmInterfaceMember, VmExecutionError> {
        match value {
            VmValue::Reference(reference) => {
                reference.with_value(|value| self.classify_interface_value(value))
            }
            VmValue::None => Ok(VmInterfaceMember::Missing),
            VmValue::FunctionRef(name) => self
                .functions
                .get(name)
                .map(function_member)
                .ok_or_else(|| VmExecutionError::new("unknown interface function")),
            VmValue::BoundMethod(bound) => Ok(bound_member(bound)),
            VmValue::StorageRef(storage) => {
                Ok(VmInterfaceMember::Datum(storage.storage_type.clone()))
            }
            VmValue::ForeignStorageRef(storage) => Ok(VmInterfaceMember::Datum(
                foreign_class(storage.is_hash).into(),
            )),
            VmValue::EventRef(_) => Ok(VmInterfaceMember::Datum("LogEvent".into())),
            _ => Ok(VmInterfaceMember::Other),
        }
    }

    fn resolve_interface_member(
        &self,
        contract: &str,
        name: &str,
        host: &mut dyn VmHost,
    ) -> Result<VmInterfaceMember, VmExecutionError> {
        let mut contract = contract.to_owned();
        let mut name = name.to_owned();
        for _ in 0..128 {
            let member = if contract == self.module.module_name {
                host.charge_execution_cost(self.interface_metadata_work())?;
                self.interface_members()?
                    .remove(&name)
                    .unwrap_or(VmInterfaceMember::Missing)
            } else {
                host.interface_member(&contract, &name, self.context.clone())?
            };
            match member {
                VmInterfaceMember::FunctionReference {
                    contract: target,
                    name: target_name,
                } => {
                    contract = target;
                    name = target_name;
                }
                other => return Ok(other),
            }
        }
        Err(VmExecutionError::new(
            "interface function reference depth limit exceeded",
        ))
    }

    pub(super) fn write_interface_attribute(
        &mut self,
        receiver: VmValue,
        name: &str,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        write_attribute(receiver, name, self.heap.capture(value)?)
    }

    pub(super) fn call_interface_class_method(
        &mut self,
        class: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let kind = if class == "importlib.Func" {
            VmInterfaceKind::Func
        } else {
            VmInterfaceKind::Var
        };
        let parameter = if kind == VmInterfaceKind::Func {
            "f"
        } else {
            "v"
        };
        let [receiver, value] = bind_unbound_is_of(args, kwargs, parameter)?;
        let VmValue::InterfaceDescriptor(mut descriptor) = receiver.snapshot() else {
            return Err(VmExecutionError::new(
                "is_of self requires an interface descriptor",
            ));
        };
        // The class selects the function body, even when self has the other descriptor kind.
        descriptor.kind = kind;
        let result = if let VmValue::InterfaceSubject(subject) = value.snapshot() {
            host.charge_execution_cost(subject.matching_work())?;
            subject_matches(&descriptor, &subject)?
        } else if kind == VmInterfaceKind::Func {
            self.func_is_of(&descriptor, &value, host)?
        } else {
            type_checks::isinstance(&value, &descriptor.field("type")?)?
        };
        Ok(VmValue::Bool(result))
    }

    pub(super) fn call_interface_method(
        &mut self,
        receiver: &VmValue,
        method: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if method != "is_of" {
            return Err(VmExecutionError::new("unknown interface descriptor method"));
        }
        let VmValue::InterfaceDescriptor(descriptor) = receiver.snapshot() else {
            return Err(VmExecutionError::new("expected interface descriptor"));
        };
        let parameter = if descriptor.kind == VmInterfaceKind::Func {
            "f"
        } else {
            "v"
        };
        let value = bind_is_of_argument(args, kwargs, parameter)?;
        let result = if let VmValue::InterfaceSubject(subject) = value.snapshot() {
            host.charge_execution_cost(subject.matching_work())?;
            subject_matches(&descriptor, &subject)?
        } else {
            match descriptor.kind {
                VmInterfaceKind::Var => {
                    type_checks::isinstance(&value, &descriptor.field("type")?)?
                }
                VmInterfaceKind::Func => self.func_is_of(&descriptor, &value, host)?,
            }
        };
        Ok(VmValue::Bool(result))
    }

    fn func_is_of(
        &mut self,
        descriptor: &VmInterfaceDescriptor,
        value: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<bool, VmExecutionError> {
        if let Some(code) = host_introspection::metadata(value) {
            host.charge_execution_cost(code.work())?;
            return matches_member(descriptor, &code.member());
        }
        match value.snapshot() {
            VmValue::FunctionRef(name) => {
                let function = self
                    .functions
                    .get(&name)
                    .ok_or_else(|| VmExecutionError::new("unknown function"))?;
                matches_function(descriptor, function)
            }
            VmValue::BoundMethod(bound) => self.func_is_of_bound(descriptor, &bound, host),
            _ => Err(VmExecutionError::new(
                "Func.is_of expects a function with Python code metadata",
            )),
        }
    }
    fn func_is_of_bound(
        &mut self,
        descriptor: &VmInterfaceDescriptor,
        bound: &VmBoundMethod,
        host: &mut dyn VmHost,
    ) -> Result<bool, VmExecutionError> {
        if let VmValue::InterfaceDescriptor(target) = bound.receiver.snapshot() {
            return matches_descriptor_method(descriptor, &target, &bound.method);
        }
        let VmValue::ContractHandle(handle) = bound.receiver.snapshot() else {
            return Err(VmExecutionError::new(
                "Func.is_of expects a function with Python code metadata",
            ));
        };
        matches_member(
            descriptor,
            &self.resolve_interface_member(&handle.module, &bound.method, host)?,
        )
    }

    pub(super) fn enforce_interface(
        &mut self,
        args: Vec<VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if args.len() != 2 {
            return Err(VmExecutionError::new(
                "enforce_interface() expects two arguments",
            ));
        }
        let contract = interface_contract_name(&args[0])?;
        let iterator = crate::iteration::iter(&args[1], &self.heap)?;
        let mut count = 0;
        while let Some(item) = self.next_item(&iterator, host)? {
            count += 1;
            if count > MAX_SEQUENCE_LENGTH {
                return Err(VmExecutionError::new("interface iteration limit exceeded"));
            }
            host.charge_execution_cost(1)?;
            let VmValue::InterfaceDescriptor(descriptor) = item.snapshot() else {
                return Err(VmExecutionError::new(
                    "interface entries must be Func or Var descriptors",
                ));
            };
            if !self.enforce_descriptor(&descriptor, &contract, host)? {
                return Ok(VmValue::Bool(false));
            }
        }
        Ok(VmValue::Bool(true))
    }

    fn enforce_descriptor(
        &mut self,
        descriptor: &VmInterfaceDescriptor,
        contract: &str,
        host: &mut dyn VmHost,
    ) -> Result<bool, VmExecutionError> {
        let name = descriptor.field("name")?;
        dict_get(&[], &name)?;
        let VmValue::String(name) = name.snapshot() else {
            return Ok(false);
        };
        let member = self.resolve_interface_member(contract, &name, host)?;
        // Missing/None and ordinary data never inspect an override.
        if matches!(
            member,
            VmInterfaceMember::Missing | VmInterfaceMember::Other
        ) {
            return matches_member(descriptor, &member);
        }
        if let Some(callback) = descriptor.attributes.get("is_of") {
            let subject = self.interface_subject(&name, member, host)?;
            return Ok(self
                .call_interface_predicate(callback.clone(), subject, host)?
                .truthy());
        }
        matches_member(descriptor, &member)
    }
}

pub(super) fn descriptor_class(value: &VmValue) -> Option<&str> {
    match value {
        VmValue::TypeMarker(name) | VmValue::Builtin(name)
            if matches!(name.as_str(), "importlib.Func" | "importlib.Var") =>
        {
            Some(name)
        }
        _ => None,
    }
}

fn bind_unbound_is_of(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
    parameter: &str,
) -> Result<[VmValue; 2], VmExecutionError> {
    if args.len() > 2 {
        return Err(VmExecutionError::new(
            "is_of() expects self and one argument",
        ));
    }
    let mut values = [None, None];
    for (slot, value) in values.iter_mut().zip(args) {
        *slot = Some(value);
    }
    for (name, value) in kwargs {
        let index = is_of_parameter_index(&name, parameter)?;
        if values[index].replace(value).is_some() {
            return Err(VmExecutionError::new(
                "is_of() multiple values for argument",
            ));
        }
    }
    let [receiver, value] = values;
    Ok([
        receiver.ok_or_else(|| VmExecutionError::new("is_of() missing self"))?,
        value.ok_or_else(|| VmExecutionError::new("is_of() missing argument"))?,
    ])
}

fn is_of_parameter_index(name: &str, parameter: &str) -> Result<usize, VmExecutionError> {
    match name {
        "self" => Ok(0),
        name if name == parameter => Ok(1),
        _ => Err(VmExecutionError::new("is_of() unexpected keyword argument")),
    }
}

fn bind_is_of_argument(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
    parameter: &str,
) -> Result<VmValue, VmExecutionError> {
    if args.len() > 1 || kwargs.len() > 1 || args.len() + kwargs.len() != 1 {
        return Err(VmExecutionError::new("is_of() expects one argument"));
    }
    if let Some((name, value)) = kwargs.into_iter().next() {
        if name != parameter {
            return Err(VmExecutionError::new("is_of() unexpected keyword argument"));
        }
        return Ok(value);
    }
    Ok(args.into_iter().next().unwrap())
}

fn interface_contract_name(value: &VmValue) -> Result<String, VmExecutionError> {
    match value.snapshot() {
        VmValue::String(name) => Ok(name),
        VmValue::ContractHandle(handle) => Ok(handle.module),
        _ => Err(VmExecutionError::new(
            "interface target must be a contract name or module",
        )),
    }
}

fn matches_descriptor_method(
    descriptor: &VmInterfaceDescriptor,
    target: &VmInterfaceDescriptor,
    method: &str,
) -> Result<bool, VmExecutionError> {
    let parameter = if target.kind == VmInterfaceKind::Func {
        "f"
    } else {
        "v"
    };
    let args = VmValue::Tuple(vec![
        VmValue::String("self".into()),
        VmValue::String(parameter.into()),
    ]);
    Ok(method == "is_of"
        && vm_values_equal(&descriptor.field("name")?, &VmValue::String("is_of".into()))?
        && vm_values_equal(&descriptor.field("args")?, &args)?)
}

fn foreign_class(is_hash: bool) -> &'static str {
    if is_hash {
        "ForeignHash"
    } else {
        "ForeignVariable"
    }
}

fn function_member(function: &FunctionIr) -> VmInterfaceMember {
    VmInterfaceMember::Function {
        name: function_name(function),
        args: function
            .parameters
            .iter()
            .filter(|parameter| {
                matches!(
                    parameter.kind.as_str(),
                    "positional_or_keyword" | "positional_only"
                )
            })
            .map(|parameter| parameter.name.clone())
            .collect(),
    }
}
fn bound_member(bound: &VmBoundMethod) -> VmInterfaceMember {
    fn receiver_member(receiver: &VmValue, method: &str) -> VmInterfaceMember {
        match receiver {
            VmValue::Reference(reference) => {
                reference.with_value(|value| receiver_member(value, method))
            }
            VmValue::ContractHandle(handle) => VmInterfaceMember::FunctionReference {
                contract: handle.module.clone(),
                name: method.into(),
            },
            _ => VmInterfaceMember::Other,
        }
    }
    receiver_member(&bound.receiver, &bound.method)
}
fn datum_value(class: &str) -> VmValue {
    if class == "LogEvent" {
        VmValue::EventRef(Box::new(VmEventDefinition {
            binding: String::new(),
            event_name: String::new(),
            params: VmValue::Dict(vec![]),
        }))
    } else {
        VmValue::StorageRef(VmStorageRef {
            binding: String::new(),
            storage_type: class.into(),
        })
    }
}
fn subject_matches(
    descriptor: &VmInterfaceDescriptor,
    subject: &VmInterfaceSubject,
) -> Result<bool, VmExecutionError> {
    if descriptor.kind != subject.kind {
        return Ok(false);
    }
    match subject.kind {
        VmInterfaceKind::Func => {
            Ok(vm_values_equal(
                &descriptor.field("name")?,
                &VmValue::String(subject.name.clone()),
            )? && vm_values_equal(&descriptor.field("args")?, &subject.args)?)
        }
        VmInterfaceKind::Var => matches_datum(
            descriptor,
            subject
                .storage_type
                .as_deref()
                .ok_or_else(|| VmExecutionError::new("storage subject has no family"))?,
        ),
    }
}

fn matches_member(
    descriptor: &VmInterfaceDescriptor,
    member: &VmInterfaceMember,
) -> Result<bool, VmExecutionError> {
    match member {
        VmInterfaceMember::Missing => Ok(false),
        VmInterfaceMember::Other => Ok(true),
        VmInterfaceMember::Datum(class) => matches_datum(descriptor, class),
        VmInterfaceMember::Function { name, args } => {
            matches_function_member(descriptor, name, args)
        }
        VmInterfaceMember::FunctionReference { .. } => Err(VmExecutionError::new(
            "unresolved interface function reference",
        )),
    }
}
fn matches_datum(
    descriptor: &VmInterfaceDescriptor,
    class: &str,
) -> Result<bool, VmExecutionError> {
    if descriptor.kind != VmInterfaceKind::Var {
        return Err(VmExecutionError::new(
            "Func.is_of expects a function with Python code metadata",
        ));
    }
    type_checks::isinstance(&datum_value(class), &descriptor.field("type")?)
}
fn matches_function_member(
    descriptor: &VmInterfaceDescriptor,
    name: &str,
    args: &[String],
) -> Result<bool, VmExecutionError> {
    if descriptor.kind == VmInterfaceKind::Var {
        return type_checks::isinstance(
            &VmValue::FunctionRef(name.into()),
            &descriptor.field("type")?,
        );
    }
    let args = VmValue::Tuple(args.iter().cloned().map(VmValue::String).collect());
    Ok(
        vm_values_equal(&descriptor.field("name")?, &VmValue::String(name.into()))?
            && vm_values_equal(&descriptor.field("args")?, &args)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn func(args: VmValue) -> VmValue {
        construct(
            "contract.interface.func",
            &[VmValue::String("probe".into()), args],
            &[],
        )
        .unwrap()
    }
    fn var() -> VmValue {
        construct(
            "contract.interface.var",
            &[
                VmValue::String("balance".into()),
                VmValue::TypeMarker("Variable".into()),
            ],
            &[],
        )
        .unwrap()
    }
    fn instance() -> VmInstance {
        let module = ModuleIr {
            ir_version: crate::XIAN_IR_V1.into(),
            vm_profile: crate::XIAN_VM_V1_PROFILE.into(),
            host_catalog_version: crate::XIAN_VM_HOST_CATALOG_V1.into(),
            module_name: "con_descriptors".into(),
            source_hash: "0".repeat(64),
            docstring: None,
            imports: vec![],
            global_declarations: vec![],
            functions: vec![],
            module_body: vec![],
            host_dependencies: vec![],
        };
        VmInstance::new(module, VmExecutionContext::default()).unwrap()
    }
    fn empty_tuple() -> VmValue {
        VmValue::Tuple(vec![])
    }

    #[test]
    fn descriptor_constructor_preserves_args_identity_and_truthy_private_name() {
        let heap = crate::heap::VmHeap::default();
        let args = heap.capture(VmValue::List(vec![])).unwrap();
        let descriptor = heap.capture(func(args.clone())).unwrap();
        assert!(attribute(&descriptor, "args")
            .unwrap()
            .unwrap()
            .identical(&args));
        assert!(attribute(&descriptor, "private").unwrap().is_err());
        let private = construct(
            "contract.interface.func",
            &[VmValue::String("probe".into())],
            &[("private".into(), VmValue::String("yes".into()))],
        )
        .unwrap();
        assert_eq!(
            attribute(&private, "name").unwrap().unwrap(),
            VmValue::String("__probe".into())
        );
        let invalid = construct(
            "contract.interface.var",
            &[
                VmValue::Int(1.into()),
                VmValue::TypeMarker("Variable".into()),
            ],
            &[],
        );
        assert!(invalid.is_err());
        assert!(construct(
            "contract.interface.var",
            &[
                VmValue::String("x".into()),
                VmValue::String("Variable".into())
            ],
            &[]
        )
        .is_err());
    }

    #[test]
    fn descriptor_identity_keys_and_mutation_are_shared() {
        let heap = crate::heap::VmHeap::default();
        let first = heap.capture(func(empty_tuple())).unwrap();
        let second = heap.capture(func(empty_tuple())).unwrap();
        assert!(vm_values_equal(&first, &first).unwrap());
        assert!(!vm_values_equal(&first, &second).unwrap());
        let mut entries = vec![];
        dict_set(&mut entries, first.clone(), vm_int(1)).unwrap();
        dict_set(&mut entries, second.clone(), vm_int(2)).unwrap();
        write_attribute(first.clone(), "name", VmValue::String("changed".into())).unwrap();
        assert_eq!(dict_get(&entries, &first).unwrap(), Some(vm_int(1)));
        assert_eq!(entries.len(), 2);
        write_attribute(first.clone(), "loop", first.clone()).unwrap();
        assert!(attribute(&first, "loop")
            .unwrap()
            .unwrap()
            .identical(&first));
        assert!(write_attribute(first, "_private", vm_int(0)).is_err());
    }

    #[test]
    fn descriptor_graph_boundaries_allow_only_inert_var_type_metadata() {
        let heap = crate::heap::VmHeap::default();
        let descriptor = heap.capture(var()).unwrap();
        assert!(crate::heap::validate_contract_values([&descriptor].into_iter()).is_ok());
        assert!(descriptor.external_value().is_err());
        write_attribute(descriptor.clone(), "loop", descriptor.clone()).unwrap();
        assert!(crate::heap::validate_contract_values([&descriptor].into_iter()).is_ok());
        write_attribute(descriptor.clone(), "extra", VmValue::Builtin("abs".into())).unwrap();
        assert!(crate::heap::validate_contract_values([&descriptor].into_iter()).is_err());
        write_attribute(descriptor.clone(), "extra", VmValue::None).unwrap();
        write_attribute(descriptor.clone(), "type", VmValue::Builtin("int".into())).unwrap();
        assert!(crate::heap::validate_contract_values([&descriptor].into_iter()).is_err());
    }

    #[test]
    fn descriptor_raw_syscalls_share_constructor_binding_and_reject_forged_dicts() {
        let mut vm = instance();
        for syscall in [
            "contract.interface.func",
            "contract.interface.var",
            "contract.enforce_interface",
        ] {
            assert!(vm
                .dispatch_host_syscall(syscall, vec![], vec![], &mut NoopHost {})
                .is_err());
        }
        assert!(vm
            .dispatch_host_syscall(
                "contract.interface.func",
                vec![VmValue::String("x".into())],
                vec![("unknown".into(), VmValue::None)],
                &mut NoopHost {}
            )
            .is_err());
        let actual = vm
            .dispatch_host_syscall(
                "contract.interface.func",
                vec![VmValue::String("x".into())],
                vec![],
                &mut NoopHost {},
            )
            .unwrap();
        assert!(matches!(actual, VmValue::InterfaceDescriptor(_)));
        let forged = VmValue::Dict(vec![(
            VmValue::String("__vm_interface__".into()),
            VmValue::String("func".into()),
        )]);
        let result = vm.dispatch_host_syscall(
            "contract.enforce_interface",
            vec![
                VmValue::String("con_descriptors".into()),
                VmValue::List(vec![forged]),
            ],
            vec![],
            &mut NoopHost {},
        );
        assert!(result.unwrap_err().to_string().contains("Func or Var"));
    }

    #[test]
    fn descriptor_function_matching_preserves_tuple_kind_and_classinfo() {
        let mut vm = instance();
        let function = FunctionIr {
            node: "function".into(),
            span: crate::Span {
                line: 1,
                col: 0,
                end_line: 1,
                end_col: 1,
            },
            name: "probe".into(),
            visibility: "export".into(),
            decorator: None,
            docstring: None,
            parameters: vec![],
            returns: None,
            body: vec![],
        };
        vm.define_function(function, &mut NoopHost {}).unwrap();
        let tuple = func(empty_tuple());
        let list = func(VmValue::List(vec![]));
        assert_eq!(
            vm.call_interface_method(
                &tuple,
                "is_of",
                vec![VmValue::FunctionRef("probe".into())],
                vec![],
                &mut NoopHost {}
            )
            .unwrap(),
            VmValue::Bool(true)
        );
        assert_eq!(
            vm.call_interface_method(
                &list,
                "is_of",
                vec![VmValue::FunctionRef("probe".into())],
                vec![],
                &mut NoopHost {}
            )
            .unwrap(),
            VmValue::Bool(false)
        );
        let class = VmHostCallable::named("importlib.Func").unwrap().value();
        assert!(type_checks::isinstance(&tuple, &class).unwrap());
        assert!(!type_checks::isinstance(&VmValue::Dict(vec![]), &class).unwrap());
        assert!(vm
            .call_expression_callable_value(
                &mut NoopHost {},
                VmValue::TypeMarker("Variable".into()),
                vec![],
                vec![]
            )
            .is_err());
    }
    fn metadata_module() -> ModuleIr {
        let mut module = instance().module;
        let function = FunctionIr {
            node: "function".into(),
            span: crate::Span {
                line: 1,
                col: 0,
                end_line: 1,
                end_col: 1,
            },
            name: "probe".into(),
            visibility: "export".into(),
            decorator: None,
            docstring: None,
            parameters: vec![],
            returns: None,
            body: vec![],
        };
        module.functions.push(function.clone());
        module.functions.push(FunctionIr {
            name: "hidden".into(),
            visibility: "private".into(),
            ..function
        });
        module.global_declarations = vec![
            serde_json::json!({"node":"storage_decl","name":"balance","storage_type":"Variable"}),
            serde_json::json!({"node":"event_decl","name":"event"}),
            serde_json::json!({"node":"value_decl","name":"constant"}),
        ];
        module
    }
    fn metadata_instance() -> VmInstance {
        let mut vm = instance();
        let module = metadata_module();
        for function in &module.functions {
            vm.define_function(function.clone(), &mut NoopHost {})
                .unwrap();
        }
        vm.globals.insert(
            "balance".into(),
            VmValue::StorageRef(VmStorageRef {
                binding: "balance".into(),
                storage_type: "Variable".into(),
            }),
        );
        vm.globals.insert("event".into(), datum_value("LogEvent"));
        vm.globals.insert("constant".into(), vm_int(7));
        vm.module = module;
        vm
    }
    fn interface_matches(items: &[VmValue], _module: &ModuleIr) -> Result<bool, VmExecutionError> {
        let value = metadata_instance().enforce_interface(
            vec![
                VmValue::String("con_descriptors".into()),
                VmValue::List(items.to_vec()),
            ],
            &mut NoopHost {},
        )?;
        Ok(value == VmValue::Bool(true))
    }
    fn descriptor_matches_module(
        descriptor: &VmInterfaceDescriptor,
        _module: &ModuleIr,
    ) -> Result<bool, VmExecutionError> {
        metadata_instance().enforce_descriptor(descriptor, "con_descriptors", &mut NoopHost {})
    }
    fn descriptor(value: VmValue) -> Box<VmInterfaceDescriptor> {
        let VmValue::InterfaceDescriptor(value) = value else {
            panic!("expected descriptor")
        };
        value
    }

    #[test]
    fn descriptor_interface_matching_uses_current_fields_and_real_member_kind() {
        let module = metadata_module();
        assert!(interface_matches(&[], &module).unwrap());
        assert!(interface_matches(&[func(empty_tuple()), var()], &module).unwrap());
        assert!(!interface_matches(&[func(VmValue::List(vec![]))], &module).unwrap());
        let private = construct(
            "contract.interface.func",
            &[VmValue::String("hidden".into())],
            &[("private".into(), VmValue::Bool(true))],
        )
        .unwrap();
        assert!(interface_matches(&[private], &module).unwrap());
        let mut changed = descriptor(func(empty_tuple()));
        changed
            .attributes
            .insert("name".into(), VmValue::String("missing".into()));
        assert!(!descriptor_matches_module(&changed, &module).unwrap());
        changed
            .attributes
            .insert("name".into(), VmValue::String("constant".into()));
        assert!(descriptor_matches_module(&changed, &module).unwrap());
        changed
            .attributes
            .insert("name".into(), VmValue::Int(7.into()));
        assert!(!descriptor_matches_module(&changed, &module).unwrap());
        changed
            .attributes
            .insert("name".into(), VmValue::List(vec![]));
        assert!(descriptor_matches_module(&changed, &module).is_err());
        changed
            .attributes
            .insert("name".into(), VmValue::String("__balance".into()));
        assert!(descriptor_matches_module(&changed, &module).is_err());
        let event = construct(
            "contract.interface.var",
            &[
                VmValue::String("event".into()),
                VmValue::TypeMarker("LogEvent".into()),
            ],
            &[],
        )
        .unwrap();
        assert!(interface_matches(&[event], &module).unwrap());
        let mut variable = descriptor(var());
        variable
            .attributes
            .insert("type".into(), VmValue::TypeMarker("Hash".into()));
        assert!(!descriptor_matches_module(&variable, &module).unwrap());
        variable
            .attributes
            .insert("name".into(), VmValue::String("probe".into()));
        assert!(!descriptor_matches_module(&variable, &module).unwrap());
    }

    #[test]
    fn descriptor_method_binding_and_bound_function_metadata_are_exact() {
        for parameter in ["f", "v"] {
            assert_eq!(
                bind_is_of_argument(vec![], vec![(parameter.into(), vm_int(3))], parameter)
                    .unwrap(),
                vm_int(3)
            );
            assert!(
                bind_is_of_argument(vec![], vec![("wrong".into(), vm_int(3))], parameter).is_err()
            );
            assert!(bind_is_of_argument(
                vec![vm_int(1)],
                vec![(parameter.into(), vm_int(3))],
                parameter
            )
            .is_err());
            assert!(bind_is_of_argument(vec![], vec![], parameter).is_err());
            assert!(bind_is_of_argument(vec![vm_int(1), vm_int(2)], vec![], parameter).is_err());
        }
        let target = descriptor(func(empty_tuple()));
        let mut matcher = descriptor(
            construct(
                "contract.interface.func",
                &[
                    VmValue::String("is_of".into()),
                    VmValue::Tuple(vec![
                        VmValue::String("self".into()),
                        VmValue::String("f".into()),
                    ]),
                ],
                &[],
            )
            .unwrap(),
        );
        assert!(matches_descriptor_method(&matcher, &target, "is_of").unwrap());
        assert!(!matches_descriptor_method(&matcher, &target, "other").unwrap());
        assert!(!matches_descriptor_method(&matcher, &descriptor(var()), "is_of").unwrap());
        matcher
            .attributes
            .insert("name".into(), VmValue::String("wrong".into()));
        assert!(!matches_descriptor_method(&matcher, &target, "is_of").unwrap());
    }

    struct MetadataHost {
        module: ModuleIr,
        costs: Vec<u64>,
        budget: u64,
    }
    impl VmHost for MetadataHost {
        fn interface_member(
            &mut self,
            contract: &str,
            name: &str,
            _context: VmExecutionContext,
        ) -> Result<VmInterfaceMember, VmExecutionError> {
            assert_eq!(contract, "con_remote");
            let mut vm = metadata_instance();
            vm.module = self.module.clone();
            let member = vm
                .interface_members()?
                .remove(name)
                .unwrap_or(VmInterfaceMember::Missing);
            self.charge_execution_cost(member.inspection_work())?;
            Ok(member)
        }
        fn charge_execution_cost(&mut self, amount: u64) -> Result<(), VmExecutionError> {
            self.costs.push(amount);
            if amount > self.budget {
                return Err(VmExecutionError::new("descriptor test budget exceeded"));
            }
            self.budget -= amount;
            Ok(())
        }
    }

    #[test]
    fn descriptor_remote_metadata_and_enforcement_work_are_metered_before_scan() {
        let mut vm = instance();
        let mut host = MetadataHost {
            module: metadata_module(),
            costs: vec![],
            budget: 100_000,
        };
        let bound = VmValue::BoundMethod(Box::new(VmBoundMethod {
            receiver: VmValue::ContractHandle(VmContractHandle {
                module: "con_remote".into(),
                origin: "dynamic_import".into(),
            }),
            method: "probe".into(),
        }));
        assert_eq!(
            vm.call_interface_method(
                &func(empty_tuple()),
                "is_of",
                vec![bound],
                vec![],
                &mut host
            )
            .unwrap(),
            VmValue::Bool(true)
        );
        assert_eq!(
            vm.enforce_interface(
                vec![
                    VmValue::String("con_remote".into()),
                    VmValue::List(vec![func(empty_tuple())])
                ],
                &mut host
            )
            .unwrap(),
            VmValue::Bool(true)
        );
        assert_eq!(host.costs, vec![6, 1, 6]);
        host.budget = 0;
        assert!(vm
            .enforce_interface(
                vec![
                    VmValue::String("con_descriptors".into()),
                    VmValue::List(vec![func(empty_tuple())])
                ],
                &mut host
            )
            .unwrap_err()
            .to_string()
            .contains("budget exceeded"));
    }

    #[test]
    fn descriptor_prefix_allocation_limit_and_attribute_read_work_are_explicit() {
        assert_eq!(
            prefixed_name(&VmValue::String("x".repeat(131_070)))
                .unwrap()
                .as_string()
                .unwrap()
                .len(),
            131_072
        );
        assert!(prefixed_name(&VmValue::String("x".repeat(131_071))).is_err());
        let mut vm = instance();
        let value = vm.heap.capture(func(empty_tuple())).unwrap();
        let mut scope = HashMap::from([("value".into(), value)]);
        let target = serde_json::json!({"node":"attribute","value":{"node":"name","id":"value"},"attr":"name"});
        let mut host = MetadataHost {
            module: metadata_module(),
            costs: vec![],
            budget: 100_000,
        };
        let (_, current) = vm
            .resolve_assignment_target(&target, &mut scope, &mut host, true)
            .unwrap();
        assert_eq!(current.unwrap().snapshot(), VmValue::String("probe".into()));
        assert_eq!(host.costs, vec![96, 64]);
        assert!(!type_checks::isinstance(
            &VmValue::StorageRef(VmStorageRef {
                binding: "foreign".into(),
                storage_type: "ForeignVariable".into()
            }),
            &VmValue::TypeMarker("Variable".into())
        )
        .unwrap());
    }

    #[test]
    fn descriptor_live_member_map_preserves_none_and_actual_global_overrides() {
        let mut vm = metadata_instance();
        assert!(matches!(
            vm.interface_members().unwrap()["constant"],
            VmInterfaceMember::Other
        ));
        vm.globals.insert("constant".into(), VmValue::None);
        vm.globals.insert("probe".into(), VmValue::None);
        let members = vm.interface_members().unwrap();
        assert_eq!(members["constant"], VmInterfaceMember::Missing);
        assert_eq!(members["probe"], VmInterfaceMember::Missing);
        vm.globals
            .insert("alias".into(), VmValue::FunctionRef("hidden".into()));
        assert_eq!(
            vm.interface_members().unwrap()["alias"],
            VmInterfaceMember::Function {
                name: "__hidden".into(),
                args: vec![]
            }
        );
    }
    #[test]
    fn descriptor_host_metadata_checks_names_arguments_and_budget() {
        let mut vm = instance();
        let mut host = MetadataHost {
            module: metadata_module(),
            costs: vec![],
            budget: 100_000,
        };
        let matcher = descriptor(
            construct(
                "contract.interface.func",
                &[
                    VmValue::String("sha3_text".into()),
                    VmValue::Tuple(vec![VmValue::String("value".into())]),
                ],
                &[],
            )
            .unwrap(),
        );
        let function = VmHostCallable::named("hashlib.sha3_text").unwrap().value();
        assert!(vm.func_is_of(&matcher, &function, &mut host).unwrap());
        let mut wrong = matcher.clone();
        wrong.attributes.insert(
            "args".into(),
            VmValue::List(vec![VmValue::String("value".into())]),
        );
        assert!(!vm.func_is_of(&wrong, &function, &mut host).unwrap());
        wrong = matcher.clone();
        wrong
            .attributes
            .insert("name".into(), VmValue::String("hashlib.sha3_text".into()));
        assert!(!vm.func_is_of(&wrong, &function, &mut host).unwrap());
        host.budget = 0;
        assert!(vm
            .func_is_of(&matcher, &function, &mut host)
            .unwrap_err()
            .to_string()
            .contains("budget"));
        vm.globals.insert("alias".into(), function);
        assert_eq!(
            vm.interface_members().unwrap()["alias"],
            VmInterfaceMember::Function {
                name: "sha3_text".into(),
                args: vec!["value".into()]
            }
        );
        vm.globals.insert(
            "alias".into(),
            VmHostCallable::named("Contract.get_info").unwrap().value(),
        );
        assert_eq!(
            vm.interface_members().unwrap()["alias"],
            VmInterfaceMember::Other
        );
    }

    #[test]
    fn descriptor_bound_and_unbound_keywords_select_the_declared_function_body() {
        let mut vm = metadata_instance();
        let mut host = MetadataHost {
            module: metadata_module(),
            costs: vec![],
            budget: 100_000,
        };
        let f = func(empty_tuple());
        let v = var();
        let target = VmValue::FunctionRef("probe".into());
        assert_eq!(
            vm.call_interface_class_method(
                "importlib.Func",
                vec![f.clone(), target.clone()],
                vec![],
                &mut host
            )
            .unwrap(),
            VmValue::Bool(true)
        );

        assert_eq!(
            vm.call_interface_method(
                &f,
                "is_of",
                vec![],
                vec![("f".into(), target.clone())],
                &mut host
            )
            .unwrap(),
            VmValue::Bool(true)
        );
        assert!(vm
            .call_interface_method(
                &f,
                "is_of",
                vec![],
                vec![("v".into(), target.clone())],
                &mut host
            )
            .is_err());
        assert_eq!(
            vm.call_interface_method(
                &v,
                "is_of",
                vec![],
                vec![("v".into(), datum_value("Variable"))],
                &mut host
            )
            .unwrap(),
            VmValue::Bool(true)
        );
        assert!(vm
            .call_interface_method(
                &v,
                "is_of",
                vec![],
                vec![("f".into(), target.clone())],
                &mut host
            )
            .is_err());
        assert_eq!(
            vm.call_interface_class_method(
                "importlib.Func",
                vec![],
                vec![("self".into(), f.clone()), ("f".into(), target.clone())],
                &mut host
            )
            .unwrap(),
            VmValue::Bool(true)
        );
        let mut wrong_self = descriptor(v);
        wrong_self
            .attributes
            .insert("name".into(), VmValue::String("probe".into()));
        assert!(vm
            .call_interface_class_method(
                "importlib.Func",
                vec![VmValue::InterfaceDescriptor(wrong_self), target.clone()],
                vec![],
                &mut host
            )
            .is_err());
        assert!(vm
            .call_interface_class_method(
                "importlib.Var",
                vec![f.clone(), datum_value("Variable")],
                vec![],
                &mut host
            )
            .is_err());
        for kwargs in [
            vec![("self".into(), f.clone())],
            vec![("wrong".into(), target.clone())],
        ] {
            assert!(vm
                .call_interface_class_method(
                    "importlib.Func",
                    vec![f.clone(), target.clone()],
                    kwargs,
                    &mut host
                )
                .is_err());
        }
    }

    #[test]
    fn descriptor_attribute_count_boundary_allows_replacement_only() {
        let mut value = descriptor(func(empty_tuple()));
        value.attributes = (0..131_072)
            .map(|index| (format!("a{index}"), VmValue::None))
            .collect();
        let heap = crate::heap::VmHeap::default();
        let value = heap.capture(VmValue::InterfaceDescriptor(value)).unwrap();
        write_attribute(value.clone(), "a0", vm_int(7)).unwrap();
        assert_eq!(
            attribute(&value, "a0").unwrap().unwrap().snapshot(),
            vm_int(7)
        );
        assert!(write_attribute(value, "new_field", VmValue::None)
            .unwrap_err()
            .to_string()
            .contains("attribute limit"));
    }

    struct RedirectHost {
        remaining: usize,
    }
    impl VmHost for RedirectHost {
        fn interface_member(
            &mut self,
            _contract: &str,
            _name: &str,
            _context: VmExecutionContext,
        ) -> Result<VmInterfaceMember, VmExecutionError> {
            if self.remaining == 0 {
                return Ok(VmInterfaceMember::Other);
            }
            self.remaining -= 1;
            Ok(VmInterfaceMember::FunctionReference {
                contract: "remote".into(),
                name: "next".into(),
            })
        }
    }
    #[test]
    fn descriptor_reference_depth_boundary_is_exact() {
        let vm = instance();
        assert_eq!(
            vm.resolve_interface_member("remote", "start", &mut RedirectHost { remaining: 127 })
                .unwrap(),
            VmInterfaceMember::Other
        );
        assert!(vm
            .resolve_interface_member("remote", "start", &mut RedirectHost { remaining: 128 })
            .unwrap_err()
            .to_string()
            .contains("depth limit"));
    }

    #[test]
    fn descriptor_unbound_wrapper_identity_inheritance_and_copy_are_preserved() {
        let mut vm = instance();
        let mut host = MetadataHost {
            module: metadata_module(),
            costs: vec![],
            budget: 100_000,
        };
        let set = VmValue::Builtin("set".into());
        let frozen = VmValue::Builtin("frozenset".into());
        let left = vm.read_attribute(set.clone(), "union", &mut host).unwrap();
        let right = vm
            .read_attribute(frozen.clone(), "union", &mut host)
            .unwrap();
        assert!(left.identical(&right));
        let value = vm
            .heap
            .capture(VmValue::FrozenSet(vec![vm_int(1)]))
            .unwrap();
        let result = vm
            .call_receiver(
                set.clone(),
                "union",
                vec![value.clone(), VmValue::List(vec![vm_int(2)])],
                vec![],
                &mut host,
            )
            .unwrap();
        assert!(matches!(result,VmValue::FrozenSet(ref items) if items.len()==2));
        let copied = vm
            .call_receiver(set, "copy", vec![value.clone()], vec![], &mut host)
            .unwrap();
        assert!(!copied.identical(&value));
        assert!(vm_values_equal(&copied, &value).unwrap());
        let arbitrary = vm.heap.capture(VmValue::List(vec![])).unwrap();
        let identity = vm
            .call_receiver(
                frozen,
                "copy",
                vec![],
                vec![("self".into(), arbitrary.clone())],
                &mut host,
            )
            .unwrap();
        assert!(identity.identical(&arbitrary));
        assert!(vm
            .call_receiver(
                VmValue::Builtin("set".into()),
                "add",
                vec![value, vm_int(2)],
                vec![],
                &mut host
            )
            .is_err());
        host.budget = 0;
        assert!(vm
            .call_receiver(
                VmValue::Builtin("set".into()),
                "copy",
                vec![VmValue::Set(vec![vm_int(1)])],
                vec![],
                &mut host
            )
            .unwrap_err()
            .to_string()
            .contains("budget"));
    }
    #[test]
    fn descriptor_metadata_pricing_vectors_cover_aliases_and_tree_boundaries() {
        // Independent gas-policy vectors: UTF-8 metadata bytes plus one unit
        // per name/entry, multiplied by the BTree insertion depth bucket.
        // Mutable global payload contents are deliberately not part of this fee.
        let mut vm = instance();
        assert_eq!(vm.interface_metadata_work(), 1);
        let mut function = metadata_module().functions.remove(0);
        function.parameters = ["a", "bb"]
            .into_iter()
            .map(|name| crate::ParameterIr {
                name: name.into(),
                kind: "positional_or_keyword".into(),
                annotation: None,
                default: None,
                span: function.span.clone(),
            })
            .collect();
        vm.functions.insert("probe".into(), function);
        assert_eq!(vm.interface_metadata_work(), 24);
        vm.globals
            .insert("a".into(), VmValue::FunctionRef("probe".into()));
        assert_eq!(vm.interface_metadata_work(), 50);
        vm.globals
            .insert("b".into(), VmValue::FunctionRef("probe".into()));
        assert_eq!(vm.interface_metadata_work(), 114);
        vm.globals.insert(
            "host".into(),
            VmHostCallable::named("hashlib.sha3_text").unwrap().value(),
        );
        assert_eq!(vm.interface_metadata_work(), 177);
        vm.globals.insert("plain".into(), VmValue::List(vec![]));
        assert_eq!(vm.interface_metadata_work(), 195);
        vm.globals
            .insert("plain".into(), VmValue::List(vec![VmValue::None; 10_000]));
        assert_eq!(vm.interface_metadata_work(), 195);
        vm.module
            .global_declarations
            .push(serde_json::json!({"name":"ledger"}));
        assert_eq!(vm.interface_metadata_work(), 216);
        // The raw IR accessor also accounts for nameless metadata entries.
        vm.module.global_declarations.push(serde_json::json!({}));
        assert_eq!(vm.interface_metadata_work(), 292);
        let mut host = MetadataHost {
            module: metadata_module(),
            costs: vec![],
            budget: 291,
        };
        assert!(vm
            .resolve_interface_member("con_descriptors", "probe", &mut host)
            .unwrap_err()
            .to_string()
            .contains("budget"));
        host.budget = 292;
        assert!(matches!(
            vm.resolve_interface_member("con_descriptors", "probe", &mut host)
                .unwrap(),
            VmInterfaceMember::Function { .. }
        ));
        vm.globals.insert(
            "missing_alias".into(),
            VmValue::FunctionRef("missing".into()),
        );
        assert_eq!(vm.interface_metadata_work(), 352);
        assert!(vm.interface_members().is_err());
    }

    #[test]
    fn descriptor_member_clone_and_host_code_pricing_vectors_are_explicit() {
        let vectors = [
            (
                VmInterfaceMember::Function {
                    name: "probe".into(),
                    args: vec!["amount".into(), "to".into()],
                },
                16,
            ),
            (
                VmInterfaceMember::FunctionReference {
                    contract: "con_remote".into(),
                    name: "probe".into(),
                },
                16,
            ),
            (VmInterfaceMember::Datum("Variable".into()), 9),
            (VmInterfaceMember::Missing, 1),
            (VmInterfaceMember::Other, 1),
        ];
        for (member, expected) in vectors {
            assert_eq!(member.inspection_work(), expected);
        }
        assert_eq!(
            host_introspection::named("hashlib.sha3_text")
                .unwrap()
                .work(),
            16
        );
        assert_eq!(host_introspection::named("set.add").unwrap().work(), 15);
    }

    #[test]
    fn descriptor_callback_order_skips_missing_and_plain_members() {
        let mut vm = metadata_instance();
        for (name, expected) in [("constant", true), ("missing", false)] {
            let mut interface = descriptor(func(empty_tuple()));
            interface
                .attributes
                .insert("name".into(), VmValue::String(name.into()));
            interface.attributes.insert("is_of".into(), vm_int(7));
            assert_eq!(
                vm.enforce_descriptor(&interface, "con_descriptors", &mut NoopHost {})
                    .unwrap(),
                expected
            );
        }
        let mut interface = descriptor(func(empty_tuple()));
        interface.attributes.insert("is_of".into(), vm_int(7));
        assert!(vm
            .enforce_descriptor(&interface, "con_descriptors", &mut NoopHost {})
            .unwrap_err()
            .to_string()
            .contains("not callable"));
        interface
            .attributes
            .insert("name".into(), VmValue::List(vec![]));
        assert!(vm
            .enforce_descriptor(&interface, "con_descriptors", &mut NoopHost {})
            .unwrap_err()
            .to_string()
            .contains("unhashable"));
    }
}
