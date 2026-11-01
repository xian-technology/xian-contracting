//! Public classinfo checks are ordered and stricter than storage type markers.
use crate::{VmExecutionError, VmValue};

type Result<T> = std::result::Result<T, VmExecutionError>;
const MAX_CLASSINFO_DEPTH: usize = 128;
const MAX_CLASSINFO_NODES: usize = 128 * 1024;

pub(in crate::interpreter) fn isinstance(value: &VmValue, target: &VmValue) -> Result<bool> {
    walk(target, 0, &mut 0, &mut |name| instance_of(value, name))
}

pub(super) fn issubclass(candidate: &VmValue, target: &VmValue) -> Result<bool> {
    // An empty target tuple returns false even for an invalid candidate. Validate
    // the candidate only when reaching a class, in the same order as Python.
    walk(target, 0, &mut 0, &mut |name| {
        let candidate = candidate_name(candidate)?;
        Ok(candidate == name || (candidate == "bool" && name == "int"))
    })
}

fn walk(
    target: &VmValue,
    depth: usize,
    nodes: &mut usize,
    check: &mut impl FnMut(&str) -> Result<bool>,
) -> Result<bool> {
    if let VmValue::Reference(reference) = target {
        return reference.with_value(|value| walk(value, depth, nodes, check));
    }
    *nodes += 1;
    if depth > MAX_CLASSINFO_DEPTH || *nodes > MAX_CLASSINFO_NODES {
        return Err(VmExecutionError::new("classinfo traversal limit exceeded"));
    }
    match target {
        VmValue::Tuple(targets) => {
            for target in targets {
                if walk(target, depth + 1, nodes, check)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => check(class_name(target).ok_or_else(|| {
            VmExecutionError::new("classinfo must be a class or tuple of classes")
        })?),
    }
}

fn candidate_name(value: &VmValue) -> Result<String> {
    if let VmValue::Reference(reference) = value {
        return reference.with_value(candidate_name);
    }
    class_name(value)
        .map(str::to_owned)
        .ok_or_else(|| VmExecutionError::new("issubclass() arg 1 must be a class"))
}

fn class_name(value: &VmValue) -> Option<&str> {
    let (VmValue::Builtin(name) | VmValue::TypeMarker(name)) = value else {
        return None;
    };
    // `range` is a guarded function in the Python environment, not a class.
    // Other callable builtins (abs, len, ...) are not class descriptors either.
    const CLASSES: &[&str] = &[
        "bool",
        "int",
        "float",
        "str",
        "bytes",
        "bytearray",
        "list",
        "dict",
        "tuple",
        "set",
        "frozenset",
        "Exception",
        "decimal",
        "datetime.datetime",
        "datetime.timedelta",
        "Any",
        "map",
        "filter",
        "zip",
        "reversed",
        "Variable",
        "Hash",
        "ForeignVariable",
        "ForeignHash",
        "LogEvent",
        "Contract",
        "importlib.Func",
        "importlib.Var",
    ];
    CLASSES.contains(&name.as_str()).then_some(name.as_str())
}

fn instance_of(value: &VmValue, name: &str) -> Result<bool> {
    if name == "Any" {
        return Err(VmExecutionError::new(
            "typing.Any cannot be used with isinstance()",
        ));
    }
    if let VmValue::Reference(reference) = value {
        return reference.with_value(|value| instance_of(value, name));
    }
    Ok(match value {
        VmValue::Iterator(iterator) => iterator.matches_public_class(name),
        VmValue::Exception(_) => name == "Exception",
        VmValue::DeploymentHandle => name == "Contract",
        VmValue::InterfaceDescriptor(descriptor) => descriptor.class_name() == name,
        VmValue::StorageRef(storage) => storage.storage_type == name,
        VmValue::ForeignStorageRef(storage) => {
            name == if storage.is_hash {
                "ForeignHash"
            } else {
                "ForeignVariable"
            }
        }
        VmValue::EventRef(_) => name == "LogEvent",
        _ => super::type_matches_name(value, name),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(name: &str) -> VmValue {
        VmValue::Builtin(name.to_owned())
    }

    #[test]
    fn classinfo_is_ordered_and_candidate_tuples_are_not_classes() {
        let number = VmValue::Int(1.into());
        let valid_first = VmValue::Tuple(vec![class("int"), class("abs")]);
        let invalid_first = VmValue::Tuple(vec![class("abs"), class("int")]);
        assert!(isinstance(&number, &valid_first).unwrap());
        assert!(isinstance(&number, &invalid_first).is_err());
        assert!(issubclass(&class("int"), &valid_first).unwrap());
        assert!(issubclass(&class("int"), &invalid_first).is_err());
        assert!(issubclass(&VmValue::Tuple(vec![class("int")]), &class("int")).is_err());
        assert!(!issubclass(&number, &VmValue::Tuple(vec![])).unwrap());
    }

    #[test]
    fn any_is_a_subclass_marker_but_not_an_instance_marker() {
        let any = VmValue::TypeMarker("Any".to_owned());
        assert!(isinstance(&VmValue::None, &any).is_err());
        assert!(issubclass(&any, &any).unwrap());
        assert!(!issubclass(&class("int"), &any).unwrap());
    }

    #[test]
    fn traversal_is_bounded_without_inspecting_short_circuited_branches() {
        let number = VmValue::Int(1.into());
        let mut nested = VmValue::Tuple(vec![]);
        for _ in 0..129 {
            nested = VmValue::Tuple(vec![nested]);
        }
        assert!(isinstance(&number, &nested).is_err());
        assert!(isinstance(&number, &VmValue::Tuple(vec![class("int"), nested])).unwrap());
        let broad = VmValue::Tuple(vec![class("str"); 131_072]);
        assert!(isinstance(&number, &broad).is_err());
    }

    #[test]
    fn scalar_and_capability_classes_have_exact_relationships() {
        use crate::{VmEventDefinition, VmException, VmForeignStorageRef, VmStorageRef};
        assert!(issubclass(&class("bool"), &class("int")).unwrap());
        assert!(!issubclass(&class("bool"), &class("str")).unwrap());
        assert!(!issubclass(&class("int"), &class("bool")).unwrap());
        let instances = [
            (
                VmValue::Exception(VmException {
                    name: "Exception".into(),
                    args: vec![],
                }),
                "Exception",
            ),
            (
                VmValue::StorageRef(VmStorageRef {
                    binding: "state".into(),
                    storage_type: "Variable".into(),
                }),
                "Variable",
            ),
            (
                VmValue::ForeignStorageRef(VmForeignStorageRef {
                    contract: "con_other".into(),
                    binding: "state".into(),
                    is_hash: false,
                }),
                "ForeignVariable",
            ),
            (
                VmValue::ForeignStorageRef(VmForeignStorageRef {
                    contract: "con_other".into(),
                    binding: "state".into(),
                    is_hash: true,
                }),
                "ForeignHash",
            ),
            (
                VmValue::EventRef(Box::new(VmEventDefinition {
                    binding: "event".into(),
                    event_name: "Seen".into(),
                    params: VmValue::Dict(vec![]),
                })),
                "LogEvent",
            ),
        ];
        for (instance, name) in instances {
            assert!(isinstance(&instance, &class(name)).unwrap());
            assert!(!isinstance(&instance, &class("int")).unwrap());
        }
    }

    #[test]
    fn exact_traversal_limits_are_accepted_for_both_public_checks() {
        let number = VmValue::Int(1.into());
        let mut nested = class("str");
        for _ in 0..128 {
            nested = VmValue::Tuple(vec![nested]);
        }
        let broad = VmValue::Tuple(vec![class("str"); 131_071]);
        for target in [nested, broad] {
            assert!(!isinstance(&number, &target).unwrap());
            assert!(!issubclass(&class("int"), &target).unwrap());
        }
    }
}
