//! Unbound ORM functions retain the receiver's family and read-only authority.
use super::*;

pub(super) fn class_method(receiver: &VmValue, method: &str) -> Option<&'static str> {
    if !resolves_to!(receiver, VmValue::Builtin(_) | VmValue::TypeMarker(_)) {
        return None;
    }
    let snapshot = receiver.snapshot();
    let (VmValue::Builtin(name) | VmValue::TypeMarker(name)) = snapshot else {
        return None;
    };
    match name.as_str() {
        "LogEvent" if method == "write_event" => Some("LogEvent"),
        "Variable" if method_signatures::storage_supports("Variable", method) => Some("Variable"),
        "ForeignVariable" if method_signatures::storage_supports("ForeignVariable", method) => {
            Some(if method == "set" {
                "ForeignVariable"
            } else {
                "Variable"
            })
        }
        "Hash" if method_signatures::storage_supports("Hash", method) => Some("Hash"),
        "ForeignHash" if method_signatures::storage_supports("ForeignHash", method) => {
            Some(if method == "all" {
                "Hash"
            } else {
                "ForeignHash"
            })
        }
        _ => None,
    }
}

fn receiver_matches(class: &str, receiver: &VmValue) -> bool {
    match receiver.snapshot() {
        VmValue::StorageRef(storage) => match class {
            "Variable" | "ForeignVariable" => matches!(
                storage.storage_type.as_str(),
                "Variable" | "ForeignVariable"
            ),
            "Hash" | "ForeignHash" => {
                matches!(storage.storage_type.as_str(), "Hash" | "ForeignHash")
            }
            _ => false,
        },
        VmValue::ForeignStorageRef(storage) => {
            storage.is_hash == matches!(class, "Hash" | "ForeignHash")
                && matches!(
                    class,
                    "Variable" | "ForeignVariable" | "Hash" | "ForeignHash"
                )
        }
        VmValue::EventRef(_) => class == "LogEvent",
        _ => false,
    }
}

impl VmInstance {
    pub(super) fn call_orm_class_method(
        &mut self,
        class: &str,
        method: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let (receiver, args, kwargs) = method_signatures::bind_wrapper_receiver(args, kwargs)?;
        if !receiver_matches(class, &receiver) {
            return Err(VmExecutionError::new(
                "ORM method received an incompatible receiver",
            ));
        }
        // Foreign overrides remain rejecting even when explicitly invoked on a
        // local receiver. Base methods still inspect the actual receiver below.
        if (class == "ForeignVariable" && method == "set")
            || (class == "ForeignHash" && matches!(method, "clear" | "clone_from"))
        {
            return Err(VmExecutionError::new("cannot write to foreign storage"));
        }
        self.call_receiver(receiver, method, args, kwargs, host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_storage_family_controls_unbound_receiver_admission() {
        let variable = VmValue::ForeignStorageRef(VmForeignStorageRef {
            contract: "target".into(),
            binding: "value".into(),
            is_hash: false,
        });
        let hash = VmValue::StorageRef(VmStorageRef {
            binding: "ledger".into(),
            storage_type: "Hash".into(),
        });
        assert!(receiver_matches("Variable", &variable));
        assert!(receiver_matches("ForeignVariable", &variable));
        assert!(!receiver_matches("Hash", &variable));
        assert!(receiver_matches("Hash", &hash));
        assert!(!receiver_matches("Variable", &hash));
        assert!(!receiver_matches("LogEvent", &hash));
        assert!(!receiver_matches("Variable", &vm_int(1)));
    }

    #[test]
    fn inherited_reads_share_function_identity_but_foreign_overrides_do_not() {
        let variable = VmValue::TypeMarker("ForeignVariable".into());
        let hash = VmValue::TypeMarker("ForeignHash".into());
        assert_eq!(class_method(&variable, "get"), Some("Variable"));
        assert_eq!(class_method(&variable, "set"), Some("ForeignVariable"));
        assert_eq!(class_method(&hash, "all"), Some("Hash"));
        assert_eq!(class_method(&hash, "clear"), Some("ForeignHash"));
        assert_eq!(class_method(&hash, "clone_from"), Some("ForeignHash"));
        assert_eq!(class_method(&hash, "set"), None);
    }
}
