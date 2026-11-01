//! Reviewed Python bridge code metadata. This is deliberately independent of
//! argument binding: co_argcount excludes keyword-only and variadic arguments.
//! Fixture provenance: tests/fixtures/interface_host_metadata.json.
use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) struct CodeMetadata {
    pub name: &'static str,
    pub args: &'static [&'static str],
    pub function: bool,
}
impl CodeMetadata {
    pub fn work(self) -> u64 {
        self.args
            .iter()
            .fold(self.name.len() as u64 + 1, |work, arg| {
                work.saturating_add(arg.len() as u64 + 1)
            })
    }
    pub fn member(self) -> VmInterfaceMember {
        VmInterfaceMember::Function {
            name: self.name.into(),
            args: self.args.iter().map(|arg| (*arg).into()).collect(),
        }
    }
}

static CATALOG: &[(&str, CodeMetadata)] = &[
    (
        "indexed",
        CodeMetadata {
            name: "indexed",
            args: &[],
            function: true,
        },
    ),
    (
        "Contract.deploy",
        CodeMetadata {
            name: "deploy",
            args: &["cls"],
            function: false,
        },
    ),
    (
        "Contract.get_info",
        CodeMetadata {
            name: "get_info",
            args: &["cls", "name"],
            function: false,
        },
    ),
    (
        "Contract.set_owner",
        CodeMetadata {
            name: "set_owner",
            args: &["cls", "name", "new_owner"],
            function: false,
        },
    ),
    (
        "Contract.set_developer",
        CodeMetadata {
            name: "set_developer",
            args: &["cls", "name", "new_developer"],
            function: false,
        },
    ),
    (
        "datetime.datetime.strptime",
        CodeMetadata {
            name: "strptime",
            args: &["cls", "date_string", "format"],
            function: false,
        },
    ),
    (
        "hashlib.sha3",
        CodeMetadata {
            name: "sha3",
            args: &["hex_str"],
            function: true,
        },
    ),
    (
        "hashlib.sha256",
        CodeMetadata {
            name: "sha256",
            args: &["hex_str"],
            function: true,
        },
    ),
    (
        "hashlib.sha3_text",
        CodeMetadata {
            name: "sha3_text",
            args: &["value"],
            function: true,
        },
    ),
    (
        "hashlib.sha3_hex",
        CodeMetadata {
            name: "sha3_hex",
            args: &["value"],
            function: true,
        },
    ),
    (
        "hashlib.sha256_text",
        CodeMetadata {
            name: "sha256_text",
            args: &["value"],
            function: true,
        },
    ),
    (
        "hashlib.sha256_hex",
        CodeMetadata {
            name: "sha256_hex",
            args: &["value"],
            function: true,
        },
    ),
    (
        "crypto.verify",
        CodeMetadata {
            name: "verify",
            args: &["vk", "msg", "signature"],
            function: true,
        },
    ),
    (
        "crypto.key_is_valid",
        CodeMetadata {
            name: "key_is_valid",
            args: &["key"],
            function: true,
        },
    ),
    (
        "importlib.import_module",
        CodeMetadata {
            name: "import_module",
            args: &["name"],
            function: true,
        },
    ),
    (
        "importlib.exists",
        CodeMetadata {
            name: "exists",
            args: &["contract"],
            function: true,
        },
    ),
    (
        "importlib.has_export",
        CodeMetadata {
            name: "has_export",
            args: &["contract", "function"],
            function: true,
        },
    ),
    (
        "importlib.call",
        CodeMetadata {
            name: "call",
            args: &["contract", "function", "kwargs"],
            function: true,
        },
    ),
    (
        "importlib.enforce_interface",
        CodeMetadata {
            name: "enforce_interface",
            args: &["contract", "interface"],
            function: true,
        },
    ),
    (
        "importlib.owner_of",
        CodeMetadata {
            name: "owner_of",
            args: &["contract"],
            function: true,
        },
    ),
    (
        "importlib.contract_info",
        CodeMetadata {
            name: "contract_info",
            args: &["contract"],
            function: true,
        },
    ),
    (
        "importlib.code_hash",
        CodeMetadata {
            name: "code_hash",
            args: &["contract", "kind"],
            function: true,
        },
    ),
    (
        "random.seed",
        CodeMetadata {
            name: "seed",
            args: &["aux_salt"],
            function: true,
        },
    ),
    (
        "random.random",
        CodeMetadata {
            name: "random",
            args: &[],
            function: true,
        },
    ),
    (
        "random.shuffle",
        CodeMetadata {
            name: "shuffle",
            args: &["items"],
            function: true,
        },
    ),
    (
        "random.getrandbits",
        CodeMetadata {
            name: "getrandbits",
            args: &["k"],
            function: true,
        },
    ),
    (
        "random.randrange",
        CodeMetadata {
            name: "randrange",
            args: &["k"],
            function: true,
        },
    ),
    (
        "random.randint",
        CodeMetadata {
            name: "randint",
            args: &["a", "b"],
            function: true,
        },
    ),
    (
        "random.choice",
        CodeMetadata {
            name: "choice",
            args: &["items"],
            function: true,
        },
    ),
    (
        "random.choices",
        CodeMetadata {
            name: "choices",
            args: &["items", "k"],
            function: true,
        },
    ),
    (
        "zk.is_available",
        CodeMetadata {
            name: "is_available",
            args: &[],
            function: true,
        },
    ),
    (
        "zk.has_verifying_key",
        CodeMetadata {
            name: "has_verifying_key",
            args: &["vk_id"],
            function: true,
        },
    ),
    (
        "zk.get_vk_info",
        CodeMetadata {
            name: "get_vk_info",
            args: &["vk_id"],
            function: true,
        },
    ),
    (
        "zk.verify_groth16_bn254",
        CodeMetadata {
            name: "verify_groth16_bn254",
            args: &["vk_hex", "proof_hex", "public_inputs"],
            function: true,
        },
    ),
    (
        "zk.verify_groth16",
        CodeMetadata {
            name: "verify_groth16",
            args: &["vk_id", "proof_hex", "public_inputs"],
            function: true,
        },
    ),
    (
        "zk.clear_prepared_vk_cache",
        CodeMetadata {
            name: "clear_prepared_vk_cache",
            args: &[],
            function: true,
        },
    ),
    (
        "zk.clear_verified_proof_cache",
        CodeMetadata {
            name: "clear_verified_proof_cache",
            args: &[],
            function: true,
        },
    ),
    (
        "zk.warm_verified_proofs",
        CodeMetadata {
            name: "warm_verified_proofs",
            args: &["requests"],
            function: true,
        },
    ),
    (
        "zk.shielded_note_append_commitments",
        CodeMetadata {
            name: "shielded_note_append_commitments",
            args: &["note_count", "filled_subtrees", "commitments"],
            function: true,
        },
    ),
    (
        "zk.shielded_command_nullifier_digest",
        CodeMetadata {
            name: "shielded_command_nullifier_digest",
            args: &["input_nullifiers"],
            function: true,
        },
    ),
    (
        "zk.shielded_command_binding",
        CodeMetadata {
            name: "shielded_command_binding",
            args: &[
                "nullifier_digest",
                "target_digest",
                "payload_digest",
                "relayer_digest",
                "expiry_digest",
                "chain_digest",
                "entrypoint_digest",
                "version_digest",
                "fee",
                "public_amount",
            ],
            function: true,
        },
    ),
    (
        "zk.shielded_command_execution_tag",
        CodeMetadata {
            name: "shielded_command_execution_tag",
            args: &["nullifier_digest", "command_binding"],
            function: true,
        },
    ),
    (
        "zk.shielded_command_public_inputs",
        CodeMetadata {
            name: "shielded_command_public_inputs",
            args: &[
                "contract_name",
                "old_root",
                "command_binding",
                "execution_tag",
                "fee",
                "public_amount",
                "input_nullifiers",
                "commitments",
                "payload_hashes",
            ],
            function: true,
        },
    ),
    (
        "zk.shielded_deposit_public_inputs",
        CodeMetadata {
            name: "shielded_deposit_public_inputs",
            args: &[
                "contract_name",
                "old_root",
                "amount",
                "commitments",
                "payload_hashes",
            ],
            function: true,
        },
    ),
    (
        "zk.shielded_output_payload_hashes",
        CodeMetadata {
            name: "shielded_output_payload_hashes",
            args: &["payload_hexes"],
            function: true,
        },
    ),
    (
        "zk.shielded_output_payload_hash",
        CodeMetadata {
            name: "shielded_output_payload_hash",
            args: &["payload_hex"],
            function: true,
        },
    ),
    (
        "zk.shielded_transfer_public_inputs",
        CodeMetadata {
            name: "shielded_transfer_public_inputs",
            args: &[
                "contract_name",
                "old_root",
                "input_nullifiers",
                "commitments",
                "payload_hashes",
            ],
            function: true,
        },
    ),
    (
        "zk.shielded_withdraw_public_inputs",
        CodeMetadata {
            name: "shielded_withdraw_public_inputs",
            args: &[
                "contract_name",
                "old_root",
                "amount",
                "recipient",
                "input_nullifiers",
                "commitments",
                "payload_hashes",
            ],
            function: true,
        },
    ),
    (
        "pow",
        CodeMetadata {
            name: "safe_pow",
            args: &[],
            function: true,
        },
    ),
    (
        "range",
        CodeMetadata {
            name: "safe_range",
            args: &[],
            function: true,
        },
    ),
    (
        "round",
        CodeMetadata {
            name: "safe_round",
            args: &["number", "ndigits"],
            function: true,
        },
    ),
    (
        "set.add",
        CodeMetadata {
            name: "add",
            args: &["self", "value"],
            function: true,
        },
    ),
    (
        "set.clear",
        CodeMetadata {
            name: "clear",
            args: &["self"],
            function: true,
        },
    ),
    (
        "set.copy",
        CodeMetadata {
            name: "copy",
            args: &["self"],
            function: true,
        },
    ),
    (
        "set.difference",
        CodeMetadata {
            name: "difference",
            args: &["self"],
            function: true,
        },
    ),
    (
        "set.discard",
        CodeMetadata {
            name: "discard",
            args: &["self", "value"],
            function: true,
        },
    ),
    (
        "set.intersection",
        CodeMetadata {
            name: "intersection",
            args: &["self"],
            function: true,
        },
    ),
    (
        "set.isdisjoint",
        CodeMetadata {
            name: "isdisjoint",
            args: &["self", "other"],
            function: true,
        },
    ),
    (
        "set.issubset",
        CodeMetadata {
            name: "issubset",
            args: &["self", "other"],
            function: true,
        },
    ),
    (
        "set.issuperset",
        CodeMetadata {
            name: "issuperset",
            args: &["self", "other"],
            function: true,
        },
    ),
    (
        "set.pop",
        CodeMetadata {
            name: "pop",
            args: &["self"],
            function: true,
        },
    ),
    (
        "set.remove",
        CodeMetadata {
            name: "remove",
            args: &["self", "value"],
            function: true,
        },
    ),
    (
        "set.symmetric_difference",
        CodeMetadata {
            name: "symmetric_difference",
            args: &["self", "other"],
            function: true,
        },
    ),
    (
        "set.union",
        CodeMetadata {
            name: "union",
            args: &["self"],
            function: true,
        },
    ),
    (
        "frozenset.copy",
        CodeMetadata {
            name: "copy",
            args: &["self"],
            function: true,
        },
    ),
    (
        "frozenset.difference",
        CodeMetadata {
            name: "difference",
            args: &["self"],
            function: true,
        },
    ),
    (
        "frozenset.intersection",
        CodeMetadata {
            name: "intersection",
            args: &["self"],
            function: true,
        },
    ),
    (
        "frozenset.isdisjoint",
        CodeMetadata {
            name: "isdisjoint",
            args: &["self", "other"],
            function: true,
        },
    ),
    (
        "frozenset.issubset",
        CodeMetadata {
            name: "issubset",
            args: &["self", "other"],
            function: true,
        },
    ),
    (
        "frozenset.issuperset",
        CodeMetadata {
            name: "issuperset",
            args: &["self", "other"],
            function: true,
        },
    ),
    (
        "frozenset.symmetric_difference",
        CodeMetadata {
            name: "symmetric_difference",
            args: &["self", "other"],
            function: true,
        },
    ),
    (
        "frozenset.union",
        CodeMetadata {
            name: "union",
            args: &["self"],
            function: true,
        },
    ),
    (
        "Variable.append",
        CodeMetadata {
            name: "append",
            args: &["self", "value"],
            function: true,
        },
    ),
    (
        "Variable.clear",
        CodeMetadata {
            name: "clear",
            args: &["self"],
            function: true,
        },
    ),
    (
        "Variable.extend",
        CodeMetadata {
            name: "extend",
            args: &["self", "values"],
            function: true,
        },
    ),
    (
        "Variable.get",
        CodeMetadata {
            name: "get",
            args: &["self"],
            function: true,
        },
    ),
    (
        "Variable.insert",
        CodeMetadata {
            name: "insert",
            args: &["self", "index", "value"],
            function: true,
        },
    ),
    (
        "Variable.pop",
        CodeMetadata {
            name: "pop",
            args: &["self", "key", "default"],
            function: true,
        },
    ),
    (
        "Variable.remove",
        CodeMetadata {
            name: "remove",
            args: &["self", "value"],
            function: true,
        },
    ),
    (
        "Variable.set",
        CodeMetadata {
            name: "set",
            args: &["self", "value"],
            function: true,
        },
    ),
    (
        "Variable.update",
        CodeMetadata {
            name: "update",
            args: &["self", "other"],
            function: true,
        },
    ),
    (
        "Hash.all",
        CodeMetadata {
            name: "all",
            args: &["self"],
            function: true,
        },
    ),
    (
        "Hash.clear",
        CodeMetadata {
            name: "clear",
            args: &["self"],
            function: true,
        },
    ),
    (
        "Hash.clone_from",
        CodeMetadata {
            name: "clone_from",
            args: &["self", "source"],
            function: true,
        },
    ),
    (
        "ForeignVariable.append",
        CodeMetadata {
            name: "append",
            args: &["self", "value"],
            function: true,
        },
    ),
    (
        "ForeignVariable.clear",
        CodeMetadata {
            name: "clear",
            args: &["self"],
            function: true,
        },
    ),
    (
        "ForeignVariable.extend",
        CodeMetadata {
            name: "extend",
            args: &["self", "values"],
            function: true,
        },
    ),
    (
        "ForeignVariable.get",
        CodeMetadata {
            name: "get",
            args: &["self"],
            function: true,
        },
    ),
    (
        "ForeignVariable.insert",
        CodeMetadata {
            name: "insert",
            args: &["self", "index", "value"],
            function: true,
        },
    ),
    (
        "ForeignVariable.pop",
        CodeMetadata {
            name: "pop",
            args: &["self", "key", "default"],
            function: true,
        },
    ),
    (
        "ForeignVariable.remove",
        CodeMetadata {
            name: "remove",
            args: &["self", "value"],
            function: true,
        },
    ),
    (
        "ForeignVariable.set",
        CodeMetadata {
            name: "set",
            args: &["self", "value"],
            function: true,
        },
    ),
    (
        "ForeignVariable.update",
        CodeMetadata {
            name: "update",
            args: &["self", "other"],
            function: true,
        },
    ),
    (
        "ForeignHash.all",
        CodeMetadata {
            name: "all",
            args: &["self"],
            function: true,
        },
    ),
    (
        "ForeignHash.clear",
        CodeMetadata {
            name: "clear",
            args: &["self"],
            function: true,
        },
    ),
    (
        "ForeignHash.clone_from",
        CodeMetadata {
            name: "clone_from",
            args: &["self", "source"],
            function: true,
        },
    ),
    (
        "LogEvent.write_event",
        CodeMetadata {
            name: "write_event",
            args: &["self", "event_data"],
            function: true,
        },
    ),
    (
        "bytes.fromhex",
        CodeMetadata {
            name: "fromhex",
            args: &["string"],
            function: true,
        },
    ),
    (
        "bytes.maketrans",
        CodeMetadata {
            name: "maketrans",
            args: &["frm", "to"],
            function: true,
        },
    ),
    (
        "bytearray.fromhex",
        CodeMetadata {
            name: "fromhex",
            args: &["string"],
            function: true,
        },
    ),
    (
        "bytearray.maketrans",
        CodeMetadata {
            name: "maketrans",
            args: &["frm", "to"],
            function: true,
        },
    ),
    (
        "importlib.Func.is_of",
        CodeMetadata {
            name: "is_of",
            args: &["self", "f"],
            function: true,
        },
    ),
    (
        "importlib.Var.is_of",
        CodeMetadata {
            name: "is_of",
            args: &["self", "v"],
            function: true,
        },
    ),
];

pub(super) fn named(binding: &str) -> Option<CodeMetadata> {
    CATALOG
        .iter()
        .find(|(name, _)| *name == binding)
        .map(|(_, code)| *code)
}

pub(super) fn metadata(value: &VmValue) -> Option<CodeMetadata> {
    match value {
        VmValue::Reference(reference) => reference.with_value(metadata),
        VmValue::HostCallable(callable) => named(callable.binding()),
        VmValue::Builtin(name) => named(name),
        VmValue::BoundMethod(bound) => method_metadata(&bound.receiver, &bound.method),
        _ => None,
    }
}

fn method_metadata(receiver: &VmValue, method: &str) -> Option<CodeMetadata> {
    if let VmValue::Reference(reference) = receiver {
        return reference.with_value(|value| method_metadata(value, method));
    }
    concrete_method_metadata(receiver, method)
}
fn concrete_method_metadata(receiver: &VmValue, method: &str) -> Option<CodeMetadata> {
    match receiver {
        VmValue::Builtin(class) | VmValue::TypeMarker(class) => class_metadata(class, method),
        VmValue::Set(_) => instance_metadata("set", method),
        VmValue::FrozenSet(_) => instance_metadata("frozenset", method),
        VmValue::StorageRef(storage) => instance_metadata(&storage.storage_type, method),
        VmValue::ForeignStorageRef(storage) => foreign_metadata(storage.is_hash, method),
        VmValue::EventRef(_) => instance_metadata("LogEvent", method),
        VmValue::InterfaceDescriptor(descriptor) => {
            instance_metadata(descriptor.class_name(), method)
        }
        _ => None,
    }
}
fn foreign_metadata(is_hash: bool, method: &str) -> Option<CodeMetadata> {
    instance_metadata(
        if is_hash {
            "ForeignHash"
        } else {
            "ForeignVariable"
        },
        method,
    )
}
fn class_metadata(class: &str, method: &str) -> Option<CodeMetadata> {
    // No allocation or invocation-signature inference during classification.
    CATALOG.iter().find_map(|(binding, code)| {
        binding
            .strip_prefix(class)
            .and_then(|suffix| suffix.strip_prefix('.'))
            .filter(|suffix| *suffix == method)
            .map(|_| *code)
    })
}
fn instance_metadata(class: &str, method: &str) -> Option<CodeMetadata> {
    class_metadata(class, method).map(|code| CodeMetadata {
        function: false,
        ..code
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_host_metadata_covers_exact_admitted_host_catalog() {
        let no_code = [
            "decimal",
            "datetime.datetime",
            "datetime.timedelta",
            "importlib.Func",
            "importlib.Var",
        ];
        let bindings = host_callables::catalog_bindings().collect::<Vec<_>>();
        assert_eq!(bindings.len(), 53);
        for binding in bindings {
            assert_ne!(
                named(binding).is_some(),
                no_code.contains(&binding),
                "{binding}"
            );
        }
        let oracle: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/interface_host_metadata.json"
        ))
        .unwrap();
        for item in oracle.as_array().unwrap() {
            let binding = item["binding"].as_str().unwrap();
            let canonical = binding
                .strip_prefix('(')
                .and_then(|v| v.split_once(")."))
                .map(|(class, method)| format!("{class}.{method}"))
                .unwrap_or_else(|| binding.into());
            let Some(code) = named(&canonical) else {
                continue;
            };
            assert_eq!(code.name, item["code_name"].as_str().unwrap(), "{binding}");
            assert_eq!(
                code.args,
                item["positional_names"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect::<Vec<_>>(),
                "{binding}"
            );
            assert_eq!(
                code.function,
                item["enforce_as_function"].as_bool().unwrap(),
                "{binding}"
            );
        }
    }
    #[test]
    fn descriptor_metadata_preserves_function_method_and_guarded_class_distinctions() {
        let bound = |receiver, method: &str| {
            VmValue::BoundMethod(Box::new(VmBoundMethod {
                receiver,
                method: method.into(),
            }))
        };
        assert!(
            metadata(&bound(VmValue::Builtin("set".into()), "add"))
                .unwrap()
                .function
        );
        assert!(
            !metadata(&bound(VmValue::Set(vec![]), "add"))
                .unwrap()
                .function
        );
        assert!(
            metadata(&bound(VmValue::Builtin("bytes".into()), "fromhex"))
                .unwrap()
                .function
        );
        assert!(metadata(&bound(VmValue::Builtin("builtins.bytes".into()), "fromhex")).is_none());
        assert!(metadata(&VmValue::Builtin("sorted".into())).is_none());
        assert!(metadata(&bound(VmValue::BuiltinSet(vec![]), "union")).is_none());
    }

    #[test]
    fn descriptor_method_metadata_selects_the_exact_public_method() {
        let factory = class_metadata("bytes", "fromhex").unwrap();
        assert_eq!(factory.name, "fromhex");
        assert_eq!(factory.args, &["string"]);
        let translation = class_metadata("bytes", "maketrans").unwrap();
        assert_eq!(translation.name, "maketrans");
        assert_eq!(translation.args, &["frm", "to"]);
        let add = class_metadata("set", "add").unwrap();
        assert_eq!(add.name, "add");
        assert_eq!(add.args, &["self", "value"]);
        assert!(class_metadata("bytes", "not_a_method").is_none());
    }
}
