//! Safe public module aliases never expose an arbitrary foreign VM value.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub enum VmPublicCallable {
    Export {
        module: String,
        function: String,
        identity: Option<usize>,
    },
    Host(VmHostCallable),
    Builtin(String),
    Type(String),
    ClassMethod {
        class: String,
        method: String,
        identity: Option<usize>,
    },
}
impl VmPublicCallable {
    pub fn inspection_work(&self) -> u64 {
        match self {
            Self::Export {
                module, function, ..
            } => module.len() as u64 + function.len() as u64 + 2,
            Self::Host(callable) => callable.binding().len() as u64 + 1,
            Self::Builtin(name) | Self::Type(name) => name.len() as u64 + 1,
            Self::ClassMethod { class, method, .. } => class.len() as u64 + method.len() as u64 + 2,
        }
    }
    fn cache_key(&self) -> String {
        match self {
            Self::Export {
                module,
                function,
                identity: None,
            } => format!("export:{module}:{function}"),
            Self::Export {
                identity: Some(id), ..
            } => format!("export-reference:{id}"),
            Self::ClassMethod {
                class,
                method,
                identity,
            } => format!("class:{class}:{method}:{identity:?}"),
            _ => String::new(),
        }
    }
}

impl VmInstance {
    pub fn public_callable_metadata_work(&self) -> u64 {
        let globals = self.globals.iter().fold(0u64, |work, (name, value)| {
            work.saturating_add(name.len() as u64 + 1)
                .saturating_add(self.public_value_work(value))
        });
        let functions = self.functions.values().fold(0u64, |work, function| {
            work.saturating_add(
                function.name.len() as u64 + self.module.module_name.len() as u64 + 2,
            )
        });
        let count = self
            .globals
            .len()
            .saturating_add(self.functions.len())
            .saturating_add(1);
        globals
            .saturating_add(functions)
            .saturating_add(1)
            .saturating_mul(count.ilog2() as u64 + 1)
    }
    fn public_value_work(&self, value: &VmValue) -> u64 {
        match value {
            VmValue::Reference(reference) => {
                reference.with_value(|value| self.public_value_work(value))
            }
            VmValue::FunctionRef(name) => {
                self.module.module_name.len() as u64 + name.len() as u64 + 2
            }
            VmValue::HostCallable(callable) => callable.binding().len() as u64 + 1,
            VmValue::Builtin(name) | VmValue::TypeMarker(name) => name.len() as u64 + 1,
            VmValue::BoundMethod(bound) => self
                .public_value_work(&bound.receiver)
                .saturating_add(bound.method.len() as u64 + 1),
            VmValue::ContractHandle(handle) => handle.module.len() as u64 + 1,
            _ => 1,
        }
    }
    pub fn public_callables(&self) -> BTreeMap<String, VmPublicCallable> {
        let mut members = BTreeMap::new();
        for function in self
            .functions
            .values()
            .filter(|function| function.visibility == "export")
        {
            members.insert(
                function.name.clone(),
                VmPublicCallable::Export {
                    module: self.module.module_name.clone(),
                    function: function.name.clone(),
                    identity: None,
                },
            );
        }
        for (name, value) in &self.globals {
            if let Some(callable) = self.classify_public_callable(value, None) {
                members.insert(name.clone(), callable);
            } else {
                members.remove(name);
            }
        }
        members.retain(|name, _| !name.starts_with('_') && !name.ends_with('_'));
        members
    }
    pub fn public_callable(&self, name: &str) -> Option<VmPublicCallable> {
        if name.starts_with('_') || name.ends_with('_') {
            return None;
        }
        if let Some(value) = self.globals.get(name) {
            return self.classify_public_callable(value, None);
        }
        self.functions
            .get(name)
            .filter(|function| function.visibility == "export")
            .map(|function| VmPublicCallable::Export {
                module: self.module.module_name.clone(),
                function: function.name.clone(),
                identity: None,
            })
    }
    fn classify_public_callable(
        &self,
        value: &VmValue,
        identity: Option<usize>,
    ) -> Option<VmPublicCallable> {
        match value {
            VmValue::Reference(reference) => reference
                .with_value(|value| self.classify_public_callable(value, Some(reference.id()))),
            VmValue::FunctionRef(name) => self
                .functions
                .get(name)
                .filter(|function| function.visibility == "export")
                .map(|_| VmPublicCallable::Export {
                    module: self.module.module_name.clone(),
                    function: name.clone(),
                    identity: None,
                }),
            VmValue::HostCallable(callable) => Some(VmPublicCallable::Host(*callable)),
            VmValue::Builtin(name) if builtin_name_value(name).is_some() || name == "Contract" => {
                Some(VmPublicCallable::Builtin(name.clone()))
            }
            VmValue::TypeMarker(name) if public_constructor(name) => {
                Some(VmPublicCallable::Type(name.clone()))
            }
            VmValue::BoundMethod(bound) => {
                classify_bound_alias(&bound.receiver, &bound.method, identity)
            }
            _ => None,
        }
    }
    pub(super) fn materialize_public_callable(
        &mut self,
        receiver: VmValue,
        descriptor: VmPublicCallable,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        match descriptor {
            VmPublicCallable::Host(callable) => Ok(callable.value()),
            VmPublicCallable::Builtin(name) => Ok(VmValue::Builtin(name)),
            VmPublicCallable::Type(name) => Ok(VmValue::TypeMarker(name)),
            descriptor => self.cached_public_callable(receiver, descriptor, host),
        }
    }
    fn cached_public_callable(
        &mut self,
        receiver: VmValue,
        descriptor: VmPublicCallable,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let receiver = self.heap.capture(receiver)?;
        let VmValue::Reference(reference) = &receiver else {
            return Err(VmExecutionError::new(
                "contract handle has no execution identity",
            ));
        };
        let key = (reference.id(), descriptor.cache_key());
        if let Some(value) = self.contract_exports.get(&key) {
            return Ok(value.clone());
        }
        let value = self.bind_public_callable(receiver, descriptor, host)?;
        let value = self.heap.capture(value)?;
        self.contract_exports.insert(key, value.clone());
        Ok(value)
    }
    fn bind_public_callable(
        &mut self,
        receiver: VmValue,
        descriptor: VmPublicCallable,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        Ok(match descriptor {
            VmPublicCallable::Export {
                module, function, ..
            } => {
                host.validate_contract_export(&module, &function)?;
                let target = match receiver.snapshot() {
                    VmValue::ContractHandle(handle) if handle.module == module => receiver,
                    _ => self
                        .heap
                        .capture(VmValue::ContractHandle(VmContractHandle {
                            module,
                            origin: "public_alias".into(),
                        }))?,
                };
                VmValue::BoundMethod(Box::new(VmBoundMethod {
                    receiver: target,
                    method: function,
                }))
            }
            VmPublicCallable::ClassMethod { class, method, .. } => {
                self.alias_class_method(&class, &method, host)?
            }
            _ => return Err(VmExecutionError::new("invalid public callable cache entry")),
        })
    }
    fn alias_class_method(
        &mut self,
        class: &str,
        method: &str,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if class.starts_with("builtins.") {
            if method == "maketrans" {
                return self.static_method(class, method);
            }
            return Ok(VmValue::BoundMethod(Box::new(VmBoundMethod {
                receiver: class_value(class),
                method: method.into(),
            })));
        }
        self.read_attribute(class_value(class), method, host)
    }
}
fn public_constructor(name: &str) -> bool {
    matches!(
        name,
        "Any"
            | "decimal"
            | "datetime.datetime"
            | "datetime.timedelta"
            | "importlib.Func"
            | "importlib.Var"
    ) || matches!(builtin_name_value(name), Some(VmValue::Builtin(_)))
}
fn class_value(name: &str) -> VmValue {
    builtin_name_value(name).unwrap_or_else(|| {
        if name == "Contract" || name.starts_with("builtins.") {
            VmValue::Builtin(name.into())
        } else {
            VmValue::TypeMarker(name.into())
        }
    })
}
fn classify_bound_alias(
    receiver: &VmValue,
    method: &str,
    identity: Option<usize>,
) -> Option<VmPublicCallable> {
    match receiver {
        VmValue::Reference(reference) => {
            reference.with_value(|value| classify_bound_alias(value, method, identity))
        }
        VmValue::ContractHandle(handle) => Some(VmPublicCallable::Export {
            module: handle.module.clone(),
            function: method.into(),
            identity,
        }),
        VmValue::Builtin(class) | VmValue::TypeMarker(class) => {
            class_method_alias(class, method, identity)
        }
        _ => None,
    }
}
fn class_method_alias(
    class: &str,
    method: &str,
    identity: Option<usize>,
) -> Option<VmPublicCallable> {
    let canonical = class.strip_prefix("builtins.").unwrap_or(class);
    PUBLIC_CLASS_METHODS
        .iter()
        .find(|(name, _)| *name == canonical)
        .filter(|(_, methods)| methods.contains(&method))
        .map(|_| VmPublicCallable::ClassMethod {
            class: class.into(),
            method: method.into(),
            identity,
        })
}

// Reviewed mirror of the Python catalog; the unit invariant detects drift.
const PUBLIC_CLASS_METHODS: &[(&str, &[&str])] = &[
    (
        "Contract",
        &["deploy", "get_info", "set_developer", "set_owner", "submit"],
    ),
    ("ForeignHash", &["all", "clear", "clone_from"]),
    (
        "ForeignVariable",
        &[
            "append", "clear", "extend", "get", "insert", "pop", "remove", "set", "update",
        ],
    ),
    ("Hash", &["all", "clear", "clone_from"]),
    ("LogEvent", &["write_event"]),
    (
        "Variable",
        &[
            "append", "clear", "extend", "get", "insert", "pop", "remove", "set", "update",
        ],
    ),
    (
        "bool",
        &[
            "as_integer_ratio",
            "bit_count",
            "bit_length",
            "conjugate",
            "from_bytes",
            "is_integer",
            "to_bytes",
        ],
    ),
    ("bytearray", &["fromhex", "maketrans"]),
    ("bytes", &["fromhex", "maketrans"]),
    ("datetime.datetime", &["strptime"]),
    (
        "dict",
        &[
            "clear",
            "copy",
            "fromkeys",
            "get",
            "items",
            "keys",
            "pop",
            "popitem",
            "setdefault",
            "update",
            "values",
        ],
    ),
    (
        "float",
        &[
            "as_integer_ratio",
            "conjugate",
            "fromhex",
            "hex",
            "is_integer",
        ],
    ),
    (
        "frozenset",
        &[
            "copy",
            "difference",
            "intersection",
            "isdisjoint",
            "issubset",
            "issuperset",
            "symmetric_difference",
            "union",
        ],
    ),
    ("importlib.Func", &["is_of"]),
    ("importlib.Var", &["is_of"]),
    (
        "int",
        &[
            "as_integer_ratio",
            "bit_count",
            "bit_length",
            "conjugate",
            "from_bytes",
            "is_integer",
            "to_bytes",
        ],
    ),
    (
        "list",
        &[
            "append", "clear", "copy", "count", "extend", "index", "insert", "pop", "remove",
            "reverse", "sort",
        ],
    ),
    (
        "set",
        &[
            "add",
            "clear",
            "copy",
            "difference",
            "discard",
            "intersection",
            "isdisjoint",
            "issubset",
            "issuperset",
            "pop",
            "remove",
            "symmetric_difference",
            "union",
        ],
    ),
    (
        "str",
        &[
            "capitalize",
            "casefold",
            "center",
            "count",
            "encode",
            "endswith",
            "expandtabs",
            "find",
            "format",
            "format_map",
            "index",
            "isalnum",
            "isalpha",
            "isascii",
            "isdecimal",
            "isdigit",
            "isidentifier",
            "islower",
            "isnumeric",
            "isprintable",
            "isspace",
            "istitle",
            "isupper",
            "join",
            "ljust",
            "lower",
            "lstrip",
            "maketrans",
            "partition",
            "removeprefix",
            "removesuffix",
            "replace",
            "rfind",
            "rindex",
            "rjust",
            "rpartition",
            "rsplit",
            "rstrip",
            "split",
            "splitlines",
            "startswith",
            "strip",
            "swapcase",
            "title",
            "translate",
            "upper",
            "zfill",
        ],
    ),
    ("tuple", &["count", "index"]),
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_alias_class_method_catalog_matches_python_and_rejects_uncatalogued_members() {
        let python: BTreeMap<String, Vec<String>> = serde_json::from_str(include_str!(
            "../../../src/contracting/execution/public_callable_methods.json"
        ))
        .unwrap();
        assert_eq!(python.len(), PUBLIC_CLASS_METHODS.len());
        for (class, methods) in PUBLIC_CLASS_METHODS {
            assert_eq!(
                &python[*class],
                &methods
                    .iter()
                    .map(|name| name.to_string())
                    .collect::<Vec<_>>()
            );
            for method in *methods {
                assert!(class_method_alias(class, method, None).is_some());
            }
            assert!(class_method_alias(class, "mro", None).is_none());
        }
        assert!(class_method_alias("bytes", "decode", None).is_none());
        assert!(class_method_alias("builtins.bytes", "fromhex", None).is_some());
        assert!(class_method_alias("set", "union", None).is_some());
        assert!(classify_bound_alias(&VmValue::String("x".into()), "upper", None).is_none());
        assert!(classify_bound_alias(
            &VmValue::StorageRef(VmStorageRef {
                binding: "state".into(),
                storage_type: "Variable".into()
            }),
            "set",
            None
        )
        .is_none());
    }
    fn alias_instance() -> VmInstance {
        let function = FunctionIr {
            node: "function".into(),
            name: "probe".into(),
            visibility: "export".into(),
            span: crate::Span {
                line: 1,
                col: 0,
                end_line: 1,
                end_col: 1,
            },
            decorator: None,
            docstring: None,
            parameters: vec![],
            returns: None,
            body: vec![],
        };
        let module = ModuleIr {
            ir_version: crate::XIAN_IR_V1.into(),
            vm_profile: crate::XIAN_VM_V1_PROFILE.into(),
            host_catalog_version: crate::XIAN_VM_HOST_CATALOG_V1.into(),
            module_name: "con_alias".into(),
            source_hash: "0".repeat(64),
            docstring: None,
            imports: vec![],
            global_declarations: vec![],
            functions: vec![
                function.clone(),
                FunctionIr {
                    name: "hidden".into(),
                    visibility: "private".into(),
                    ..function
                },
            ],
            module_body: vec![],
            host_dependencies: vec![],
        };
        VmInstance::new(module, VmExecutionContext::default()).unwrap()
    }
    struct AliasHost;
    impl VmHost for AliasHost {
        fn validate_contract_export(
            &mut self,
            module: &str,
            name: &str,
        ) -> Result<(), VmExecutionError> {
            if module == "con_alias" && name == "probe" {
                Ok(())
            } else {
                Err(VmExecutionError::new("not a canonical export"))
            }
        }
        fn public_callable(
            &mut self,
            _module: &str,
            name: &str,
            _context: VmExecutionContext,
        ) -> Result<Option<VmPublicCallable>, VmExecutionError> {
            Ok((name == "length").then(|| VmPublicCallable::Builtin("len".into())))
        }
    }
    fn alias_handle(vm: &VmInstance) -> VmValue {
        vm.heap
            .capture(VmValue::ContractHandle(VmContractHandle {
                module: "con_alias".into(),
                origin: "dynamic_import".into(),
            }))
            .unwrap()
    }

    #[test]
    fn public_alias_classification_never_exports_foreign_object_graphs() {
        let mut vm = alias_instance();
        vm.globals
            .insert("public".into(), VmValue::FunctionRef("probe".into()));
        vm.globals
            .insert("private".into(), VmValue::FunctionRef("hidden".into()));
        vm.globals.insert(
            "data".into(),
            VmValue::List(vec![VmValue::Builtin("len".into())]),
        );
        vm.globals.insert(
            "storage".into(),
            VmValue::StorageRef(VmStorageRef {
                binding: "balance".into(),
                storage_type: "Variable".into(),
            }),
        );
        vm.globals
            .insert("namespace".into(), VmValue::Builtin("hashlib".into()));
        vm.globals
            .insert("class".into(), VmValue::Builtin("int".into()));
        let members = vm.public_callables();
        for rejected in ["private", "data", "storage", "namespace", "hidden"] {
            assert!(!members.contains_key(rejected), "{rejected}");
        }
        assert!(
            matches!(members["public"],VmPublicCallable::Export{ref module,ref function,..} if module=="con_alias" && function=="probe")
        );
        assert!(matches!(members["class"],VmPublicCallable::Builtin(ref name) if name=="int"));
        for name in ["_private_alias", "trailing_"] {
            vm.globals
                .insert(name.into(), VmValue::Builtin("len".into()));
            assert!(!vm.public_callables().contains_key(name));
            assert!(vm.public_callable(name).is_none());
        }
        assert!(vm.public_callable("probe").is_some());
        assert!(vm.public_callable("hidden").is_none());
        for name in ["decimal", "int", "datetime.datetime", "importlib.Func"] {
            vm.globals
                .insert("constructor".into(), VmValue::TypeMarker(name.into()));
            assert!(
                matches!(vm.public_callable("constructor"),Some(VmPublicCallable::Type(actual)) if actual==name)
            );
        }
        for name in [
            "Variable",
            "Hash",
            "ForeignVariable",
            "ForeignHash",
            "LogEvent",
        ] {
            vm.globals
                .insert("constructor".into(), VmValue::TypeMarker(name.into()));
            assert!(vm.public_callable("constructor").is_none());
        }
        vm.globals.insert("probe".into(), VmValue::None);
        assert!(!vm.public_callables().contains_key("probe"));
        assert!(vm.public_callable("probe").is_none());
    }

    #[test]
    fn public_alias_identity_reuses_exports_and_shared_class_functions_only() {
        let mut vm = alias_instance();
        let mut host = AliasHost;
        let module = alias_handle(&vm);
        let other = alias_handle(&vm);
        let descriptor = VmPublicCallable::Export {
            module: "con_alias".into(),
            function: "probe".into(),
            identity: None,
        };
        let first = vm
            .materialize_public_callable(module.clone(), descriptor.clone(), &mut host)
            .unwrap();
        let alias = vm
            .materialize_public_callable(module.clone(), descriptor.clone(), &mut host)
            .unwrap();
        let imported = vm
            .materialize_public_callable(other, descriptor, &mut host)
            .unwrap();
        assert!(first.identical(&alias));
        assert!(!first.identical(&imported));
        let bound = first.snapshot();
        let VmValue::BoundMethod(bound) = bound else {
            panic!("expected callable export")
        };
        assert!(bound.receiver.identical(&module));
        let foreign_handle = vm
            .heap
            .capture(VmValue::ContractHandle(VmContractHandle {
                module: "forwarder".into(),
                origin: "dynamic_import".into(),
            }))
            .unwrap();
        let forwarded = vm
            .materialize_public_callable(
                foreign_handle,
                VmPublicCallable::Export {
                    module: "con_alias".into(),
                    function: "probe".into(),
                    identity: Some(40),
                },
                &mut host,
            )
            .unwrap();
        let VmValue::BoundMethod(bound) = forwarded.snapshot() else {
            panic!("expected forwarded export")
        };
        assert_eq!(
            bound.receiver.as_contract_handle().unwrap().module,
            "con_alias"
        );
        let static_a = vm
            .alias_class_method("builtins.bytes", "maketrans", &mut host)
            .unwrap();
        let static_b = vm
            .alias_class_method("builtins.bytes", "maketrans", &mut host)
            .unwrap();
        assert!(static_a.identical(&static_b));
        let class_a = vm
            .alias_class_method("builtins.bytes", "fromhex", &mut host)
            .unwrap();
        let class_b = vm
            .alias_class_method("builtins.bytes", "fromhex", &mut host)
            .unwrap();
        let class_a = vm.heap.capture(class_a).unwrap();
        let class_b = vm.heap.capture(class_b).unwrap();
        assert!(!class_a.identical(&class_b));
        assert!(vm_values_equal(&class_a, &class_b).unwrap());

        let factory = VmPublicCallable::ClassMethod {
            class: "bytes".into(),
            method: "fromhex".into(),
            identity: Some(1),
        };
        let alias = vm
            .materialize_public_callable(module.clone(), factory, &mut host)
            .unwrap();
        let direct = vm
            .read_attribute(VmValue::Builtin("bytes".into()), "fromhex", &mut host)
            .unwrap();
        assert!(alias.identical(&direct));
        let first = vm
            .materialize_public_callable(
                module.clone(),
                VmPublicCallable::ClassMethod {
                    class: "Contract".into(),
                    method: "get_info".into(),
                    identity: Some(1),
                },
                &mut host,
            )
            .unwrap();
        let second = vm
            .materialize_public_callable(
                module.clone(),
                VmPublicCallable::ClassMethod {
                    class: "Contract".into(),
                    method: "get_info".into(),
                    identity: Some(2),
                },
                &mut host,
            )
            .unwrap();
        assert!(!first.identical(&second));
        assert!(vm_values_equal(&first, &second).unwrap());
        assert!(vm
            .materialize_public_callable(
                module,
                VmPublicCallable::Export {
                    module: "con_alias".into(),
                    function: "hidden".into(),
                    identity: None
                },
                &mut host
            )
            .is_err());
    }

    #[test]
    fn public_alias_static_ir_resolves_member_before_argument_effects() {
        let mut vm = alias_instance();
        let mut host = AliasHost;
        vm.imports.insert("target".into(), "con_remote".into());
        let mut scope = HashMap::from([(
            "target".into(),
            VmValue::ContractHandle(VmContractHandle {
                module: "con_remote".into(),
                origin: "static_import".into(),
            }),
        )]);
        let call = serde_json::json!({"node":"call","syscall_id":"contract.export_call","contract_target":{"kind":"static_import","module":"con_remote","binding":"target"},"func":{"node":"attribute","value":{"node":"name","id":"target"},"attr":"unsafe"},"args":[{"node":"bin_op","operator":"floordiv","left":{"node":"constant","value_type":"int","value":"1"},"right":{"node":"constant","value_type":"int","value":"0"}}],"keywords":[]});
        let error = vm
            .eval_call(call.as_object().unwrap(), &mut scope, &mut host)
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("module attribute is not an admitted public callable"));
        let mut call = call;
        call["func"]["attr"] = serde_json::json!("length");
        call["args"] = serde_json::json!([{"node":"list","elements":[{"node":"constant","value_type":"int","value":"1"}]}]);
        assert_eq!(
            vm.eval_call(call.as_object().unwrap(), &mut scope, &mut host)
                .unwrap()
                .snapshot(),
            vm_int(1)
        );
    }
}
