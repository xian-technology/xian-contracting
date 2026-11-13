//! Admitted execution-local host callables and their public argument signatures.
use super::*;

type Arguments = (Vec<VmValue>, Vec<(String, VmValue)>);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmHostCallable {
    spec: &'static HostCallableSpec,
}
#[derive(Debug, PartialEq, Eq)]
struct HostCallableSpec {
    binding: &'static str,
    syscall: &'static str,
    names: &'static [&'static str],
    defaults: &'static [DefaultValue],
    positional: usize,
    keyword_output: usize,
    variadic: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DefaultValue {
    Missing,
    Null,
    False,
    Zero,
    EmptyTuple,
    Text(&'static str),
}
use self::DefaultValue::*;
const fn named(
    binding: &'static str,
    syscall: &'static str,
    names: &'static [&'static str],
    defaults: &'static [DefaultValue],
    positional: usize,
    keyword_output: usize,
) -> HostCallableSpec {
    HostCallableSpec {
        binding,
        syscall,
        names,
        defaults,
        positional,
        keyword_output,
        variadic: false,
    }
}
const fn variadic(binding: &'static str, syscall: &'static str) -> HostCallableSpec {
    HostCallableSpec {
        binding,
        syscall,
        names: &[],
        defaults: &[],
        positional: 0,
        keyword_output: 0,
        variadic: true,
    }
}
static CATALOG: &[HostCallableSpec] = &[
    variadic("indexed", "event.indexed"),
    named(
        "Contract.deploy",
        "contract.deploy",
        &[
            "name",
            "code",
            "owner",
            "constructor_args",
            "developer",
            "deployer",
            "initiator",
        ],
        &[Missing, Missing, Null, Null, Null, Null, Null],
        0,
        0,
    ),
    named(
        "Contract.get_info",
        "contract.info",
        &["name"],
        &[Missing],
        1,
        1,
    ),
    named(
        "Contract.set_owner",
        "contract.set_owner",
        &["name", "new_owner"],
        &[Missing, Missing],
        2,
        2,
    ),
    named(
        "Contract.set_developer",
        "contract.set_developer",
        &["name", "new_developer"],
        &[Missing, Missing],
        2,
        2,
    ),
    named("decimal", "numeric.decimal.new", &["a"], &[Missing], 1, 1),
    named(
        "datetime.datetime",
        "time.datetime.new",
        &[
            "year",
            "month",
            "day",
            "hour",
            "minute",
            "second",
            "microsecond",
        ],
        &[Missing, Missing, Missing, Zero, Zero, Zero, Zero],
        7,
        7,
    ),
    named(
        "datetime.timedelta",
        "time.timedelta.new",
        &["weeks", "days", "hours", "minutes", "seconds"],
        &[Zero, Zero, Zero, Zero, Zero],
        5,
        5,
    ),
    named(
        "datetime.datetime.strptime",
        "time.datetime.strptime",
        &["date_string", "format"],
        &[Missing, Missing],
        2,
        2,
    ),
    named(
        "hashlib.sha3",
        "hash.sha3_256_legacy",
        &["hex_str"],
        &[Missing],
        1,
        1,
    ),
    named(
        "hashlib.sha256",
        "hash.sha256_legacy",
        &["hex_str"],
        &[Missing],
        1,
        1,
    ),
    named(
        "hashlib.sha3_text",
        "hash.sha3_256_text",
        &["value"],
        &[Missing],
        1,
        1,
    ),
    named(
        "hashlib.sha3_hex",
        "hash.sha3_256_hex",
        &["value"],
        &[Missing],
        1,
        1,
    ),
    named(
        "hashlib.sha256_text",
        "hash.sha256_text",
        &["value"],
        &[Missing],
        1,
        1,
    ),
    named(
        "hashlib.sha256_hex",
        "hash.sha256_hex",
        &["value"],
        &[Missing],
        1,
        1,
    ),
    named(
        "crypto.verify",
        "crypto.ed25519_verify",
        &["vk", "msg", "signature"],
        &[Missing, Missing, Missing],
        3,
        3,
    ),
    named(
        "crypto.key_is_valid",
        "crypto.key_is_valid",
        &["key"],
        &[Missing],
        1,
        1,
    ),
    named(
        "importlib.import_module",
        "contract.import",
        &["name"],
        &[Missing],
        1,
        1,
    ),
    named(
        "importlib.exists",
        "contract.exists",
        &["contract"],
        &[Missing],
        1,
        1,
    ),
    named(
        "importlib.has_export",
        "contract.has_export",
        &["contract", "function"],
        &[Missing, Missing],
        2,
        2,
    ),
    named(
        "importlib.call",
        "contract.call",
        &["contract", "function", "kwargs"],
        &[Missing, Missing, Null],
        3,
        3,
    ),
    named(
        "importlib.enforce_interface",
        "contract.enforce_interface",
        &["contract", "interface"],
        &[Missing, Missing],
        2,
        2,
    ),
    named(
        "importlib.owner_of",
        "contract.owner_of",
        &["contract"],
        &[Missing],
        1,
        1,
    ),
    named(
        "importlib.contract_info",
        "contract.info",
        &["contract"],
        &[Missing],
        1,
        1,
    ),
    named(
        "importlib.code_hash",
        "contract.code_hash",
        &["contract", "kind"],
        &[Missing, Text("runtime")],
        2,
        2,
    ),
    named(
        "importlib.Func",
        "contract.interface.func",
        &["name", "args", "private"],
        &[Missing, EmptyTuple, False],
        3,
        2,
    ),
    named(
        "importlib.Var",
        "contract.interface.var",
        &["name", "t"],
        &[Missing, Missing],
        2,
        2,
    ),
    named("random.seed", "random.seed", &["aux_salt"], &[Null], 1, 1),
    named("random.random", "random.random", &[], &[], 0, 0),
    named(
        "random.shuffle",
        "random.shuffle",
        &["items"],
        &[Missing],
        1,
        1,
    ),
    named(
        "random.getrandbits",
        "random.getrandbits",
        &["k"],
        &[Missing],
        1,
        1,
    ),
    named(
        "random.randrange",
        "random.randrange",
        &["k"],
        &[Missing],
        1,
        1,
    ),
    named(
        "random.randint",
        "random.randint",
        &["a", "b"],
        &[Missing, Missing],
        2,
        2,
    ),
    named(
        "random.choice",
        "random.choice",
        &["items"],
        &[Missing],
        1,
        1,
    ),
    named(
        "random.choices",
        "random.choices",
        &["items", "k"],
        &[Missing, Missing],
        2,
        2,
    ),
    named("zk.is_available", "zk.is_available", &[], &[], 0, 0),
    named(
        "zk.has_verifying_key",
        "zk.has_verifying_key",
        &["vk_id"],
        &[Missing],
        1,
        1,
    ),
    named(
        "zk.get_vk_info",
        "zk.get_vk_info",
        &["vk_id"],
        &[Missing],
        1,
        1,
    ),
    named(
        "zk.verify_groth16_bn254",
        "zk.verify_groth16_bn254",
        &["vk_hex", "proof_hex", "public_inputs"],
        &[Missing, Missing, Missing],
        3,
        3,
    ),
    named(
        "zk.verify_groth16",
        "zk.verify_groth16",
        &["vk_id", "proof_hex", "public_inputs"],
        &[Missing, Missing, Missing],
        3,
        3,
    ),
    named(
        "zk.clear_prepared_vk_cache",
        "zk.clear_prepared_vk_cache",
        &[],
        &[],
        0,
        0,
    ),
    named(
        "zk.clear_verified_proof_cache",
        "zk.clear_verified_proof_cache",
        &[],
        &[],
        0,
        0,
    ),
    named(
        "zk.warm_verified_proofs",
        "zk.warm_verified_proofs",
        &["requests"],
        &[Missing],
        1,
        1,
    ),
    named(
        "zk.shielded_note_append_commitments",
        "zk.shielded_note_append_commitments",
        &["note_count", "filled_subtrees", "commitments"],
        &[Missing, Missing, Missing],
        3,
        3,
    ),
    named(
        "zk.shielded_command_nullifier_digest",
        "zk.shielded_command_nullifier_digest",
        &["input_nullifiers"],
        &[Missing],
        1,
        1,
    ),
    named(
        "zk.shielded_command_binding",
        "zk.shielded_command_binding",
        &[
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
        &[
            Missing, Missing, Missing, Missing, Missing, Missing, Missing, Missing, Missing,
            Missing,
        ],
        10,
        10,
    ),
    named(
        "zk.shielded_command_execution_tag",
        "zk.shielded_command_execution_tag",
        &["nullifier_digest", "command_binding"],
        &[Missing, Missing],
        2,
        2,
    ),
    named(
        "zk.shielded_command_public_inputs",
        "zk.shielded_command_public_inputs",
        &[
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
        &[
            Missing, Missing, Missing, Missing, Missing, Missing, Missing, Missing, Missing,
        ],
        9,
        9,
    ),
    named(
        "zk.shielded_deposit_public_inputs",
        "zk.shielded_deposit_public_inputs",
        &[
            "contract_name",
            "old_root",
            "amount",
            "commitments",
            "payload_hashes",
        ],
        &[Missing, Missing, Missing, Missing, Missing],
        5,
        5,
    ),
    named(
        "zk.shielded_output_payload_hashes",
        "zk.shielded_output_payload_hashes",
        &["payload_hexes"],
        &[Missing],
        1,
        1,
    ),
    named(
        "zk.shielded_output_payload_hash",
        "zk.shielded_output_payload_hash",
        &["payload_hex"],
        &[Missing],
        1,
        1,
    ),
    named(
        "zk.shielded_transfer_public_inputs",
        "zk.shielded_transfer_public_inputs",
        &[
            "contract_name",
            "old_root",
            "input_nullifiers",
            "commitments",
            "payload_hashes",
        ],
        &[Missing, Missing, Missing, Missing, Missing],
        5,
        5,
    ),
    named(
        "zk.shielded_withdraw_public_inputs",
        "zk.shielded_withdraw_public_inputs",
        &[
            "contract_name",
            "old_root",
            "amount",
            "recipient",
            "input_nullifiers",
            "commitments",
            "payload_hashes",
        ],
        &[
            Missing, Missing, Missing, Missing, Missing, Missing, Missing,
        ],
        7,
        7,
    ),
];
#[cfg(test)]
pub(super) fn catalog_bindings() -> impl Iterator<Item = &'static str> {
    CATALOG.iter().map(|spec| spec.binding)
}

impl VmHostCallable {
    pub(super) fn value(self) -> VmValue {
        if matches!(self.binding(), "importlib.Func" | "importlib.Var") {
            return VmValue::TypeMarker(self.binding().into());
        }
        if self.binding().starts_with("Contract.") {
            VmValue::BoundMethod(Box::new(VmBoundMethod {
                receiver: VmValue::Builtin("Contract".into()),
                method: self.binding().rsplit('.').next().unwrap().into(),
            }))
        } else {
            VmValue::HostCallable(self)
        }
    }
    pub(crate) fn binding(self) -> &'static str {
        self.spec.binding
    }
    pub(super) fn syscall(self) -> &'static str {
        self.spec.syscall
    }
    pub(super) fn named(name: &str) -> Option<Self> {
        CATALOG
            .iter()
            .find(|spec| spec.binding == name)
            .map(|spec| Self { spec })
    }
    pub(super) fn for_syscall(id: &str, member: Option<&str>) -> Option<Self> {
        CATALOG
            .iter()
            .find(|spec| {
                spec.syscall == id
                    && member.is_none_or(|name| spec.binding.rsplit('.').next() == Some(name))
            })
            .or_else(|| CATALOG.iter().find(|spec| spec.syscall == id))
            .map(|spec| Self { spec })
    }
    pub(super) fn bind(
        self,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<Arguments, VmExecutionError> {
        if self.spec.variadic {
            return if kwargs.is_empty() {
                Ok((args, kwargs))
            } else {
                Err(self.invalid("accepts positional arguments only"))
            };
        }
        if args.len() > self.spec.positional {
            return Err(self.invalid("too many positional arguments"));
        }
        let mut bound = vec![None; self.spec.names.len()];
        for (index, value) in args.into_iter().enumerate() {
            bound[index] = Some(value);
        }
        for (name, value) in kwargs {
            let index = self
                .spec
                .names
                .iter()
                .position(|candidate| *candidate == name)
                .ok_or_else(|| self.invalid(&format!("unexpected keyword '{name}'")))?;
            if bound[index].is_some() {
                return Err(self.invalid(&format!("multiple values for '{name}'")));
            }
            bound[index] = Some(value);
        }
        self.finish_binding(bound)
    }
    fn finish_binding(
        self,
        mut bound: Vec<Option<VmValue>>,
    ) -> Result<Arguments, VmExecutionError> {
        for (index, default) in self.spec.defaults.iter().enumerate() {
            if *default == Missing && bound[index].is_none() {
                return Err(self.invalid(&format!("missing argument '{}'", self.spec.names[index])));
            }
        }
        let last = bound
            .iter()
            .rposition(Option::is_some)
            .map_or(0, |index| index + 1);
        let mut args = Vec::new();
        let mut kwargs = Vec::new();
        for index in 0..last {
            if index >= self.spec.keyword_output {
                if let Some(value) = bound[index].take() {
                    kwargs.push((self.spec.names[index].into(), value));
                }
            } else {
                args.push(
                    bound[index]
                        .take()
                        .unwrap_or_else(|| self.spec.defaults[index].value()),
                );
            }
        }
        Ok((args, kwargs))
    }
    fn invalid(self, message: &str) -> VmExecutionError {
        VmExecutionError::new(format!("{}(): {message}", self.binding()))
    }
}
impl DefaultValue {
    fn value(self) -> VmValue {
        match self {
            Missing | Null => VmValue::None,
            False => VmValue::Bool(false),
            Zero => vm_int(0),
            EmptyTuple => VmValue::Tuple(vec![]),
            Text(text) => VmValue::String(text.into()),
        }
    }
}

impl VmInstance {
    pub(super) fn call_host_callable(
        &mut self,
        callable: VmHostCallable,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let (args, kwargs) = callable.bind(args, kwargs)?;
        match callable.syscall() {
            "contract.interface.func" | "contract.interface.var" => {
                interface_descriptors::construct(callable.syscall(), &args, &kwargs)
            }
            "contract.enforce_interface" => self.enforce_interface(args, host),
            _ => self.dispatch_host_syscall(callable.syscall(), args, kwargs, host),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn catalog_lookup_defaults_and_variadic_calls_keep_public_semantics() {
        for (id, member, binding) in [
            (
                "contract.info",
                Some("contract_info"),
                "importlib.contract_info",
            ),
            ("contract.info", Some("get_info"), "Contract.get_info"),
            ("contract.info", None, "Contract.get_info"),
            (
                "hash.sha256_text",
                Some("sha256_text"),
                "hashlib.sha256_text",
            ),
        ] {
            assert_eq!(
                VmHostCallable::for_syscall(id, member).unwrap().binding(),
                binding
            );
        }
        assert!(VmHostCallable::for_syscall("not.admitted", Some("sha256_text")).is_none());
        let random = VmHostCallable::named("random.random").unwrap();
        assert_eq!(random.bind(vec![], vec![]).unwrap(), (vec![], vec![]));
        let indexed = VmHostCallable::named("indexed").unwrap();
        assert_eq!(
            indexed
                .bind(
                    vec![
                        VmValue::Builtin("int".into()),
                        VmValue::Builtin("str".into())
                    ],
                    vec![]
                )
                .unwrap()
                .0,
            vec![
                VmValue::Builtin("int".into()),
                VmValue::Builtin("str".into())
            ]
        );
        assert!(indexed
            .bind(vec![], vec![("types".into(), VmValue::None)])
            .is_err());
        let delta = VmHostCallable::named("datetime.timedelta").unwrap();
        assert_eq!(
            delta
                .bind(vec![], vec![("days".into(), vm_int(2))])
                .unwrap()
                .0,
            vec![vm_int(0), vm_int(2)]
        );
    }

    #[test]
    fn internal_type_slot_is_narrow_and_external_diagnostics_keep_context() {
        let marker = VmValue::TypeMarker("Hash".into());
        let args = vec![VmValue::String("state".into()), marker.clone()];
        assert_eq!(
            host_arguments("contract.interface.var", args, vec![])
                .unwrap()
                .0,
            vec![
                VmValue::String("state".into()),
                VmValue::String("Hash".into())
            ]
        );
        assert!(host_arguments("random.seed", vec![marker], vec![]).is_err());
        assert!(host_arguments(
            "contract.interface.var",
            vec![
                VmValue::String("state".into()),
                VmValue::Builtin("int".into())
            ],
            vec![]
        )
        .is_err());
        let bound = VmValue::BoundMethod(Box::new(VmBoundMethod {
            receiver: VmValue::List(vec![]),
            method: "append".into(),
        }));
        assert_eq!(
            bound.external_value().unwrap_err().to_string(),
            "bound methods cannot cross the VM boundary"
        );
        assert_eq!(
            crate::heap::validate_contract_values(std::iter::once(&bound))
                .unwrap_err()
                .to_string(),
            "bound methods cannot cross contract boundaries"
        );
    }

    #[test]
    fn catalog_binds_keywords_without_losing_alias_spelling() {
        let hash = VmHostCallable::named("hashlib.sha3_text").unwrap();
        assert_eq!(
            hash.bind(
                vec![],
                vec![("value".into(), VmValue::String("abc".into()))]
            )
            .unwrap()
            .0,
            vec![VmValue::String("abc".into())]
        );
        assert!(hash.bind(vec![], vec![]).is_err());
        assert!(hash
            .bind(vec![VmValue::None], vec![("value".into(), VmValue::None)])
            .is_err());
        for (binding, key, wrong) in [
            ("Contract.get_info", "name", "contract"),
            ("importlib.contract_info", "contract", "name"),
        ] {
            let c = VmHostCallable::named(binding).unwrap();
            assert!(c.bind(vec![], vec![(key.into(), VmValue::None)]).is_ok());
            assert!(c.bind(vec![], vec![(wrong.into(), VmValue::None)]).is_err());
        }
    }
    #[test]
    fn internal_transport_keeps_keyword_only_fields_and_defaults() {
        let c = VmHostCallable::named("importlib.Func").unwrap();
        let (args, kwargs) = c
            .bind(
                vec![VmValue::String("f".into())],
                vec![("private".into(), VmValue::Bool(true))],
            )
            .unwrap();
        assert_eq!(
            args,
            vec![VmValue::String("f".into()), VmValue::Tuple(vec![])]
        );
        assert_eq!(kwargs, vec![("private".into(), VmValue::Bool(true))]);
        let deploy = VmHostCallable::named("Contract.deploy").unwrap();
        assert!(deploy.bind(vec![VmValue::None], vec![]).is_err());
        assert!(deploy
            .bind(
                vec![],
                vec![
                    ("name".into(), VmValue::None),
                    ("code".into(), VmValue::None),
                    ("driver".into(), VmValue::None)
                ]
            )
            .is_err());
    }
}

impl VmInstance {
    pub(super) fn host_callable_attribute(
        &mut self,
        value: &VmValue,
        name: &str,
        host: &mut dyn VmHost,
    ) -> Option<Result<VmValue, VmExecutionError>> {
        if !resolves_to!(value, VmValue::Builtin(_) | VmValue::ContractHandle(_)) {
            return None;
        }
        match value.snapshot() {
            VmValue::Builtin(module) if is_host_module(&module) => {
                self.host_module_attribute(&module, name)
            }
            VmValue::ContractHandle(handle) => {
                Some(self.contract_export_attribute(value, &handle.module, name, host))
            }
            _ => None,
        }
    }
    fn contract_export_attribute(
        &mut self,
        value: &VmValue,
        module: &str,
        name: &str,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let descriptor = if module == self.module.module_name {
            host.charge_execution_cost(self.public_callable_metadata_work())?;
            self.public_callable(name)
        } else {
            host.public_callable(module, name, self.context.clone())?
        };
        let descriptor = descriptor.ok_or_else(|| {
            VmExecutionError::new("module attribute is not an admitted public callable")
        })?;
        self.materialize_public_callable(value.clone(), descriptor, host)
    }

    fn host_module_attribute(
        &self,
        module: &str,
        name: &str,
    ) -> Option<Result<VmValue, VmExecutionError>> {
        let path = format!("{module}.{name}");
        if let Some(callable) = VmHostCallable::named(&path) {
            let result = if matches!(path.as_str(), "datetime.datetime" | "datetime.timedelta") {
                VmValue::TypeMarker(path)
            } else {
                callable.value()
            };
            return Some(Ok(result));
        }
        if module != "datetime" {
            return None;
        }
        Some(self.resolve_host_binding(time_constant_binding(name)?))
    }
    pub(super) fn call_contract_export(
        &mut self,
        handle: VmContractHandle,
        method: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        host.call_contract_shared(VmContractCall {
            target: VmContractTarget::DynamicImport {
                module: handle.module,
            },
            function: method.into(),
            args,
            kwargs,
            caller_contract: self.context.this.clone(),
            signer: self.context.signer.clone(),
            entry: self.context.entry.clone(),
            submission_name: self.context.submission_name.clone(),
            now: self.context.now.clone(),
            block_num: self.context.block_num.clone(),
            block_hash: self.context.block_hash.clone(),
            chain_id: self.context.chain_id.clone(),
            input_hash: self.context.input_hash.clone(),
        })
    }
}

fn is_host_module(name: &str) -> bool {
    matches!(
        name,
        "hashlib" | "crypto" | "random" | "zk" | "importlib" | "datetime" | "Contract"
    )
}

pub(super) fn callback_needs_dispatch_charge(value: &VmValue) -> bool {
    match value.snapshot() {
        VmValue::HostCallable(_) => true,
        VmValue::TypeMarker(name) => VmHostCallable::named(&name).is_some(),
        VmValue::BoundMethod(bound) => bound_callback_needs_dispatch_charge(&bound),
        _ => false,
    }
}

fn bound_callback_needs_dispatch_charge(bound: &VmBoundMethod) -> bool {
    match bound.receiver.snapshot() {
        VmValue::DeploymentHandle
        | VmValue::ContractHandle(_)
        | VmValue::InterfaceDescriptor(_) => true,
        VmValue::Builtin(name) => matches!(
            name.as_str(),
            "Contract" | "importlib.Func" | "importlib.Var"
        ),
        VmValue::TypeMarker(name) => name == "datetime.datetime" && bound.method == "strptime",
        _ => false,
    }
}

/// Only the Var constructor has an internal type-descriptor slot. All other
/// host inputs must obey normal capability boundaries before Python conversion.
pub(super) fn host_arguments(
    syscall: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<Arguments, VmExecutionError> {
    let args = args
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            if syscall == "contract.interface.var" && index == 1 {
                internal_storage_type(&value)
            } else {
                value.external_value()
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let kwargs = kwargs
        .into_iter()
        .map(|(name, value)| Ok((name, value.external_value()?)))
        .collect::<Result<Vec<_>, VmExecutionError>>()?;
    Ok((args, kwargs))
}
fn internal_storage_type(value: &VmValue) -> Result<VmValue, VmExecutionError> {
    match value.snapshot() {
        VmValue::TypeMarker(name)
            if matches!(
                name.as_str(),
                "Variable" | "Hash" | "ForeignVariable" | "ForeignHash"
            ) =>
        {
            Ok(VmValue::String(name))
        }
        _ => Err(VmExecutionError::new(
            "importlib.Var() requires a storage class descriptor",
        )),
    }
}

fn time_constant_binding(name: &str) -> Option<&'static str> {
    Some(match name {
        "SECONDS" => "time.seconds",
        "MINUTES" => "time.minutes",
        "HOURS" => "time.hours",
        "DAYS" => "time.days",
        "WEEKS" => "time.weeks",
        _ => return None,
    })
}
