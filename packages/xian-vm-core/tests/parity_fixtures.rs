use num_bigint::BigInt;
use num_traits::ToPrimitive;
use serde_json::{Map, Value};
use std::env;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use xian_vm_core::{
    ModuleIr, VmContractCall, VmContractTarget, VmDateTime, VmDecimal, VmEvent, VmExecutionContext,
    VmExecutionError, VmHost, VmInstance, VmTimeDelta, VmValue,
};
use xian_zk::{
    shielded_command_binding_hex, shielded_command_execution_tag_hex,
    shielded_command_nullifier_digest_hex, shielded_output_payload_hash_hex,
    shielded_output_payload_hash_hexes,
};

struct ModuleHarness {
    instance: VmInstance,
    owner: Option<String>,
}

#[derive(Default)]
struct ParityHarness {
    modules: HashMap<String, ModuleHarness>,
    events: Vec<VmEvent>,
}

impl ParityHarness {
    fn from_fixture(fixture: &Map<String, Value>) -> Self {
        let mut harness = Self::default();

        if let Some(modules) = fixture.get("modules").and_then(Value::as_array) {
            for module in modules {
                let module = module
                    .as_object()
                    .expect("fixture module should be an object");
                let module_name = module
                    .get("module_name")
                    .and_then(Value::as_str)
                    .expect("fixture module_name should be a string");
                let module_ir: ModuleIr = serde_json::from_value(
                    module
                        .get("ir")
                        .cloned()
                        .expect("fixture module should include IR"),
                )
                .expect("module IR should deserialize");
                let mut instance = VmInstance::new(module_ir, VmExecutionContext::default())
                    .expect("module should initialize");
                apply_initial_state(
                    &mut instance,
                    module
                        .get("initial_state")
                        .and_then(Value::as_object)
                        .expect("fixture module should include initial_state"),
                );
                harness.modules.insert(
                    module_name.to_owned(),
                    ModuleHarness {
                        instance,
                        owner: module
                            .get("owner")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                    },
                );
            }
            harness.sync_foreign_storage_views();
            return harness;
        }

        let module_name = fixture
            .get("module_name")
            .and_then(Value::as_str)
            .expect("legacy fixture should include module_name");
        let module_ir: ModuleIr = serde_json::from_value(
            fixture
                .get("ir")
                .cloned()
                .expect("legacy fixture should include IR"),
        )
        .expect("legacy IR should deserialize");
        let mut instance = VmInstance::new(module_ir, VmExecutionContext::default())
            .expect("legacy module should initialize");
        apply_initial_state(
            &mut instance,
            fixture
                .get("initial_state")
                .and_then(Value::as_object)
                .expect("legacy fixture should include initial_state"),
        );
        harness.modules.insert(
            module_name.to_owned(),
            ModuleHarness {
                instance,
                owner: fixture
                    .get("owner")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            },
        );
        harness.sync_foreign_storage_views();
        harness
    }

    fn invoke(
        &mut self,
        module_name: &str,
        function: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        context: VmExecutionContext,
    ) -> Result<VmValue, VmExecutionError> {
        self.invoke_module_call(module_name, function, args, kwargs, context)
    }

    fn invoke_module_call(
        &mut self,
        module_name: &str,
        function: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        mut context: VmExecutionContext,
    ) -> Result<VmValue, VmExecutionError> {
        let owner = self
            .modules
            .get(module_name)
            .and_then(|module| module.owner.clone());

        if let Some(owner) = &owner {
            if context.caller.as_deref() != Some(owner.as_str()) {
                return Err(VmExecutionError::new("Caller is not the owner!"));
            }
        }

        let mut module = self
            .modules
            .remove(module_name)
            .ok_or_else(|| VmExecutionError::new(format!("unknown module '{module_name}'")))?;

        context.this = Some(module_name.to_owned());
        context.owner = owner;

        let previous_context = module.instance.context().clone();
        *module.instance.context_mut() = context;
        let result = module.instance.call_function(self, function, args, kwargs);
        *module.instance.context_mut() = previous_context;

        self.modules.insert(module_name.to_owned(), module);
        self.sync_foreign_storage_views();
        result
    }

    fn sync_foreign_storage_views(&mut self) {
        let snapshots = self
            .modules
            .values()
            .map(|module| module.instance.storage_snapshot())
            .collect::<Vec<_>>();
        for module in self.modules.values_mut() {
            for snapshot in &snapshots {
                module.instance.apply_foreign_snapshot(snapshot);
            }
        }
    }

    fn collect_state(&self, expected_state: &Map<String, Value>, root_module: &str) -> Value {
        if expected_state.contains_key("variables") || expected_state.contains_key("hashes") {
            let module = self
                .modules
                .get(root_module)
                .expect("root module should exist");
            return collect_actual_state_for_module(&module.instance, expected_state);
        }

        Value::Object(Map::from_iter(expected_state.iter().map(
            |(module_name, state)| {
                let module = self
                    .modules
                    .get(module_name)
                    .unwrap_or_else(|| panic!("module '{}' missing in harness", module_name));
                (
                    module_name.clone(),
                    collect_actual_state_for_module(
                        &module.instance,
                        state
                            .as_object()
                            .expect("module state expectation should be an object"),
                    ),
                )
            },
        )))
    }

    fn module_exists(&self, module_name: &str) -> bool {
        self.modules.contains_key(module_name)
    }

    fn module_has_export(&self, module_name: &str, export_name: &str) -> bool {
        self.modules
            .get(module_name)
            .map(|module| module.instance.has_export(export_name))
            .unwrap_or(false)
    }
}

impl VmHost for ParityHarness {
    fn emit_event(&mut self, event: VmEvent) -> Result<(), VmExecutionError> {
        self.events.push(event);
        Ok(())
    }

    fn read_variable(
        &mut self,
        contract: &str,
        binding: &str,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        let direct = self
            .modules
            .get(contract)
            .and_then(|module| module.instance.get_variable(binding));
        if direct.is_some() {
            return Ok(direct);
        }
        let foreign_binding = format!("{contract}:{binding}");
        Ok(self
            .modules
            .values()
            .find_map(|module| module.instance.get_variable(&foreign_binding)))
    }

    fn read_hash(
        &mut self,
        contract: &str,
        binding: &str,
        key: &VmValue,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        let direct = self
            .modules
            .get(contract)
            .map(|module| module.instance.get_hash_value(binding, key))
            .transpose()?
            .flatten();
        if direct.is_some() {
            return Ok(direct);
        }
        let foreign_binding = format!("{contract}:{binding}");
        for module in self.modules.values() {
            if let Some(value) = module.instance.get_hash_value(&foreign_binding, key)? {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    fn call_contract(&mut self, call: VmContractCall) -> Result<VmValue, VmExecutionError> {
        let target_module = contract_target_module(&call.target).to_owned();
        let context_this = target_module.clone();
        self.invoke_module_call(
            &target_module,
            &call.function,
            call.args,
            call.kwargs,
            VmExecutionContext {
                this: Some(context_this),
                caller: call.caller_contract,
                signer: call.signer,
                owner: None,
                entry: call.entry,
                submission_name: call.submission_name,
                now: call.now,
                block_num: call.block_num,
                block_hash: call.block_hash,
                chain_id: call.chain_id,
            },
        )
    }

    fn handle_syscall(
        &mut self,
        syscall_id: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        match syscall_id {
            "contract.exists" => Ok(VmValue::Bool(
                self.module_exists(required_string_arg("module", &args, &kwargs, 0)?),
            )),
            "contract.has_export" => Ok(VmValue::Bool(self.module_has_export(
                required_string_arg("module", &args, &kwargs, 0)?,
                required_string_arg("export_name", &args, &kwargs, 1)?,
            ))),
            "zk.shielded_command_nullifier_digest" => Ok(VmValue::String(
                shielded_command_nullifier_digest_hex(&required_string_list_arg(
                    "input_nullifiers",
                    &args,
                    &kwargs,
                    0,
                )?)
                .map_err(|err| VmExecutionError::new(err.to_string()))?,
            )),
            "zk.shielded_command_binding" => Ok(VmValue::String(
                shielded_command_binding_hex(
                    required_string_arg("nullifier_digest", &args, &kwargs, 0)?,
                    required_string_arg("target_digest", &args, &kwargs, 1)?,
                    required_string_arg("payload_digest", &args, &kwargs, 2)?,
                    required_string_arg("relayer_digest", &args, &kwargs, 3)?,
                    required_string_arg("expiry_digest", &args, &kwargs, 4)?,
                    required_string_arg("chain_digest", &args, &kwargs, 5)?,
                    required_string_arg("entrypoint_digest", &args, &kwargs, 6)?,
                    required_string_arg("version_digest", &args, &kwargs, 7)?,
                    required_u64_arg("fee", &args, &kwargs, 8)?,
                    required_u64_arg("public_amount", &args, &kwargs, 9)?,
                )
                .map_err(|err| VmExecutionError::new(err.to_string()))?,
            )),
            "zk.shielded_command_execution_tag" => Ok(VmValue::String(
                shielded_command_execution_tag_hex(
                    required_string_arg("nullifier_digest", &args, &kwargs, 0)?,
                    required_string_arg("command_binding", &args, &kwargs, 1)?,
                )
                .map_err(|err| VmExecutionError::new(err.to_string()))?,
            )),
            "zk.shielded_output_payload_hash" => {
                Ok(VmValue::String(shielded_output_payload_hash_hex(
                    required_string_arg("payload_hex", &args, &kwargs, 0)?,
                )))
            }
            "zk.shielded_output_payload_hashes" => Ok(VmValue::List(
                shielded_output_payload_hash_hexes(&required_string_list_arg(
                    "payload_hexes",
                    &args,
                    &kwargs,
                    0,
                )?)
                .into_iter()
                .map(VmValue::String)
                .collect(),
            )),
            other => Err(VmExecutionError::new(format!(
                "unsupported host syscall '{other}'"
            ))),
        }
    }
}

#[test]
fn curated_python_runtime_parity_fixtures_match_rust_vm() {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let fixture_filter = env::var("XIAN_VM_FIXTURE_FILTER").ok();
    let mut files = fs::read_dir(&fixture_dir)
        .expect("fixture directory should exist")
        .map(|entry| entry.expect("fixture entry should load").path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .filter(|path| {
            fixture_filter.as_ref().is_none_or(|filter| {
                path.file_name()
                    .and_then(|value| value.to_str())
                    .map(|name| name.contains(filter))
                    .unwrap_or(false)
            })
        })
        .collect::<Vec<_>>();
    files.sort();
    assert!(!files.is_empty(), "expected at least one parity fixture");

    for path in files {
        run_fixture(&path);
    }
}

fn run_fixture(path: &PathBuf) {
    let fixture_value: Value =
        serde_json::from_str(&fs::read_to_string(path).expect("fixture should be readable"))
            .expect("fixture JSON should parse");
    let fixture = fixture_value
        .as_object()
        .expect("fixture root should be an object");

    let call = fixture
        .get("call")
        .and_then(Value::as_object)
        .expect("fixture should include call object");
    let root_module = call
        .get("module")
        .and_then(Value::as_str)
        .or_else(|| fixture.get("module_name").and_then(Value::as_str))
        .expect("fixture should identify call module");
    let function = call
        .get("function")
        .and_then(Value::as_str)
        .expect("call.function should be a string");
    let args = call
        .get("args")
        .and_then(Value::as_array)
        .map(|values| values.iter().map(json_to_vm_value).collect::<Vec<_>>())
        .unwrap_or_default();
    let kwargs = call
        .get("kwargs")
        .and_then(Value::as_object)
        .map(|values| {
            let mut kwargs = values
                .iter()
                .map(|(key, value)| (key.clone(), json_to_vm_value(value)))
                .collect::<Vec<_>>();
            kwargs.sort_by(|left, right| left.0.cmp(&right.0));
            kwargs
        })
        .unwrap_or_default();
    let context = json_to_context(
        fixture
            .get("context")
            .and_then(Value::as_object)
            .expect("fixture should include context object"),
    );

    let mut harness = ParityHarness::from_fixture(fixture);
    let result = harness
        .invoke(root_module, function, args, kwargs, context)
        .unwrap_or_else(|err| panic!("fixture {} failed: {err}", path.display()));

    let expected = fixture
        .get("expected")
        .and_then(Value::as_object)
        .expect("fixture should include expected object");

    assert_eq!(
        vm_value_to_json(&result),
        expected
            .get("result")
            .cloned()
            .expect("expected.result missing"),
        "result mismatch for {}",
        path.display()
    );

    let actual_state = harness.collect_state(
        expected
            .get("state")
            .and_then(Value::as_object)
            .expect("expected.state missing"),
        root_module,
    );
    assert_eq!(
        actual_state,
        expected
            .get("state")
            .cloned()
            .expect("expected.state missing"),
        "state mismatch for {}",
        path.display()
    );

    let actual_events = Value::Array(harness.events.iter().map(vm_event_to_json).collect());
    assert_eq!(
        actual_events,
        expected
            .get("events")
            .cloned()
            .expect("expected.events missing"),
        "event mismatch for {}",
        path.display()
    );
}

fn apply_initial_state(instance: &mut VmInstance, initial_state: &Map<String, Value>) {
    for variable in initial_state
        .get("variables")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let variable = variable
            .as_object()
            .expect("variable seed should be an object");
        instance
            .set_variable_state(
                variable
                    .get("binding")
                    .and_then(Value::as_str)
                    .expect("variable seed binding should be a string"),
                json_to_vm_value(
                    variable
                        .get("value")
                        .expect("variable seed should include value"),
                ),
            )
            .expect("variable seed should apply");
    }

    for hash in initial_state
        .get("hashes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let hash = hash.as_object().expect("hash seed should be an object");
        let binding = hash
            .get("binding")
            .and_then(Value::as_str)
            .expect("hash seed binding should be a string");
        for entry in hash
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let entry = entry.as_object().expect("hash entry should be an object");
            instance
                .set_hash_value(
                    binding,
                    &json_to_hash_key(entry.get("key").expect("hash entry key missing")),
                    json_to_vm_value(entry.get("value").expect("hash entry value missing")),
                )
                .expect("hash seed should apply");
        }
    }

    for variable in initial_state
        .get("foreign_variables")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let variable = variable
            .as_object()
            .expect("foreign variable seed should be an object");
        instance.set_foreign_variable(
            variable
                .get("contract")
                .and_then(Value::as_str)
                .expect("foreign variable contract missing"),
            variable
                .get("name")
                .and_then(Value::as_str)
                .expect("foreign variable name missing"),
            json_to_vm_value(
                variable
                    .get("value")
                    .expect("foreign variable value missing"),
            ),
        );
    }

    for hash in initial_state
        .get("foreign_hashes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let hash = hash
            .as_object()
            .expect("foreign hash seed should be an object");
        let contract = hash
            .get("contract")
            .and_then(Value::as_str)
            .expect("foreign hash contract missing");
        let name = hash
            .get("name")
            .and_then(Value::as_str)
            .expect("foreign hash name missing");
        for entry in hash
            .get("entries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let entry = entry
                .as_object()
                .expect("foreign hash entry should be an object");
            instance
                .set_foreign_hash_value(
                    contract,
                    name,
                    &json_to_hash_key(entry.get("key").expect("foreign hash key missing")),
                    json_to_vm_value(entry.get("value").expect("foreign hash value missing")),
                )
                .expect("foreign hash seed should apply");
        }
    }
}

fn collect_actual_state_for_module(
    instance: &VmInstance,
    expected_state: &Map<String, Value>,
) -> Value {
    let mut state = Map::new();

    let variables = expected_state
        .get("variables")
        .and_then(Value::as_array)
        .map(|values| {
            Value::Array(
                values
                    .iter()
                    .map(|value| {
                        let value = value
                            .as_object()
                            .expect("expected variable should be an object");
                        let binding = value
                            .get("binding")
                            .and_then(Value::as_str)
                            .expect("expected variable binding missing");
                        Value::Object(Map::from_iter([
                            ("binding".to_owned(), Value::String(binding.to_owned())),
                            (
                                "value".to_owned(),
                                instance
                                    .get_variable(binding)
                                    .map(|value| vm_value_to_json(&value))
                                    .unwrap_or(Value::Null),
                            ),
                        ]))
                    })
                    .collect(),
            )
        })
        .unwrap_or_else(|| Value::Array(Vec::new()));
    state.insert("variables".to_owned(), variables);

    let hashes = expected_state
        .get("hashes")
        .and_then(Value::as_array)
        .map(|hashes| {
            Value::Array(
                hashes
                    .iter()
                    .map(|hash| {
                        let hash = hash.as_object().expect("expected hash should be an object");
                        let binding = hash
                            .get("binding")
                            .and_then(Value::as_str)
                            .expect("expected hash binding missing");
                        let entries = hash
                            .get("entries")
                            .and_then(Value::as_array)
                            .expect("expected hash entries missing");
                        Value::Object(Map::from_iter([
                            ("binding".to_owned(), Value::String(binding.to_owned())),
                            (
                                "entries".to_owned(),
                                Value::Array(
                                    entries
                                        .iter()
                                        .map(|entry| {
                                            let entry = entry
                                                .as_object()
                                                .expect("expected hash entry should be an object");
                                            let key_value = entry
                                                .get("key")
                                                .expect("expected hash key missing");
                                            Value::Object(Map::from_iter([
                                                ("key".to_owned(), key_value.clone()),
                                                (
                                                    "value".to_owned(),
                                                    instance
                                                        .get_hash_value(
                                                            binding,
                                                            &json_to_hash_key(key_value),
                                                        )
                                                        .expect("hash lookup should succeed")
                                                        .map(|value| vm_value_to_json(&value))
                                                        .unwrap_or(Value::Null),
                                                ),
                                            ]))
                                        })
                                        .collect(),
                                ),
                            ),
                        ]))
                    })
                    .collect(),
            )
        })
        .unwrap_or_else(|| Value::Array(Vec::new()));
    state.insert("hashes".to_owned(), hashes);

    Value::Object(state)
}

fn json_to_context(value: &Map<String, Value>) -> VmExecutionContext {
    VmExecutionContext {
        this: value.get("this").and_then(Value::as_str).map(str::to_owned),
        caller: value
            .get("caller")
            .and_then(Value::as_str)
            .map(str::to_owned),
        signer: value
            .get("signer")
            .and_then(Value::as_str)
            .map(str::to_owned),
        owner: value
            .get("owner")
            .and_then(Value::as_str)
            .map(str::to_owned),
        entry: value.get("entry").and_then(json_to_entry),
        submission_name: value
            .get("submission_name")
            .and_then(Value::as_str)
            .map(str::to_owned),
        now: json_to_vm_value(value.get("now").unwrap_or(&Value::Null)),
        block_num: json_to_vm_value(value.get("block_num").unwrap_or(&Value::Null)),
        block_hash: json_to_vm_value(value.get("block_hash").unwrap_or(&Value::Null)),
        chain_id: json_to_vm_value(value.get("chain_id").unwrap_or(&Value::Null)),
    }
}

fn json_to_entry(value: &Value) -> Option<(String, String)> {
    let values = value.as_array()?;
    if values.len() != 2 {
        return None;
    }
    Some((
        values[0].as_str()?.to_owned(),
        values[1].as_str()?.to_owned(),
    ))
}

fn json_to_hash_key(value: &Value) -> VmValue {
    match value {
        Value::Array(values) => VmValue::Tuple(values.iter().map(json_to_vm_value).collect()),
        other => json_to_vm_value(other),
    }
}

fn json_to_vm_value(value: &Value) -> VmValue {
    match value {
        Value::Null => VmValue::None,
        Value::Bool(value) => VmValue::Bool(*value),
        Value::Number(value) => {
            if let Some(int_value) = value.as_i64() {
                VmValue::Int(int_value.into())
            } else if let Some(int_value) = value.as_u64() {
                VmValue::Int(int_value.into())
            } else {
                VmValue::Float(value.as_f64().expect("float value should decode"))
            }
        }
        Value::String(value) => VmValue::String(value.clone()),
        Value::Array(values) => VmValue::List(values.iter().map(json_to_vm_value).collect()),
        Value::Object(values) => {
            if values.get("__vm_type__").and_then(Value::as_str) == Some("int") {
                let literal = values
                    .get("value")
                    .and_then(Value::as_str)
                    .expect("int fixture value should be a string");
                return VmValue::Int(
                    BigInt::from_str(literal).expect("int fixture value should parse"),
                );
            }
            if values.get("__vm_type__").and_then(Value::as_str) == Some("decimal") {
                let literal = values
                    .get("value")
                    .and_then(Value::as_str)
                    .expect("decimal fixture value should be a string");
                return VmValue::Decimal(
                    VmDecimal::from_str_literal(literal)
                        .expect("decimal fixture value should parse"),
                );
            }
            if values.get("__vm_type__").and_then(Value::as_str) == Some("datetime") {
                let parts = values
                    .get("parts")
                    .and_then(Value::as_array)
                    .expect("datetime fixture value should include parts");
                return VmValue::DateTime(
                    VmDateTime::new(
                        parts[0].as_i64().expect("datetime year should be i64"),
                        parts[1].as_i64().expect("datetime month should be i64"),
                        parts[2].as_i64().expect("datetime day should be i64"),
                        parts[3].as_i64().expect("datetime hour should be i64"),
                        parts[4].as_i64().expect("datetime minute should be i64"),
                        parts[5].as_i64().expect("datetime second should be i64"),
                        parts[6]
                            .as_i64()
                            .expect("datetime microsecond should be i64"),
                    )
                    .expect("datetime fixture value should parse"),
                );
            }
            if values.get("__vm_type__").and_then(Value::as_str) == Some("timedelta") {
                let seconds = values
                    .get("seconds")
                    .and_then(Value::as_i64)
                    .expect("timedelta fixture value should include seconds");
                return VmValue::TimeDelta(
                    VmTimeDelta::from_raw_seconds(seconds)
                        .expect("timedelta fixture value should parse"),
                );
            }
            VmValue::Dict(
                values
                    .iter()
                    .map(|(key, value)| (VmValue::String(key.clone()), json_to_vm_value(value)))
                    .collect(),
            )
        }
    }
}

fn vm_value_to_json(value: &VmValue) -> Value {
    match value {
        VmValue::None => Value::Null,
        VmValue::Bool(value) => Value::Bool(*value),
        VmValue::Int(value) => {
            if let Some(value) = value.to_i64() {
                Value::Number(value.into())
            } else if let Some(value) = value.to_u64() {
                Value::Number(value.into())
            } else {
                Value::Object(Map::from_iter([
                    ("__vm_type__".to_owned(), Value::String("int".to_owned())),
                    ("value".to_owned(), Value::String(value.to_string())),
                ]))
            }
        }
        VmValue::Float(value) => {
            Value::Number(serde_json::Number::from_f64(*value).expect("float should serialize"))
        }
        VmValue::Decimal(value) => Value::Object(Map::from_iter([
            (
                "__vm_type__".to_owned(),
                Value::String("decimal".to_owned()),
            ),
            ("value".to_owned(), Value::String(value.to_string())),
        ])),
        VmValue::DateTime(value) => Value::Object(Map::from_iter([
            (
                "__vm_type__".to_owned(),
                Value::String("datetime".to_owned()),
            ),
            (
                "parts".to_owned(),
                Value::Array(vec![
                    Value::Number(value.year().into()),
                    Value::Number(value.month().into()),
                    Value::Number(value.day().into()),
                    Value::Number(value.hour().into()),
                    Value::Number(value.minute().into()),
                    Value::Number(value.second().into()),
                    Value::Number(value.microsecond().into()),
                ]),
            ),
        ])),
        VmValue::TimeDelta(value) => Value::Object(Map::from_iter([
            (
                "__vm_type__".to_owned(),
                Value::String("timedelta".to_owned()),
            ),
            ("seconds".to_owned(), Value::Number(value.seconds().into())),
        ])),
        VmValue::String(value) => Value::String(value.clone()),
        VmValue::List(values) => Value::Array(values.iter().map(vm_value_to_json).collect()),
        VmValue::Tuple(values) => Value::Array(values.iter().map(vm_value_to_json).collect()),
        VmValue::Dict(entries) => {
            Value::Object(Map::from_iter(entries.iter().map(|(key, value)| {
                let key = match key {
                    VmValue::String(value) => value.clone(),
                    other => other.to_string(),
                };
                (key, vm_value_to_json(value))
            })))
        }
        VmValue::ContractHandle(handle) => Value::String(handle.module.clone()),
        VmValue::StorageRef(storage) => Value::String(storage.binding.clone()),
        VmValue::EventRef(event) => Value::String(event.event_name.clone()),
        VmValue::Builtin(name) => Value::String(name.clone()),
        VmValue::FunctionRef(name) => Value::String(name.clone()),
        VmValue::TypeMarker(name) => Value::String(name.clone()),
    }
}

fn vm_event_to_json(event: &VmEvent) -> Value {
    Value::Object(Map::from_iter([
        ("contract".to_owned(), Value::String(event.contract.clone())),
        ("event".to_owned(), Value::String(event.event.clone())),
        ("signer".to_owned(), vm_value_to_json(&event.signer)),
        ("caller".to_owned(), vm_value_to_json(&event.caller)),
        (
            "data_indexed".to_owned(),
            Value::Object(Map::from_iter(
                event
                    .data_indexed
                    .iter()
                    .map(|(key, value)| (key.clone(), vm_value_to_json(value))),
            )),
        ),
        (
            "data".to_owned(),
            Value::Object(Map::from_iter(
                event
                    .data
                    .iter()
                    .map(|(key, value)| (key.clone(), vm_value_to_json(value))),
            )),
        ),
    ]))
}

fn contract_target_module(target: &VmContractTarget) -> &str {
    match target {
        VmContractTarget::StaticImport { module, .. }
        | VmContractTarget::DynamicImport { module }
        | VmContractTarget::LocalHandle { module, .. }
        | VmContractTarget::FactoryCall { module, .. } => module,
    }
}

fn required_argument<'a>(
    name: &str,
    args: &'a [VmValue],
    kwargs: &'a [(String, VmValue)],
    position: usize,
) -> Result<&'a VmValue, VmExecutionError> {
    if let Some(value) = args.get(position) {
        return Ok(value);
    }
    kwargs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
        .ok_or_else(|| VmExecutionError::new(format!("missing required argument '{name}'")))
}

fn required_string_arg<'a>(
    name: &str,
    args: &'a [VmValue],
    kwargs: &'a [(String, VmValue)],
    position: usize,
) -> Result<&'a str, VmExecutionError> {
    match required_argument(name, args, kwargs, position)? {
        VmValue::String(value) => Ok(value),
        other => Err(VmExecutionError::new(format!(
            "argument '{name}' must be a string, got {}",
            vm_value_type_name(other)
        ))),
    }
}

fn required_u64_arg(
    name: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
    position: usize,
) -> Result<u64, VmExecutionError> {
    match required_argument(name, args, kwargs, position)? {
        VmValue::Int(value) => value
            .to_u64()
            .ok_or_else(|| VmExecutionError::new(format!("argument '{name}' must fit into u64"))),
        other => Err(VmExecutionError::new(format!(
            "argument '{name}' must be an integer, got {}",
            vm_value_type_name(other)
        ))),
    }
}

fn required_string_list_arg(
    name: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
    position: usize,
) -> Result<Vec<String>, VmExecutionError> {
    let value = required_argument(name, args, kwargs, position)?;
    let items = match value {
        VmValue::List(items) | VmValue::Tuple(items) => items,
        other => {
            return Err(VmExecutionError::new(format!(
                "argument '{name}' must be a sequence, got {}",
                vm_value_type_name(other)
            )))
        }
    };
    items
        .iter()
        .map(|item| match item {
            VmValue::String(value) => Ok(value.clone()),
            other => Err(VmExecutionError::new(format!(
                "argument '{name}' items must be strings, got {}",
                vm_value_type_name(other)
            ))),
        })
        .collect()
}

fn vm_value_type_name(value: &VmValue) -> &'static str {
    match value {
        VmValue::None => "NoneType",
        VmValue::Bool(_) => "bool",
        VmValue::Int(_) => "int",
        VmValue::Float(_) => "float",
        VmValue::Decimal(_) => "decimal",
        VmValue::DateTime(_) => "datetime",
        VmValue::TimeDelta(_) => "timedelta",
        VmValue::String(_) => "str",
        VmValue::List(_) => "list",
        VmValue::Tuple(_) => "tuple",
        VmValue::Dict(_) => "dict",
        VmValue::ContractHandle(_) => "contract_handle",
        VmValue::StorageRef(_) => "storage_ref",
        VmValue::EventRef(_) => "event_ref",
        VmValue::Builtin(_) => "builtin",
        VmValue::FunctionRef(_) => "function_ref",
        VmValue::TypeMarker(_) => "type_marker",
    }
}
