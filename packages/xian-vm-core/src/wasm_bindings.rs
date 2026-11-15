//! The browser binding (`@xian-tech/vm`): a chain in memory (`sandbox`)
//! behind a JavaScript class. Requests and results cross as JSON strings;
//! see the package README for their shapes and the value encoding.
use crate::sandbox::{Sandbox, SandboxError};
use wasm_bindgen::prelude::*;

impl From<SandboxError> for JsError {
    fn from(error: SandboxError) -> Self {
        JsError::new(&error.0)
    }
}

fn utf8(bytes: &[u8]) -> Result<&str, JsError> {
    std::str::from_utf8(bytes).map_err(|error| JsError::new(&format!("snapshot: {error}")))
}

/// A chain in memory running the node's engine.
#[wasm_bindgen]
pub struct VmChain {
    sandbox: Sandbox,
}

#[wasm_bindgen]
impl VmChain {
    /// A new chain holding the submission contract (`CreateOptions` JSON).
    #[wasm_bindgen(constructor)]
    pub fn new(options_json: Option<String>) -> Result<VmChain, JsError> {
        let options = options_json.as_deref().unwrap_or("{}");
        Ok(Self {
            sandbox: Sandbox::create(options)?,
        })
    }

    /// An independent copy of the chain.
    #[wasm_bindgen(js_name = clone)]
    pub fn duplicate(&self) -> VmChain {
        Self {
            sandbox: self.sandbox.duplicate(),
        }
    }

    /// The committed state (`StateSnapshot` JSON).
    #[wasm_bindgen(js_name = exportState)]
    pub fn export_state(&self) -> String {
        self.sandbox.export()
    }

    /// The UTF-8 bytes of `exportState()`.
    #[wasm_bindgen(js_name = exportStateBytes)]
    pub fn export_state_bytes(&self) -> Vec<u8> {
        self.sandbox.export().into_bytes()
    }

    /// A chain holding a `StateSnapshot`.
    #[wasm_bindgen(js_name = importState)]
    pub fn import_state(snapshot: &str) -> Result<VmChain, JsError> {
        Ok(Self {
            sandbox: Sandbox::import(snapshot)?,
        })
    }

    /// A chain holding the UTF-8 bytes of a `StateSnapshot`.
    #[wasm_bindgen(js_name = importStateBytes)]
    pub fn import_state_bytes(snapshot: &[u8]) -> Result<VmChain, JsError> {
        Self::import_state(utf8(snapshot)?)
    }

    /// Run a `DeployRequest`; returns the `TxOutcome` JSON.
    pub fn deploy(&self, request_json: &str) -> Result<String, JsError> {
        Ok(self.sandbox.deploy(request_json)?)
    }

    /// Run a `CallRequest`; returns the `TxOutcome` JSON.
    pub fn call(&self, request_json: &str) -> Result<String, JsError> {
        Ok(self.sandbox.call(request_json)?)
    }

    /// The wire JSON text at `key`, or undefined.
    pub fn get(&self, key: &str) -> Option<String> {
        self.sandbox.get(key)
    }

    /// `[[key, wireText], ...]` under `prefix`, in key order.
    pub fn items(&self, prefix: &str, limit: Option<u32>) -> String {
        self.sandbox
            .items(prefix, limit.map(|limit| limit as usize))
    }

    /// Store a wire JSON text at `key`, or delete the key (undefined).
    #[wasm_bindgen(js_name = setValue)]
    pub fn set_value(&self, key: &str, wire_text: Option<String>) -> Result<(), JsError> {
        Ok(self.sandbox.set_value(key, wire_text.as_deref())?)
    }

    /// Delete every key of contract `name`.
    #[wasm_bindgen(js_name = removeContract)]
    pub fn remove_contract(&self, name: &str) {
        self.sandbox.remove_contract(name)
    }

    /// The deployed contracts' names (JSON array).
    pub fn contracts(&self) -> String {
        self.sandbox.contracts()
    }

    /// `ContractInfo` JSON of contract `name`, or undefined.
    pub fn contract(&self, name: &str) -> Option<String> {
        self.sandbox.contract(name)
    }

    /// The hex state root over every key not starting with `__`.
    #[wasm_bindgen(js_name = stateRoot)]
    pub fn state_root(&self) -> Result<String, JsError> {
        Ok(self.sandbox.state_root()?)
    }
}

/// The engine's versions (JSON).
#[wasm_bindgen(js_name = runtimeInfo)]
pub fn runtime_info() -> String {
    crate::sandbox::runtime_info()
}

/// The canonical decimal text the wire format requires (`"1.50"` -> `"1.5"`).
#[wasm_bindgen(js_name = canonicalDecimal)]
pub fn canonical_decimal(text: &str) -> Result<String, JsError> {
    xian_numeric::canonical_decimal(text).map_err(JsError::new)
}
