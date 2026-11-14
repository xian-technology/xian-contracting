//! The contracts' IR as the node prepares it, read once per run.
use super::IR_KEY;
use crate::module_cache::shared_module;
use crate::state_view::StateView;
use crate::{ValidatedModuleIr, VmValue, XIAN_VM_V2_PROFILE};
use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

/// What a contract's IR key holds.
#[derive(Clone)]
pub(crate) enum Ir {
    /// Missing (or null).
    Absent,
    /// A value that is not a non-empty string: no runnable module.
    Other,
    Text(Rc<CachedModule>),
}

impl Ir {
    /// The IR a stored value holds, as `Driver.get` reads it.
    pub(super) fn of(value: Option<VmValue>) -> Self {
        match value {
            None | Some(VmValue::None) => Self::Absent,
            Some(VmValue::String(text)) if !text.is_empty() => Self::Text(Rc::new(CachedModule {
                text,
                validated: OnceCell::new(),
            })),
            Some(_) => Self::Other,
        }
    }
}

/// A contract's IR text and, once needed, its validated module.
pub(crate) struct CachedModule {
    pub(crate) text: String,
    validated: OnceCell<Result<ValidatedModuleIr, String>>,
}

impl CachedModule {
    pub(crate) fn validated(&self, name: &str) -> Result<ValidatedModuleIr, String> {
        self.validated
            .get_or_init(|| shared_module(name, &self.text).map_err(|error| error.to_string()))
            .clone()
    }
}

/// The IR of the contracts one run read, by contract name, so a large IR is
/// decoded and validated once per run. Only a write to an IR key changes
/// it: the run's own staging forgets such keys, and every run starts empty
/// (the Python path writes between runs).
#[derive(Default)]
pub(crate) struct Modules(RefCell<HashMap<String, Ir>>);

impl Modules {
    pub(crate) fn clear(&self) {
        self.0.borrow_mut().clear();
    }

    pub(crate) fn forget(&self, key: &str) {
        if let Some(name) = key.strip_suffix(&format!(".{IR_KEY}")) {
            self.0.borrow_mut().remove(name);
        }
    }

    /// The IR of `name`, read as `Driver.get` reads it.
    pub(crate) fn ir(&self, view: &StateView, name: &str) -> Result<Ir, String> {
        if let Some(ir) = self.0.borrow().get(name) {
            return Ok(ir.clone());
        }
        let ir = Ir::of(view.get(&format!("{name}.{IR_KEY}"))?);
        self.0.borrow_mut().insert(name.to_owned(), ir.clone());
        Ok(ir)
    }
}

/// The module `name` as the node prepares it: `None` for an IR that is not
/// a valid xian_vm_v2 module. Whether the chain lets a module that uses zk
/// host syscalls run is the caller's check (`features`).
pub(crate) fn runnable(name: &str, cached: &CachedModule) -> Option<ValidatedModuleIr> {
    let module = cached.validated(name).ok()?;
    (module.vm_profile == XIAN_VM_V2_PROFILE).then_some(module)
}

/// `module_ir_uses_runtime_feature(module_ir, "zk")`.
pub(crate) fn uses_zk(module: &ValidatedModuleIr) -> bool {
    module.host_dependencies.iter().any(|dependency| {
        dependency.category == "zk"
            || dependency.id.starts_with("zk.")
            || dependency.binding.starts_with("zk.")
    })
}

/// Whether `module` exports `function`.
pub(crate) fn exports(module: &ValidatedModuleIr, function: &str) -> bool {
    module
        .functions
        .iter()
        .any(|candidate| candidate.visibility == "export" && candidate.name == function)
}
