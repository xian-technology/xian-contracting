//! The contracts' IR as the node prepares it, read once per run.
// The browser build runs single transactions: block-only parts are unused there.
#![cfg_attr(not(feature = "python-extension"), allow(dead_code))]
use super::IR_KEY;
use crate::module_cache::shared_module;
use crate::state_view::StateView;
use crate::{ValidatedModuleIr, VmExecutionError, VmValue, XIAN_VM_V2_PROFILE};
use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

/// Loading precedes contract instructions, so the transaction must pay before
/// parsing IR, regardless of whether the process cache already holds it.
/// These aggregate limits also apply to unmetered system execution.
const MAX_LOADED_MODULES: usize = 512;
const MAX_LOADED_IR_BYTES: usize = 16 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct ModuleLoads {
    names: HashMap<String, usize>,
    bytes: usize,
}

impl ModuleLoads {
    pub(crate) fn observe(
        &mut self,
        name: &str,
        ir: &Ir,
        charges: &mut super::HostCharges,
    ) -> Result<(), VmExecutionError> {
        let bytes = match ir {
            Ir::Text(cached) => cached.text.len(),
            _ => 0,
        };
        let previous = self.names.get(name).copied();
        if previous.is_some_and(|previous| previous >= bytes) {
            return Ok(());
        }
        // A name can be inspected while absent, then deployed and loaded by
        // its constructor. Count and price the newly available IR as well.
        let additional = bytes - previous.unwrap_or(0);
        self.require_capacity(previous.is_none(), additional)?;
        if charges.metered() {
            let key_bytes = if previous.is_none() {
                name.len() + 1 + super::IR_KEY.len()
            } else {
                0
            };
            let read_bytes = additional + key_bytes;
            charges.record(read_bytes as u64 * crate::metering::VM_READ_COST_PER_BYTE)?;
        }
        self.bytes += additional;
        self.names.insert(name.to_owned(), bytes);
        Ok(())
    }

    fn require_capacity(&self, new_name: bool, bytes: usize) -> Result<(), VmExecutionError> {
        if new_name && self.names.len() >= MAX_LOADED_MODULES {
            return Err(VmExecutionError::new(format!(
                "module graph exceeds {MAX_LOADED_MODULES} modules"
            )));
        }
        if bytes > MAX_LOADED_IR_BYTES.saturating_sub(self.bytes) {
            return Err(VmExecutionError::new(format!(
                "module graph exceeds {MAX_LOADED_IR_BYTES} IR bytes"
            )));
        }
        Ok(())
    }
}

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
/// (state may change between runs).
#[derive(Default)]
struct ModuleReads {
    entries: HashMap<String, Ir>,
    bytes: usize,
}

impl ModuleReads {
    fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0;
    }

    fn forget(&mut self, name: &str) {
        if let Some(ir) = self.entries.remove(name) {
            self.bytes -= cached_bytes(name, &ir);
        }
    }

    fn keep(&mut self, name: &str, ir: Ir) {
        let bytes = cached_bytes(name, &ir);
        if bytes > MAX_LOADED_IR_BYTES {
            return;
        }
        if self.entries.len() >= MAX_LOADED_MODULES || self.bytes + bytes > MAX_LOADED_IR_BYTES {
            self.clear();
        }
        self.bytes += bytes;
        self.entries.insert(name.to_owned(), ir);
    }
}

fn cached_bytes(name: &str, ir: &Ir) -> usize {
    name.len()
        + match ir {
            Ir::Text(cached) => cached.text.len(),
            _ => 0,
        }
}

#[derive(Default)]
pub(crate) struct Modules(RefCell<ModuleReads>);

impl Modules {
    pub(crate) fn clear(&self) {
        self.0.borrow_mut().clear();
    }

    pub(crate) fn forget(&self, key: &str) {
        if let Some(name) = key.strip_suffix(&format!(".{IR_KEY}")) {
            self.0.borrow_mut().forget(name);
        }
    }

    /// The IR of `name`, read as `Driver.get` reads it.
    pub(crate) fn ir(&self, view: &StateView, name: &str) -> Result<Ir, String> {
        if let Some(ir) = self.0.borrow().entries.get(name) {
            return Ok(ir.clone());
        }
        let ir = Ir::of(view.get(&format!("{name}.{IR_KEY}"))?);
        self.0.borrow_mut().keep(name, ir.clone());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_state::BlockState;
    use crate::committed_store::CommittedStore;
    use crate::memory_store::MemoryStore;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct CountedStore {
        store: MemoryStore,
        reads: AtomicUsize,
    }

    impl CommittedStore for CountedStore {
        fn read(&self, key: &[u8], read: &mut dyn FnMut(Option<&[u8]>)) -> Result<(), String> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.store.read(key, read)
        }

        fn scan_from(
            &self,
            start: &[u8],
            visit: &mut dyn FnMut(&[u8], &[u8]) -> Result<bool, String>,
        ) -> Result<(), String> {
            self.store.scan_from(start, visit)
        }
    }

    #[test]
    fn ir_read_charges_and_allowance_boundaries_are_transactional() {
        let ir = Ir::of(Some(VmValue::String("{}".to_owned())));
        let mut charges = super::super::HostCharges::new(crate::VmBudget::new(0), true, "con_x");
        let mut loads = ModuleLoads::default();
        loads.observe("con_x", &ir, &mut charges).unwrap();
        // 2 IR bytes plus the20-byte con_x.__xian_ir_v1__ key, at2 raw/byte.
        assert_eq!(charges.raw_cost(), 44);
        loads.observe("con_x", &ir, &mut charges).unwrap();
        assert_eq!(charges.raw_cost(), 44);
        loads.observe("con_y", &Ir::Absent, &mut charges).unwrap();
        assert_eq!(charges.raw_cost(), 84);
        loads.observe("con_y", &ir, &mut charges).unwrap();
        assert_eq!(charges.raw_cost(), 88);

        let mut unmetered = super::super::HostCharges::new(crate::VmBudget::new(0), false, "con_x");
        let mut bounded = ModuleLoads::default();
        for index in 0..MAX_LOADED_MODULES {
            bounded
                .observe(&format!("con_{index}"), &Ir::Absent, &mut unmetered)
                .unwrap();
        }
        assert!(bounded
            .observe("con_extra", &Ir::Absent, &mut unmetered)
            .is_err());
        assert_eq!(unmetered.raw_cost(), 0);

        let mut full_bytes = ModuleLoads::default();
        let larger = Ir::of(Some(VmValue::String("x".repeat(131_072))));
        for index in 0..127 {
            full_bytes
                .observe(&format!("con_previous_{index}"), &larger, &mut unmetered)
                .unwrap();
        }
        let smaller = Ir::of(Some(VmValue::String("x".repeat(131_070))));
        full_bytes
            .observe("con_previous_127", &smaller, &mut unmetered)
            .unwrap();
        full_bytes.observe("con_x", &ir, &mut unmetered).unwrap();
        assert!(full_bytes
            .observe("con_extra", &ir, &mut unmetered)
            .is_err());
    }

    #[test]
    fn the_block_read_cache_bounds_retained_modules_and_bytes() {
        for (count, text_bytes) in [(MAX_LOADED_MODULES + 1, 1), (17, 1024 * 1024)] {
            let encoded: Arc<[u8]> =
                Arc::from(format!("\"{}\"", "x".repeat(text_bytes)).into_bytes());
            let store = Arc::new(CountedStore {
                store: MemoryStore::from_entries((0..count).map(|index| {
                    (
                        format!("con_{index}.{}", super::super::IR_KEY).into_bytes(),
                        encoded.clone(),
                    )
                })),
                reads: AtomicUsize::new(0),
            });
            let view = StateView::new(store.clone(), Arc::new(Mutex::new(BlockState::default())));
            let modules = Modules::default();
            for index in 0..count {
                assert!(matches!(
                    modules.ir(&view, &format!("con_{index}")).unwrap(),
                    Ir::Text(_)
                ));
            }
            let before = store.reads.load(Ordering::Relaxed);
            assert!(matches!(modules.ir(&view, "con_0").unwrap(), Ir::Text(_)));
            assert_eq!(store.reads.load(Ordering::Relaxed), before + 1);
        }
    }
}
