//! Validated module IR shared by the executions of one process.
//!
//! Parsing and validating a module's IR is pure: the same text always yields
//! the same module or the same error, and it is never charged to chi. An
//! execution therefore reuses the module parsed from byte-identical text
//! instead of parsing it again. A cached module is found only through its full
//! IR text, so a deploy, an update or a rollback that changes a contract's IR
//! can never reach a stale module, and what the cache holds (or evicts) never
//! changes a result. Failures are not cached; they are cheap to repeat.
use crate::{IrValidationError, ValidatedModuleIr};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Modules kept at most; the least recently used one is evicted first.
const MAX_MODULES: usize = 512;
/// IR text kept at most, in bytes. Larger modules are parsed but not kept.
const MAX_TEXT_BYTES: usize = 64 << 20;

struct CachedModule {
    ir_json: Box<str>,
    module: ValidatedModuleIr,
    last_used: u64,
}

pub(crate) struct ModuleCache {
    modules: HashMap<String, CachedModule>,
    max_modules: usize,
    max_text_bytes: usize,
    text_bytes: usize,
    clock: u64,
}

impl ModuleCache {
    pub(crate) fn new(max_modules: usize, max_text_bytes: usize) -> Self {
        Self {
            modules: HashMap::new(),
            max_modules,
            max_text_bytes,
            text_bytes: 0,
            clock: 0,
        }
    }

    /// The module parsed from `ir_json`, the IR stored for contract `name`.
    pub(crate) fn module(
        &mut self,
        name: &str,
        ir_json: &str,
    ) -> Result<ValidatedModuleIr, IrValidationError> {
        self.clock += 1;
        if let Some(cached) = self.modules.get_mut(name) {
            if *cached.ir_json == *ir_json {
                cached.last_used = self.clock;
                return Ok(cached.module.clone());
            }
        }
        let module = ValidatedModuleIr::parse(ir_json)?;
        self.keep(name, ir_json, &module);
        Ok(module)
    }

    fn keep(&mut self, name: &str, ir_json: &str, module: &ValidatedModuleIr) {
        self.forget(name);
        if ir_json.len() > self.max_text_bytes {
            return;
        }
        while self.modules.len() >= self.max_modules
            || self.text_bytes + ir_json.len() > self.max_text_bytes
        {
            self.evict_least_recently_used();
        }
        self.text_bytes += ir_json.len();
        self.modules.insert(
            name.to_owned(),
            CachedModule {
                ir_json: ir_json.into(),
                module: module.clone(),
                last_used: self.clock,
            },
        );
    }

    fn forget(&mut self, name: &str) {
        if let Some(removed) = self.modules.remove(name) {
            self.text_bytes -= removed.ir_json.len();
        }
    }

    fn evict_least_recently_used(&mut self) {
        let oldest = self
            .modules
            .iter()
            .min_by_key(|(_, cached)| cached.last_used)
            .map(|(name, _)| name.clone());
        if let Some(name) = oldest {
            self.forget(&name);
        }
    }
}

/// The process-wide cache behind [`ModuleCache::module`].
pub(crate) fn shared_module(
    name: &str,
    ir_json: &str,
) -> Result<ValidatedModuleIr, IrValidationError> {
    static SHARED: OnceLock<Mutex<ModuleCache>> = OnceLock::new();
    SHARED
        .get_or_init(|| Mutex::new(ModuleCache::new(MAX_MODULES, MAX_TEXT_BYTES)))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .module(name, ir_json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_module_ir;
    use std::sync::Arc;

    fn same(left: &ValidatedModuleIr, right: &ValidatedModuleIr) -> bool {
        Arc::ptr_eq(&left.shared(), &right.shared())
    }
    use serde_json::json;

    fn ir(name: &str, docstring: &str) -> String {
        json!({
            "ir_version": "xian_ir_v1",
            "vm_profile": "xian_vm_v1",
            "host_catalog_version": "xian_vm_v1_host_v1",
            "module_name": name,
            "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "docstring": docstring,
            "imports": [],
            "global_declarations": [],
            "functions": [],
            "module_body": [],
            "host_dependencies": []
        })
        .to_string()
    }

    #[test]
    fn identical_text_reuses_the_parsed_module() {
        let mut cache = ModuleCache::new(4, 1 << 20);
        let text = ir("con_a", "v1");

        let first = cache.module("con_a", &text).unwrap();
        let second = cache.module("con_a", &text.clone()).unwrap();

        assert!(same(&first, &second));
        assert_eq!(*first, parse_module_ir(&text).unwrap());
    }

    #[test]
    fn changed_text_for_a_contract_is_parsed_again() {
        let mut cache = ModuleCache::new(4, 1 << 20);
        let old = cache.module("con_a", &ir("con_a", "v1")).unwrap();

        let new = cache.module("con_a", &ir("con_a", "v2")).unwrap();
        let back = cache.module("con_a", &ir("con_a", "v1")).unwrap();

        assert_eq!(new.docstring.as_deref(), Some("v2"));
        assert_eq!(back.docstring.as_deref(), Some("v1"));
        assert!(!same(&old, &back));
        assert_eq!(cache.modules.len(), 1);
        assert_eq!(cache.text_bytes, ir("con_a", "v1").len());
    }

    #[test]
    fn invalid_text_fails_like_a_fresh_parse_every_time() {
        let mut cache = ModuleCache::new(4, 1 << 20);
        let valid = cache.module("con_a", &ir("con_a", "v1")).unwrap();
        let invalid = ir("con_a", "v1").replace("xian_ir_v1", "xian_ir_v0");

        let error = cache.module("con_a", &invalid).unwrap_err();

        assert_eq!(error, parse_module_ir(&invalid).unwrap_err());
        assert_eq!(cache.module("con_a", &invalid).unwrap_err(), error);
        assert_eq!(cache.text_bytes, ir("con_a", "v1").len());
        assert!(same(
            &cache.module("con_a", &ir("con_a", "v1")).unwrap(),
            &valid
        ));
    }

    #[test]
    fn the_least_recently_used_module_is_evicted_at_the_count_limit() {
        let mut cache = ModuleCache::new(2, 1 << 20);
        let a = cache.module("con_a", &ir("con_a", "a")).unwrap();
        cache.module("con_b", &ir("con_b", "b")).unwrap();
        assert!(same(&a, &cache.module("con_a", &ir("con_a", "a")).unwrap()));

        cache.module("con_c", &ir("con_c", "c")).unwrap();

        let mut kept = cache.modules.keys().cloned().collect::<Vec<_>>();
        kept.sort();
        assert_eq!(kept, ["con_a", "con_c"]);
    }

    #[test]
    fn the_text_limit_bounds_what_is_kept() {
        let size = ir("con_a", "a").len();
        let mut cache = ModuleCache::new(8, 2 * size);
        cache.module("con_a", &ir("con_a", "a")).unwrap();
        cache.module("con_b", &ir("con_b", "b")).unwrap();
        cache.module("con_c", &ir("con_c", "c")).unwrap();
        assert_eq!(cache.modules.len(), 2);
        assert_eq!(cache.text_bytes, 2 * size);

        let oversized = ir("con_big", &"x".repeat(2 * size));
        let module = cache.module("con_big", &oversized).unwrap();

        assert_eq!(module.module_name, "con_big");
        assert!(cache.modules.get("con_big").is_none());
        assert_eq!(cache.modules.len(), 2);
    }

    #[test]
    fn the_shared_cache_parses_like_parse_module_ir() {
        let text = ir("con_shared_probe", "shared");

        let first = shared_module("con_shared_probe", &text).unwrap();
        let second = shared_module("con_shared_probe", &text).unwrap();

        assert!(same(&first, &second));
        assert_eq!(*first, parse_module_ir(&text).unwrap());
    }
}
