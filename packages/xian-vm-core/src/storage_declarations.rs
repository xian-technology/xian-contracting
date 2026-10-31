//! Evaluate ORM declaration arguments once, in authored order.
use super::*;

impl VmInstance {
    pub(super) fn storage_options(
        &mut self,
        args: &[Value],
        keywords: &[Value],
        host: &mut dyn VmHost,
    ) -> Result<HashMap<String, VmValue>, VmExecutionError> {
        let mut scope = self.globals.clone();
        let args = self.eval_call_arguments(args, &mut scope, host)?;
        let kwargs = self.eval_call_keywords(keywords, &mut scope, host, None)?;
        // The Python compiler supplies contract/name keywords to declarations.
        // Any authored positional argument binds contract a second time.
        if !args.is_empty()
            || kwargs
                .iter()
                .any(|(name, _)| matches!(name.as_str(), "contract" | "name"))
        {
            return Err(VmExecutionError::new(
                "duplicate storage contract/name argument",
            ));
        }
        Ok(kwargs.into_iter().collect())
    }
}

pub(super) fn foreign_key(options: &HashMap<String, VmValue>) -> Result<String, VmExecutionError> {
    let contract = options
        .get("foreign_contract")
        .ok_or_else(|| VmExecutionError::new("foreign storage requires foreign_contract"))?
        .as_string()?;
    let name = options
        .get("foreign_name")
        .ok_or_else(|| VmExecutionError::new("foreign storage requires foreign_name"))?
        .as_string()?;
    Ok(foreign_storage_key(&contract, &name))
}
