use pyo3::create_exception;
use pyo3::exceptions::PyAssertionError;
use pyo3::prelude::*;
use std::collections::HashMap;

const DEFAULT_COST: u64 = 4;
const MAX_STAMPS: u64 = 6_500_000;
const MAX_CALL_COUNT: u64 = 800_000;

create_exception!(
    xian_native_tracer,
    NativeStampExceededError,
    PyAssertionError
);
create_exception!(
    xian_native_tracer,
    NativeCallLimitExceededError,
    PyAssertionError
);

#[pyclass(unsendable)]
struct InstructionMeter {
    cost: u64,
    stamp_supplied: u64,
    call_count: u64,
    started: bool,
    instruction_costs: HashMap<usize, HashMap<u32, u64>>,
}

impl InstructionMeter {
    fn ensure_cost_limit(&mut self) -> PyResult<()> {
        if self.cost > self.stamp_supplied || self.cost > MAX_STAMPS {
            self.started = false;
            return Err(NativeStampExceededError::new_err(
                "The cost has exceeded the stamp supplied!",
            ));
        }
        Ok(())
    }
}

#[pymethods]
impl InstructionMeter {
    #[new]
    fn new() -> Self {
        Self {
            cost: 0,
            stamp_supplied: 0,
            call_count: 0,
            started: false,
            instruction_costs: HashMap::new(),
        }
    }

    fn start(&mut self) {
        self.cost = 0;
        self.call_count = 0;
        self.started = true;
    }

    fn stop(&mut self) {
        self.started = false;
    }

    fn reset(&mut self) {
        self.stop();
        self.cost = 0;
        self.stamp_supplied = 0;
        self.call_count = 0;
        self.instruction_costs.clear();
    }

    fn register_code(
        &mut self,
        code: &Bound<'_, PyAny>,
        offset_costs: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let key = code.as_ptr() as usize;
        let parsed: HashMap<u32, u64> = offset_costs.extract()?;
        self.instruction_costs.insert(key, parsed);
        Ok(())
    }

    fn set_stamp(&mut self, stamp: u64) {
        self.stamp_supplied = stamp;
    }

    fn add_cost(&mut self, new_cost: u64) -> PyResult<()> {
        self.cost = self.cost.saturating_add(new_cost);
        self.ensure_cost_limit()
    }

    fn instruction_callback(
        &mut self,
        code: &Bound<'_, PyAny>,
        instruction_offset: u32,
    ) -> PyResult<()> {
        self.call_count = self.call_count.saturating_add(1);
        if self.call_count > MAX_CALL_COUNT {
            self.started = false;
            return Err(NativeCallLimitExceededError::new_err(
                "Call count exceeded threshold! Infinite Loop?",
            ));
        }

        let code_id = code.as_ptr() as usize;
        let cost = self
            .instruction_costs
            .get(&code_id)
            .and_then(|table| table.get(&instruction_offset))
            .copied()
            .unwrap_or(DEFAULT_COST);
        self.cost = self.cost.saturating_add(cost);
        self.ensure_cost_limit()
    }

    fn get_stamp_used(&self) -> u64 {
        self.cost
    }

    fn is_started(&self) -> bool {
        self.started
    }
}

#[pymodule]
fn _native(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<InstructionMeter>()?;
    module.add(
        "NativeStampExceededError",
        py.get_type::<NativeStampExceededError>(),
    )?;
    module.add(
        "NativeCallLimitExceededError",
        py.get_type::<NativeCallLimitExceededError>(),
    )?;
    Ok(())
}
