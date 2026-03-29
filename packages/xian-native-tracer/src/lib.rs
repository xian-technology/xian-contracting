use pyo3::create_exception;
use pyo3::exceptions::PyAssertionError;
use pyo3::prelude::*;
use pyo3::types::PyType;
use std::collections::HashMap;

const DEFAULT_COST: u64 = 4;
const DEFAULT_OPCODE_COST: u16 = DEFAULT_COST as u16;

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
    max_stamps: u64,
    max_events: u64,
    opcode_costs: [u16; 256],
    instruction_costs: HashMap<usize, Box<[u16]>>,
    stamp_exceeded_type: Py<PyType>,
    call_limit_type: Py<PyType>,
}

impl InstructionMeter {
    fn stamp_exceeded_error(&self, py: Python<'_>) -> PyErr {
        PyErr::from_type(
            self.stamp_exceeded_type.bind(py).clone(),
            "The cost has exceeded the stamp supplied!",
        )
    }

    fn call_limit_error(&self, py: Python<'_>) -> PyErr {
        PyErr::from_type(
            self.call_limit_type.bind(py).clone(),
            "Call count exceeded threshold! Infinite Loop?",
        )
    }

    fn ensure_cost_limit(&mut self, py: Python<'_>) -> PyResult<()> {
        if self.cost > self.stamp_supplied || self.cost > self.max_stamps {
            self.started = false;
            return Err(self.stamp_exceeded_error(py));
        }
        Ok(())
    }

    fn build_instruction_costs(&self, co_code: &[u8]) -> Box<[u16]> {
        let mut costs = Vec::with_capacity(co_code.len().div_ceil(2));
        for chunk in co_code.chunks(2) {
            let opcode = chunk[0] as usize;
            let cost = self
                .opcode_costs
                .get(opcode)
                .copied()
                .unwrap_or(DEFAULT_OPCODE_COST);
            costs.push(cost);
        }
        costs.into_boxed_slice()
    }
}

#[pymethods]
impl InstructionMeter {
    #[new]
    fn new(
        opcode_costs: Vec<u16>,
        max_stamps: u64,
        max_events: u64,
        stamp_exceeded_type: Py<PyType>,
        call_limit_type: Py<PyType>,
    ) -> PyResult<Self> {
        if opcode_costs.len() != 256 {
            return Err(PyAssertionError::new_err(
                "opcode_costs must contain exactly 256 entries",
            ));
        }
        let mut opcode_cost_table = [DEFAULT_OPCODE_COST; 256];
        opcode_cost_table.copy_from_slice(&opcode_costs);

        Ok(Self {
            cost: 0,
            stamp_supplied: 0,
            call_count: 0,
            started: false,
            max_stamps,
            max_events,
            opcode_costs: opcode_cost_table,
            instruction_costs: HashMap::new(),
            stamp_exceeded_type,
            call_limit_type,
        })
    }

    fn start(&mut self) {
        self.cost = 0;
        self.call_count = 0;
        self.started = true;
    }

    fn stop(&mut self) {
        self.started = false;
    }

    #[pyo3(signature = (clear_metadata = true))]
    fn reset(&mut self, clear_metadata: bool) {
        self.stop();
        self.cost = 0;
        self.stamp_supplied = 0;
        self.call_count = 0;
        if clear_metadata {
            self.instruction_costs.clear();
        }
    }

    fn register_code(&mut self, code: &Bound<'_, PyAny>) -> PyResult<()> {
        let key = code.as_ptr() as usize;
        if self.instruction_costs.contains_key(&key) {
            return Ok(());
        }
        let co_code: Vec<u8> = code.getattr("co_code")?.extract()?;
        let parsed = self.build_instruction_costs(&co_code);
        self.instruction_costs.insert(key, parsed);
        Ok(())
    }

    fn set_stamp(&mut self, stamp: u64) {
        self.stamp_supplied = stamp;
    }

    fn add_cost(&mut self, new_cost: u64, py: Python<'_>) -> PyResult<()> {
        self.cost = self.cost.saturating_add(new_cost);
        self.ensure_cost_limit(py)
    }

    fn instruction_callback(
        &mut self,
        code: &Bound<'_, PyAny>,
        instruction_offset: u32,
    ) -> PyResult<()> {
        if !self.started {
            return Ok(());
        }

        self.call_count = self.call_count.saturating_add(1);
        if self.call_count > self.max_events {
            self.started = false;
            return Err(self.call_limit_error(code.py()));
        }

        let code_id = code.as_ptr() as usize;
        let instruction_index = (instruction_offset as usize) / 2;
        let cost = self
            .instruction_costs
            .get(&code_id)
            .and_then(|table| table.get(instruction_index))
            .copied()
            .unwrap_or(DEFAULT_OPCODE_COST);
        self.cost = self.cost.saturating_add(cost as u64);
        self.ensure_cost_limit(code.py())
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
