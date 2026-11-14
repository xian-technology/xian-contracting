//! A run whose panic becomes an error instead of unwinding into the caller.
use std::panic::{catch_unwind, AssertUnwindSafe};

/// `run()`, or the panic message when it panicked.
///
/// For runs whose state is dropped afterwards (a simulation over a fork):
/// nothing they touched is used again, so unwind safety is not a concern.
pub(crate) fn catching<T>(run: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(run)).map_err(|panic| {
        panic
            .downcast_ref::<&str>()
            .map(|text| (*text).to_owned())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::catching;

    #[test]
    fn a_finished_run_returns_its_value() {
        assert_eq!(catching(|| 7), Ok(7));
    }

    #[test]
    fn a_panic_becomes_its_message() {
        assert_eq!(
            catching(|| -> u8 { panic!("static text") }),
            Err("static text".to_owned())
        );
        let detail = 3;
        assert_eq!(
            catching(|| -> u8 { panic!("formatted {detail}") }),
            Err("formatted 3".to_owned())
        );
        assert_eq!(
            catching(|| -> u8 { std::panic::panic_any(5_u8) }),
            Err("unknown panic".to_owned())
        );
    }
}
