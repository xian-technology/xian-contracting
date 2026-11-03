//! Opt-in operator diagnostics. Records never contain contract values or errors.
//! A failed diagnostic sink must not turn a VM result into an execution failure.
use chrono::{DateTime, SecondsFormat, Utc};
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LABEL_CHARS: usize = 64;

fn label(value: &str) -> String {
    value
        .chars()
        .take(MAX_LABEL_CHARS)
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || "_-.".contains(ch) {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn timestamp() -> String {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(elapsed.as_secs())
        .ok()
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, elapsed.subsec_nanos()))
        .map(|now| now.to_rfc3339_opts(SecondsFormat::Millis, true))
        .unwrap_or_else(|| "time-unavailable".to_owned())
}

fn write_record(writer: &mut impl Write, event: &str, contract: &str, function: &str, kind: &str) {
    let _ = writeln!(
        writer,
        "{} | DEBUG | xian-vm | {} | contract={} function={} kind={} pid={}",
        timestamp(),
        label(event),
        label(contract),
        label(function),
        label(kind),
        std::process::id()
    );
}

pub(super) fn emit(event: &str, contract: &str, function: &str, kind: &str) {
    write_record(&mut io::stderr().lock(), event, contract, function, kind);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BrokenWriter;
    impl Write for BrokenWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "closed diagnostic sink",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_broken_diagnostic_sink_is_not_an_execution_error() {
        write_record(&mut BrokenWriter, "call_exit", "con_example", "probe", "ok");
    }

    #[test]
    fn records_are_bounded_single_line_metadata_with_utc_time() {
        let mut output = Vec::new();
        let injected = "name\n\r\x1b🙂".repeat(1000);
        write_record(&mut output, "call_enter", &injected, &injected, &injected);
        let text = String::from_utf8(output).unwrap();
        assert!(text.len() < 400);
        assert_eq!(text.lines().count(), 1);
        assert!(!text.contains('\r') && !text.contains('\x1b') && !text.contains('🙂'));
        assert!(text.contains("Z | DEBUG | xian-vm | call_enter | contract="));
        assert!(text.contains(&format!(" pid={}", std::process::id())));
        let end = text.find(" | DEBUG").unwrap();
        DateTime::parse_from_rfc3339(&text[..end]).unwrap();
    }
}
