//! Deterministic codecs. No host locale, codec registry or error callbacks.
use crate::VmExecutionError;
const MAX_BYTES: usize = 128 * 1024;
type Result<T> = std::result::Result<T, VmExecutionError>;

#[derive(Clone, Copy)]
enum Codec {
    Utf8,
    Ascii,
    Latin1,
}
#[derive(Clone, Copy)]
enum Errors {
    Strict,
    Ignore,
    Replace,
    Backslash,
}

fn codec(name: &str) -> Result<Codec> {
    let name = name.to_ascii_lowercase().replace(['_', ' '], "-");
    match name.as_str() {
        "utf8" | "utf-8" | "u8" | "utf" | "cp65001" => Ok(Codec::Utf8),
        "ascii" | "us-ascii" | "us" | "646" | "ansi-x3.4-1968" | "ansi-x3.4-1986" | "iso646-us" => {
            Ok(Codec::Ascii)
        }
        "latin1" | "latin-1" | "latin" | "l1" | "iso-8859-1" | "iso8859-1" | "cp819" | "ibm819" => {
            Ok(Codec::Latin1)
        }
        _ => Err(VmExecutionError::new("unsupported deterministic encoding")),
    }
}
fn errors(name: &str) -> Result<Errors> {
    match name {
        "strict" => Ok(Errors::Strict),
        "ignore" => Ok(Errors::Ignore),
        "replace" => Ok(Errors::Replace),
        "backslashreplace" => Ok(Errors::Backslash),
        _ => Err(VmExecutionError::new(
            "unsupported deterministic error handler",
        )),
    }
}
fn extend(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    if output.len().saturating_add(bytes.len()) > MAX_BYTES {
        return Err(VmExecutionError::new("encoding allocation limit exceeded"));
    }
    output.extend_from_slice(bytes);
    Ok(())
}
fn escape(ch: char) -> String {
    let number = ch as u32;
    if number <= 0xff {
        format!("\\x{number:02x}")
    } else if number <= 0xffff {
        format!("\\u{number:04x}")
    } else {
        format!("\\U{number:08x}")
    }
}
pub(super) fn encode(text: &str, name: &str, mode: &str) -> Result<Vec<u8>> {
    let codec = codec(name)?;
    let mode = errors(mode)?;
    let mut output = Vec::new();
    for ch in text.chars() {
        encode_character(&mut output, ch, codec, mode)?;
    }
    Ok(output)
}
fn encode_character(output: &mut Vec<u8>, ch: char, codec: Codec, mode: Errors) -> Result<()> {
    if matches!(codec, Codec::Utf8) {
        let mut bytes = [0; 4];
        return extend(output, ch.encode_utf8(&mut bytes).as_bytes());
    }
    let maximum = if matches!(codec, Codec::Ascii) {
        127
    } else {
        255
    };
    if (ch as u32) <= maximum {
        extend(output, &[ch as u8])
    } else {
        encode_error(output, ch, mode)
    }
}
fn encode_error(output: &mut Vec<u8>, ch: char, mode: Errors) -> Result<()> {
    match mode {
        Errors::Strict => Err(VmExecutionError::new(
            "character cannot be encoded as ASCII/Latin-1",
        )),
        Errors::Ignore => Ok(()),
        Errors::Replace => extend(output, b"?"),
        Errors::Backslash => extend(output, escape(ch).as_bytes()),
    }
}
pub(super) fn decode(bytes: &[u8], name: &str, mode: &str) -> Result<String> {
    let codec = codec(name)?;
    let mode = errors(mode)?;
    let mut output = Vec::new();
    match codec {
        Codec::Utf8 => decode_utf8(bytes, mode, &mut output)?,
        Codec::Ascii => decode_ascii(bytes, mode, &mut output)?,
        Codec::Latin1 => decode_latin1(bytes, &mut output)?,
    }

    String::from_utf8(output).map_err(|_| VmExecutionError::new("invalid decoded text"))
}
fn decode_ascii(bytes: &[u8], mode: Errors, output: &mut Vec<u8>) -> Result<()> {
    for byte in bytes {
        if *byte < 128 {
            extend(output, &[*byte])?;
        } else {
            decode_error(&[*byte], mode, output, "invalid ASCII")?;
        }
    }
    Ok(())
}
fn decode_latin1(bytes: &[u8], output: &mut Vec<u8>) -> Result<()> {
    for byte in bytes {
        let mut data = [0; 4];
        extend(output, char::from(*byte).encode_utf8(&mut data).as_bytes())?;
    }
    Ok(())
}
fn decode_utf8(mut bytes: &[u8], mode: Errors, output: &mut Vec<u8>) -> Result<()> {
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(_) => {
                extend(output, bytes)?;
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                extend(output, &bytes[..valid])?;
                let count = error.error_len().unwrap_or(bytes.len() - valid);
                decode_error(&bytes[valid..valid + count], mode, output, "invalid UTF-8")?;
                bytes = &bytes[valid + count..];
            }
        }
    }
    Ok(())
}
fn decode_error(bytes: &[u8], mode: Errors, output: &mut Vec<u8>, message: &str) -> Result<()> {
    match mode {
        Errors::Strict => Err(VmExecutionError::new(message)),
        Errors::Ignore => Ok(()),
        Errors::Replace => extend(output, "�".as_bytes()),
        Errors::Backslash => {
            for byte in bytes {
                extend(output, format!("\\x{byte:02x}").as_bytes())?;
            }
            Ok(())
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_utf8_sequences_match_python_units() {
        assert_eq!(decode(b"\xe2\x82X\xff", "utf8", "replace").unwrap(), "�X�");
        assert_eq!(decode(b"\xed\xa0\x80", "utf8", "replace").unwrap(), "���");
        assert_eq!(decode(b"\xf0\x90\x80", "utf8", "replace").unwrap(), "�");
        assert_eq!(
            decode(b"\xe2\x82X", "utf8", "backslashreplace").unwrap(),
            "\\xe2\\x82X"
        );
    }
    #[test]
    fn codec_output_is_bounded() {
        assert!(encode(&"é".repeat(MAX_BYTES), "ascii", "backslashreplace").is_err());
        assert!(decode(&vec![255; MAX_BYTES], "latin1", "strict").is_err());
        assert!(decode(b"a", "utf16", "strict").is_err());
        assert!(decode(b"a", "utf8", "surrogateescape").is_err());
    }
    #[test]
    fn codec_character_and_allocation_boundaries() {
        assert_eq!(encode("\u{7f}", "ascii", "strict").unwrap(), [127]);
        assert_eq!(encode("ÿ", "latin1", "strict").unwrap(), [255]);
        assert_eq!(
            encode("ÿ\u{ffff}😀", "ascii", "backslashreplace").unwrap(),
            b"\\xff\\uffff\\U0001f600"
        );
        assert_eq!(encode("aé😀", "ascii", "ignore").unwrap(), b"a");
        assert_eq!(encode("aé😀", "ascii", "replace").unwrap(), b"a??");
        assert!(encode("é", "ascii", "strict").is_err());
        assert_eq!(encode("é😀", "utf8", "strict").unwrap(), "é😀".as_bytes());
        assert_eq!(
            encode(&"a".repeat(MAX_BYTES), "ascii", "strict")
                .unwrap()
                .len(),
            MAX_BYTES
        );
        assert_eq!(decode(b"abc\xe2\x82", "utf8", "replace").unwrap(), "abc�");
    }
}
