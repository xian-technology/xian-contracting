//! Python string properties pinned to historical Unicode 15.0.0 semantics.
//! Rust's Unicode tables and Alphabetic/Numeric properties are not equivalent.
#[path = "unicode_string_tables.rs"]
mod tables;

const ALPHA: u8 = 1;
const DIGIT: u8 = 2;
const NUMERIC: u8 = 4;
const LOWER: u8 = 8;
const CASED: u8 = 16;
const SPACE: u8 = 32;
const CASE_IGNORABLE: u8 = 64;

fn properties(character: char) -> u8 {
    let code = u32::from(character);
    let position = tables::RANGES.partition_point(|(_, end, _)| *end < code);
    tables::RANGES
        .get(position)
        .filter(|(start, _, _)| *start <= code)
        .map_or(0, |(_, _, flags)| *flags)
}

pub(super) fn predicate(method: &str, value: &str) -> bool {
    if method == "islower" {
        return is_lower(value);
    }
    let mask = match method {
        "isalpha" => ALPHA,
        "isdigit" => DIGIT,
        "isalnum" => ALPHA | NUMERIC,
        _ => unreachable!("only supported string predicates enter this helper"),
    };
    !value.is_empty()
        && value
            .chars()
            .all(|character| properties(character) & mask != 0)
}

fn is_lower(value: &str) -> bool {
    let mut has_lower = false;
    for character in value.chars() {
        let flags = properties(character);
        if flags & CASED != 0 && flags & LOWER == 0 {
            return false;
        }
        has_lower |= flags & LOWER != 0;
    }
    has_lower
}

pub(in crate::interpreter) fn is_whitespace(character: char) -> bool {
    properties(character) & SPACE != 0
}

fn push_mapping(output: &mut String, character: char, mappings: &[(u32, &str)]) {
    match mappings.binary_search_by_key(&u32::from(character), |(code, _)| *code) {
        Ok(index) => output.push_str(mappings[index].1),
        Err(_) => output.push(character),
    }
}

pub(super) fn upper(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        push_mapping(&mut output, character, tables::UPPER);
    }
    output
}

pub(super) fn lower(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut previous_cased = false;
    let mut remaining = value.chars();
    while let Some(character) = remaining.next() {
        let flags = properties(character);
        if character == '\u{03A3}' && final_sigma(previous_cased, remaining.clone()) {
            output.push('\u{03C2}');
        } else {
            push_mapping(&mut output, character, tables::LOWER);
        }
        if flags & CASE_IGNORABLE == 0 {
            previous_cased = flags & CASED != 0;
        }
    }
    output
}

fn final_sigma(previous_cased: bool, remaining: std::str::Chars<'_>) -> bool {
    if !previous_cased {
        return false;
    }
    // Sigma itself is not ignorable, so each following ignorable run is scanned
    // at most once here and once by lower(): total work is linear in input size.
    let next = remaining
        .map(properties)
        .find(|flags| flags & CASE_IGNORABLE == 0);
    next.is_none_or(|flags| flags & CASED == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn digit_and_alphabetic_properties_are_python_properties() {
        assert!(!predicate("isdigit", "¼"));
        assert!(predicate("isdigit", "²١"));
        assert!(!predicate("isalpha", "\u{0345}"));
        assert!(!predicate("isalnum", "\u{0345}"));
        assert!(predicate("isalnum", "a¼²中"));
        for method in ["isalpha", "isdigit", "isalnum", "islower"] {
            assert!(!predicate(method, ""));
        }
    }

    #[test]
    fn lower_requires_a_lowercase_character_and_ignores_uncased_letters() {
        assert!(predicate("islower", "a中1"));
        assert!(predicate("islower", "\u{0345}"));
        assert!(!predicate("islower", "中1"));
        assert!(!predicate("islower", "aǅ"));
        assert!(!predicate("islower", "aA"));
    }

    #[test]
    fn python_control_separators_are_whitespace() {
        for code in 0x1C..=0x1F {
            assert!(is_whitespace(char::from_u32(code).unwrap()));
        }
        assert!(is_whitespace('\u{0085}'));
        assert!(is_whitespace('\u{3000}'));
        assert!(!is_whitespace('\u{200B}'));
        assert!(!is_whitespace('\0'));
    }

    #[test]
    fn lookup_matches_every_historical_codepoint_property() {
        // The digest was captured from all Python 3.12 codepoint predicates.
        // Surrogates are not Rust chars; all their Python property bits are zero.
        let mut digest = Sha256::new();
        for code in 0..=0x10FFFF {
            digest.update([char::from_u32(code).map_or(0, properties)]);
        }
        assert_eq!(hex::encode(digest.finalize()), tables::PROPERTIES_SHA256);
        for pair in tables::RANGES.windows(2) {
            assert!(pair[0].0 <= pair[0].1);
            assert!(pair[0].1 < pair[1].0);
        }
    }

    #[test]
    fn contextual_sigma_ignores_marks_but_not_uncased_letters() {
        for (input, expected) in [
            ("ΟΣ", "ος"),
            ("ΟΣΑ", "οσα"),
            ("AΣ\u{0345}", "aς\u{0345}"),
            ("AΣ\u{0345}A", "aσ\u{0345}a"),
            ("A\u{0345}Σ", "a\u{0345}ς"),
            ("\u{0345}Σ", "\u{0345}σ"),
            ("ǅΣ", "ǆς"),
            ("中Σ", "中σ"),
            ("A'Σ", "a'ς"),
            ("AΣ'A", "aσ'a"),
            ("AΣ 中", "aς 中"),
        ] {
            assert_eq!(lower(input), expected, "{input}");
        }
        assert_eq!(lower("ßﬃİ"), "ßﬃi\u{0307}");
        assert_eq!(upper("ßﬃİ"), "SSFFIİ");
        assert_eq!(lower("\u{1C89}\u{1C8A}"), "\u{1C89}\u{1C8A}");
        assert_eq!(upper("\u{1C89}\u{1C8A}"), "\u{1C89}\u{1C8A}");
    }

    #[test]
    fn every_scalar_case_mapping_matches_the_historical_runtime() {
        for (mapping, expected) in [
            (lower as fn(&str) -> String, tables::LOWER_SHA256),
            (upper, tables::UPPER_SHA256),
        ] {
            let mut digest = Sha256::new();
            for code in 0..=0x10FFFF {
                let Some(character) = char::from_u32(code) else {
                    continue;
                };
                let output = mapping(&character.to_string());
                digest.update(code.to_be_bytes());
                digest.update((output.len() as u32).to_be_bytes());
                digest.update(output.as_bytes());
            }
            assert_eq!(hex::encode(digest.finalize()), expected);
        }
    }

    #[test]
    fn codepoints_introduced_after_unicode_15_remain_unassigned() {
        // U+2EBF0 was added in Unicode 15.1 (CJK Extension I).
        assert!(!predicate("isalpha", "\u{2EBF0}"));
        assert!(!predicate("isalnum", "\u{2EBF0}"));
        // U+1C89 was added in Unicode 16 (Cyrillic capital Tje).
        assert_eq!(properties('\u{1C89}'), 0);
    }
}
