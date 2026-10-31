//! Python string properties pinned to historical Unicode 15.0.0 semantics.
//! Rust's Unicode tables and Alphabetic/Numeric properties are not equivalent.
#[path = "unicode_string_tables.rs"]
mod tables;

const ALPHA: u16 = 1;
const DIGIT: u16 = 2;
const NUMERIC: u16 = 4;
const LOWER: u16 = 8;
const CASED: u16 = 16;
const SPACE: u16 = 32;
const CASE_IGNORABLE: u16 = 64;
const DECIMAL: u16 = 128;
const UPPER: u16 = 256;
const TITLE: u16 = 512;
const PRINTABLE: u16 = 1024;
const IDENTIFIER_START: u16 = 2048;
const IDENTIFIER_CONTINUE: u16 = 4096;
const LINEBREAK: u16 = 8192;

fn properties(character: char) -> u16 {
    let code = u32::from(character);
    let position = tables::RANGES.partition_point(|(_, end, _)| *end < code);
    tables::RANGES
        .get(position)
        .filter(|(start, _, _)| *start <= code)
        .map_or(0, |(_, _, flags)| *flags)
}

pub(super) fn predicate(method: &str, value: &str) -> bool {
    match method {
        "islower" => return is_cased_kind(value, LOWER),
        "isupper" => return is_cased_kind(value, UPPER),
        "istitle" => return is_title(value),
        "isidentifier" => return is_identifier(value),
        "isprintable" => return value.chars().all(|ch| properties(ch) & PRINTABLE != 0),
        _ => {}
    }
    let mask = predicate_mask(method);
    !value.is_empty()
        && value
            .chars()
            .all(|character| properties(character) & mask != 0)
}

fn predicate_mask(method: &str) -> u16 {
    match method {
        "isalpha" => ALPHA,
        "isdigit" => DIGIT,
        "isdecimal" => DECIMAL,
        "isnumeric" => NUMERIC,
        "isspace" => SPACE,
        "isalnum" => ALPHA | NUMERIC,
        _ => unreachable!("only supported string predicates enter this helper"),
    }
}

fn is_cased_kind(value: &str, kind: u16) -> bool {
    let mut has_lower = false;
    for character in value.chars() {
        let flags = properties(character);
        if flags & CASED != 0 && flags & kind == 0 {
            return false;
        }
        has_lower |= flags & kind != 0;
    }
    has_lower
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|ch| properties(ch) & IDENTIFIER_START != 0)
        && chars.all(|ch| properties(ch) & IDENTIFIER_CONTINUE != 0)
}

fn is_title(value: &str) -> bool {
    let mut previous_cased = false;
    let mut has_cased = false;
    for ch in value.chars() {
        let flags = properties(ch);
        if flags & (UPPER | TITLE) != 0 && previous_cased {
            return false;
        }
        if flags & LOWER != 0 && !previous_cased {
            return false;
        }
        previous_cased = flags & CASED != 0;
        has_cased |= previous_cased;
    }
    has_cased
}

pub(in crate::interpreter) fn is_printable(character: char) -> bool {
    properties(character) & PRINTABLE != 0
}

pub(super) fn is_linebreak(character: char) -> bool {
    properties(character) & LINEBREAK != 0
}

pub(in crate::interpreter) fn is_whitespace(character: char) -> bool {
    properties(character) & SPACE != 0
}

fn mapping_for<'a>(character: char, mappings: &[(u32, &'a str)]) -> Option<&'a str> {
    mappings
        .binary_search_by_key(&u32::from(character), |(code, _)| *code)
        .ok()
        .map(|index| mappings[index].1)
}
fn push_mapping(output: &mut String, character: char, mappings: &[(u32, &str)]) {
    if let Some(mapped) = mapping_for(character, mappings) {
        output.push_str(mapped);
    } else {
        output.push(character);
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

pub(super) fn transform_length(value: &str, method: &str) -> usize {
    let mut previous_cased = false;
    let mut length = 0usize;
    for (index, ch) in value.chars().enumerate() {
        let flags = properties(ch);
        let (mapping, _) = transform_mapping(method, flags, previous_cased, index == 0);
        length = length.saturating_add(mapping_for(ch, mapping).map_or(ch.len_utf8(), str::len));
        previous_cased = flags & CASED != 0;
    }
    // Contextual sigma changes U+03C3 to U+03C2: both occupy two UTF-8 bytes.
    length
}

pub(super) fn transform(value: &str, method: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut previous_cased = false;
    let mut previous_significant_cased = false;
    let mut remaining = value.chars();
    let mut first = true;
    while let Some(character) = remaining.next() {
        let flags = properties(character);
        let (mapping, lower_context) = transform_mapping(method, flags, previous_cased, first);
        if lower_context
            && character == '\u{03A3}'
            && final_sigma(previous_significant_cased, remaining.clone())
        {
            output.push('\u{03C2}');
        } else {
            push_mapping(&mut output, character, mapping);
        }
        previous_cased = flags & CASED != 0;
        if flags & CASE_IGNORABLE == 0 {
            previous_significant_cased = previous_cased;
        }
        first = false;
    }
    output
}

fn transform_mapping(
    method: &str,
    flags: u16,
    previous_cased: bool,
    first: bool,
) -> (&'static [(u32, &'static str)], bool) {
    match method {
        "casefold" => (tables::CASEFOLD, false),
        "capitalize" if first => (tables::TITLE, false),
        "capitalize" => (tables::LOWER, true),
        "title" if previous_cased => (tables::LOWER, true),
        "title" => (tables::TITLE, false),
        "swapcase" => swapcase_mapping(flags),
        _ => unreachable!("only supported Unicode transforms enter this helper"),
    }
}

fn swapcase_mapping(flags: u16) -> (&'static [(u32, &'static str)], bool) {
    if flags & UPPER != 0 {
        (tables::LOWER, true)
    } else if flags & LOWER != 0 {
        (tables::UPPER, false)
    } else {
        (&[], false)
    }
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
            digest.update(char::from_u32(code).map_or(0, properties).to_le_bytes());
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
            (|value| transform(value, "title"), tables::TITLE_SHA256),
            (
                |value| transform(value, "casefold"),
                tables::CASEFOLD_SHA256,
            ),
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
    fn expanded_predicates_and_case_transforms_match_python() {
        for (method, value, expected) in [
            ("isdecimal", "١", true),
            ("isdecimal", "²", false),
            ("isnumeric", "¼", true),
            ("isidentifier", "变量", true),
            ("isidentifier", "_x1", true),
            ("isidentifier", "class", true),
            ("isidentifier", "1x", false),
            ("isprintable", "", true),
            ("isprintable", " ", true),
            ("isprintable", "\u{00A0}", false),
            ("isspace", "\u{001C}", true),
            ("isspace", "", false),
            ("istitle", "ǅ Ab", true),
            ("istitle", "HELLO", false),
            ("isupper", "A中", true),
            ("isupper", "中", false),
        ] {
            assert_eq!(predicate(method, value), expected, "{method} {value}");
        }
        assert_eq!(transform("ßABC", "capitalize"), "Ssabc");
        assert_eq!(transform("AΣ", "capitalize"), "Aς");
        assert_eq!(transform("AΣ", "swapcase"), "aς");
        assert_eq!(transform("ǅßA", "swapcase"), "ǅSSa");
        assert_eq!(
            transform("they're BILL'S friends", "title"),
            "They'Re Bill'S Friends"
        );
        assert_eq!(transform("Straße İΣς", "casefold"), "strasse i\u{0307}σσ");
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
