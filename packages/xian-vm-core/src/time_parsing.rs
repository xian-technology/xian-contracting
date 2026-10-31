//! Python strptime defaults and microsecond fields over Chrono's calendar parser.
use chrono::format::{parse_and_remainder, Parsed, StrftimeItems};
use chrono::{Datelike, Days, Duration, NaiveDate, NaiveDateTime};

use crate::VmExecutionError;

type Result<T> = std::result::Result<T, VmExecutionError>;
fn error() -> VmExecutionError {
    VmExecutionError::new("datetime.strptime() failed")
}

pub(super) fn parse(text: &str, format: &str) -> Result<NaiveDateTime> {
    let tokens = format_tokens(format)?;
    work_bound(text, format, &tokens)?;
    let mut parsed = parse_fields(Parsed::new(), text, &tokens, &mut Work::new())?;
    default_date(&mut parsed)?;
    parsed.hour_div_12.get_or_insert(0);
    parsed.hour_mod_12.get_or_insert(0);
    parsed.minute.get_or_insert(0);
    parsed.second.get_or_insert(0);
    parsed.nanosecond.get_or_insert(0);
    let date = parsed.to_naive_date().map_err(|_| error())?;
    let time = parsed.to_naive_time().map_err(|_| error())?;
    if !(1..=9999).contains(&date.year()) || parsed.second == Some(60) {
        return Err(error());
    }
    Ok(date.and_time(time))
}

const MAX_PARSE_WORK: u64 = 1_000_000;

pub(super) fn work_cost(text: &str, format: &str) -> Result<u64> {
    work_bound(text, format, &format_tokens(format)?)
}

fn work_bound(text: &str, format: &str, tokens: &[Token]) -> Result<u64> {
    let mut branches = 1u64;
    let mut numeric = 0u64;
    for token in tokens {
        if let Token::Numeric(directive) = token {
            let (minimum, maximum) = directive_width(*directive);
            branches = branches.saturating_mul((maximum - minimum + 1) as u64);
            numeric += 1;
        }
    }
    let bytes = (text.len() as u64).saturating_add(format.len() as u64);
    let work = bytes
        .saturating_add(32 * numeric + 1)
        .saturating_mul(branches);
    if work > MAX_PARSE_WORK {
        return Err(work_error());
    }
    Ok(work)
}

fn work_error() -> VmExecutionError {
    VmExecutionError::new("datetime parse work limit exceeded")
}

struct Work {
    remaining: u64,
    exhausted: bool,
}
impl Work {
    fn new() -> Self {
        Self {
            remaining: MAX_PARSE_WORK,
            exhausted: false,
        }
    }
    fn charge(&mut self, amount: u64) -> Result<()> {
        match self.remaining.checked_sub(amount) {
            Some(remaining) => {
                self.remaining = remaining;
                Ok(())
            }
            None => {
                self.exhausted = true;
                Err(work_error())
            }
        }
    }
}

const NUMERIC_DIRECTIVES: &str = "YymdHIMSfjUWwuGV";

#[derive(Debug)]
enum Token {
    Literal(String),
    Numeric(char),
}

fn policy_error() -> VmExecutionError {
    VmExecutionError::new("unsupported datetime format")
}

fn format_tokens(format: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut literal = String::new();
    let mut seen = std::collections::HashSet::new();
    let mut characters = format.chars();
    while let Some(character) = characters.next() {
        if character != '%' {
            literal.push(character);
            continue;
        }
        let directive = characters.next().ok_or_else(policy_error)?;
        if directive == '%' {
            literal.push('%');
            continue;
        }
        if !NUMERIC_DIRECTIVES.contains(directive) || !seen.insert(directive) {
            return Err(policy_error());
        }
        push_literal(&mut tokens, &mut literal);
        tokens.push(Token::Numeric(directive));
    }
    push_literal(&mut tokens, &mut literal);
    validate_combinations(&seen)?;
    Ok(tokens)
}

fn push_literal(tokens: &mut Vec<Token>, literal: &mut String) {
    if !literal.is_empty() {
        tokens.push(Token::Literal(std::mem::take(literal)));
    }
}

fn validate_combinations(seen: &std::collections::HashSet<char>) -> Result<()> {
    for (left, right) in [('Y', 'y'), ('H', 'I'), ('U', 'W'), ('w', 'u')] {
        if seen.contains(&left) && seen.contains(&right) {
            return Err(policy_error());
        }
    }
    if seen.contains(&'G') || seen.contains(&'V') {
        validate_iso(seen)?;
    }
    Ok(())
}

fn validate_iso(seen: &std::collections::HashSet<char>) -> Result<()> {
    let complete =
        seen.contains(&'G') && seen.contains(&'V') && (seen.contains(&'u') || seen.contains(&'w'));
    if !complete || "YymdjUW".chars().any(|field| seen.contains(&field)) {
        return Err(policy_error());
    }
    Ok(())
}

fn parse_fields(parsed: Parsed, text: &str, tokens: &[Token], work: &mut Work) -> Result<Parsed> {
    work.charge(1)?;
    match tokens.split_first() {
        None if text.is_empty() => Ok(parsed),
        None => Err(error()),
        Some((Token::Literal(literal), remaining)) => {
            parse_fields(parsed, parse_literal(text, literal, work)?, remaining, work)
        }
        Some((Token::Numeric(directive), remaining)) => {
            parse_numeric(parsed, text, *directive, remaining, work)
        }
    }
}

fn format_whitespace(character: char) -> bool {
    matches!(character, '\u{9}'..='\u{d}' | '\u{1c}'..='\u{20}' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}

fn parse_literal<'a>(mut text: &'a str, literal: &str, work: &mut Work) -> Result<&'a str> {
    let mut characters = literal.chars().peekable();
    while let Some(character) = characters.next() {
        work.charge(character.len_utf8() as u64)?;
        if format_whitespace(character) {
            while characters.peek().is_some_and(|c| format_whitespace(*c)) {
                characters.next();
            }
            text = consume_whitespace(text, work)?;
        } else {
            text = text.strip_prefix(character).ok_or_else(error)?;
        }
    }
    Ok(text)
}

fn consume_whitespace<'a>(text: &'a str, work: &mut Work) -> Result<&'a str> {
    let mut bytes = 0;
    for character in text.chars().take_while(|c| format_whitespace(*c)) {
        work.charge(character.len_utf8() as u64)?;
        bytes += character.len_utf8();
    }
    if bytes == 0 {
        return Err(error());
    }
    Ok(&text[bytes..])
}

fn numeric_width(text: &str, directive: char) -> (usize, usize) {
    if directive == 'd' && text.starts_with(' ') {
        return (
            2,
            if text.as_bytes().get(1).is_some_and(u8::is_ascii_digit) {
                2
            } else {
                0
            },
        );
    }
    let (minimum, maximum) = directive_width(directive);
    let digits = text
        .bytes()
        .take(maximum)
        .take_while(u8::is_ascii_digit)
        .count();
    (minimum, digits)
}

fn directive_width(directive: char) -> (usize, usize) {
    match directive {
        'Y' | 'G' => (4, 4),
        'y' => (2, 2),
        'f' => (1, 6),
        'j' => (1, 3),
        'w' | 'u' => (1, 1),
        _ => (1, 2),
    }
}

fn parse_numeric(
    parsed: Parsed,
    text: &str,
    directive: char,
    remaining: &[Token],
    work: &mut Work,
) -> Result<Parsed> {
    let (minimum, maximum) = numeric_width(text, directive);
    for length in (minimum..=maximum).rev() {
        work.charge(8)?;
        let mut candidate = parsed.clone();
        if parse_number(&mut candidate, &text[..length], directive).is_err() {
            continue;
        }
        match parse_fields(candidate, &text[length..], remaining, work) {
            Ok(result) => return Ok(result),
            Err(_) if work.exhausted => return Err(work_error()),
            Err(_) => {}
        }
    }
    Err(error())
}

fn parse_number(parsed: &mut Parsed, text: &str, directive: char) -> Result<()> {
    if directive == 'f' {
        let value: i64 = text.parse().map_err(|_| error())?;
        return parsed
            .set_nanosecond(value * 10i64.pow(9 - text.len() as u32))
            .map_err(|_| error());
    }
    // Python's lexical second field admits60/61, then datetime rejects leap seconds.
    if directive == 'S' {
        let second: u32 = text.parse().map_err(|_| error())?;
        if second > 61 {
            return Err(error());
        }
        parsed.second = Some(second);
        return Ok(());
    }
    let format = format!("%{directive}");
    let remaining =
        parse_and_remainder(parsed, text, StrftimeItems::new(&format)).map_err(|_| error())?;
    if !remaining.is_empty() {
        return Err(error());
    }
    Ok(())
}

fn default_year(parsed: &mut Parsed) {
    if let Some(year) = parsed.year_mod_100 {
        parsed
            .year_div_100
            .get_or_insert(if year >= 69 { 19 } else { 20 });
    } else if parsed.year.is_none() && parsed.isoyear.is_none() {
        parsed.year = Some(1900);
    }
}

fn default_date(parsed: &mut Parsed) -> Result<()> {
    default_year(parsed);
    if parsed.weekday.is_none() {
        parsed.week_from_sun = None;
        parsed.week_from_mon = None;
    }
    resolve_ordinal(parsed)?;
    resolve_week(parsed)?;
    let week_date = parsed.isoweek.is_some()
        || parsed.week_from_sun.is_some()
        || parsed.week_from_mon.is_some();
    if !week_date {
        // Python ignores a weekday alongside ordinary calendar fields.
        parsed.weekday = None;
    }
    if parsed.ordinal.is_none() && !week_date {
        parsed.month.get_or_insert(1);
        parsed.day.get_or_insert(1);
    }
    Ok(())
}

fn resolve_ordinal(parsed: &mut Parsed) -> Result<()> {
    let Some(ordinal) = parsed.ordinal else {
        return Ok(());
    };
    let year = parsed
        .year
        .or_else(|| Some(parsed.year_div_100? * 100 + parsed.year_mod_100?))
        .ok_or_else(error)?;
    let date = NaiveDate::from_ymd_opt(year, 1, 1)
        .and_then(|date| date.checked_add_days(Days::new(u64::from(ordinal - 1))))
        .ok_or_else(error)?;
    resolved_date(parsed, date);
    Ok(())
}

fn resolve_week(parsed: &mut Parsed) -> Result<()> {
    let Some(weekday) = parsed.weekday else {
        return Ok(());
    };
    let Some((week, sunday)) = week_spec(parsed) else {
        return Ok(());
    };
    let year = parsed
        .year
        .or_else(|| Some(parsed.year_div_100? * 100 + parsed.year_mod_100?))
        .ok_or_else(error)?;
    let january = NaiveDate::from_ymd_opt(year, 1, 1).ok_or_else(error)?;
    let first = weekday_number(january.weekday(), sunday);
    let day = weekday_number(weekday, sunday);
    let offset = if week == 0 {
        day - first
    } else {
        (7 - first) % 7 + i64::from(week - 1) * 7 + day
    };
    let date = january
        .checked_add_signed(Duration::days(offset))
        .ok_or_else(error)?;
    resolved_date(parsed, date);
    Ok(())
}

fn week_spec(parsed: &Parsed) -> Option<(u32, bool)> {
    match (parsed.week_from_sun, parsed.week_from_mon) {
        (Some(week), _) => Some((week, true)),
        (_, Some(week)) => Some((week, false)),
        _ => None,
    }
}

fn weekday_number(weekday: chrono::Weekday, sunday: bool) -> i64 {
    if sunday {
        weekday.num_days_from_sunday().into()
    } else {
        weekday.num_days_from_monday().into()
    }
}

fn resolved_date(parsed: &mut Parsed, date: NaiveDate) {
    parsed.year = Some(date.year());
    parsed.year_div_100 = None;
    parsed.year_mod_100 = None;
    parsed.month = Some(date.month());
    parsed.day = Some(date.day());
    parsed.ordinal = None;
    parsed.week_from_sun = None;
    parsed.week_from_mon = None;
    parsed.weekday = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_components_use_python_defaults() {
        for (text, format, expected) in [
            ("2026-02-03", "%Y-%m-%d", "2026-02-03 00:00:00"),
            ("23:45", "%H:%M", "1900-01-01 23:45:00"),
            ("2026", "%Y", "2026-01-01 00:00:00"),
            ("03-02", "%d-%m", "1900-02-03 00:00:00"),
            ("2024 060", "%Y %j", "2024-02-29 00:00:00"),
            ("69", "%y", "1969-01-01 00:00:00"),
            ("68", "%y", "2068-01-01 00:00:00"),
            ("2026 00 0", "%Y %U %w", "2025-12-28 00:00:00"),
            ("2026 53 0", "%Y %U %w", "2027-01-03 00:00:00"),
            ("2023 366", "%Y %j", "2024-01-01 00:00:00"),
        ] {
            assert_eq!(parse(text, format).unwrap().to_string(), expected);
        }
    }

    #[test]
    fn fractional_seconds_are_decimal_microseconds() {
        for (digits, micros) in [("1", 100000), ("1234", 123400), ("123456", 123456)] {
            let value = parse(&format!("12:34:56.{digits}"), "%H:%M:%S.%f").unwrap();
            assert_eq!(value.and_utc().timestamp_subsec_micros(), micros);
        }
        assert!(parse("12:34:56.1234567", "%H:%M:%S.%f").is_err());
        assert!(parse("0000-01-01", "%Y-%m-%d").is_err());
        assert!(parse("23:59:60", "%H:%M:%S").is_err());
    }
}
