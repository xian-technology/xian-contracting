//! Python strptime defaults and microsecond fields over Chrono's calendar parser.
use chrono::format::{parse_and_remainder, Parsed, StrftimeItems};
use chrono::{Datelike, Days, Duration, NaiveDate, NaiveDateTime};

use crate::VmExecutionError;

type Result<T> = std::result::Result<T, VmExecutionError>;
fn error() -> VmExecutionError {
    VmExecutionError::new("datetime.strptime() failed")
}

pub(super) fn parse(text: &str, format: &str) -> Result<NaiveDateTime> {
    let mut parsed = Parsed::new();
    parse_fields(&mut parsed, text, format)?;
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

fn parse_fields(parsed: &mut Parsed, mut text: &str, format: &str) -> Result<()> {
    let mut segment = String::new();
    let twelve_hour = has_directive(format, 'I');
    let mut characters = format.chars();
    while let Some(character) = characters.next() {
        if character != '%' {
            segment.push(character);
            continue;
        }
        let directive = characters.next().ok_or_else(error)?;
        text = parse_directive(parsed, text, directive, twelve_hour, &mut segment)?;
    }
    if !parse_segment(parsed, text, &segment)?.is_empty() {
        return Err(error());
    }
    Ok(())
}

fn parse_directive<'a>(
    parsed: &mut Parsed,
    mut text: &'a str,
    directive: char,
    twelve_hour: bool,
    segment: &mut String,
) -> Result<&'a str> {
    if directive == 'p' && !twelve_hour {
        text = parse_segment(parsed, text, segment)?;
        segment.clear();
        text = parse_segment(&mut Parsed::new(), text, "%p")?;
    } else if directive == 'f' {
        text = parse_segment(parsed, text, segment)?;
        segment.clear();
        text = fraction(parsed, text)?;
    } else {
        segment.push('%');
        segment.push(directive);
    }
    Ok(text)
}

fn has_directive(format: &str, expected: char) -> bool {
    let mut characters = format.chars();
    while let Some(character) = characters.next() {
        if character == '%' && characters.next() == Some(expected) {
            return true;
        }
    }
    false
}

fn parse_segment<'a>(parsed: &mut Parsed, text: &'a str, format: &str) -> Result<&'a str> {
    parse_and_remainder(parsed, text, StrftimeItems::new(format)).map_err(|_| error())
}

fn fraction<'a>(parsed: &mut Parsed, text: &'a str) -> Result<&'a str> {
    let count = text.bytes().take(6).take_while(u8::is_ascii_digit).count();
    if count == 0 {
        return Err(error());
    }
    let value: i64 = text[..count].parse().map_err(|_| error())?;
    parsed
        .set_nanosecond(value * 10i64.pow(9 - count as u32))
        .map_err(|_| error())?;
    Ok(&text[count..])
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
            ("PM", "%p", "1900-01-01 00:00:00"),
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
