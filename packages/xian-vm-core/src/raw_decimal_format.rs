//! Decimal's numeric formatting keeps quantum; output allocation is bounded.
use super::*;
const LIMIT: usize = 128 * 1024;

struct Spec {
    fill: char,
    align: char,
    sign: char,
    width: usize,
    precision: Option<usize>,
    kind: char,
    grouping: bool,
    positive_zero: bool,
    zero_padding: bool,
}

fn number(chars: &[char], position: &mut usize) -> Result<Option<usize>> {
    let start = *position;
    let mut value = 0usize;
    while let Some(digit) = chars.get(*position).and_then(|ch| ch.to_digit(10)) {
        if !chars[*position].is_ascii() {
            return Err(error());
        }
        value = value
            .checked_mul(10)
            .and_then(|n| n.checked_add(digit as usize))
            .filter(|n| *n <= LIMIT)
            .ok_or_else(error)?;
        *position += 1;
    }
    Ok((*position != start).then_some(value))
}

fn parse(text: &str) -> Result<Spec> {
    let chars: Vec<_> = text.chars().collect();
    let mut spec = Spec {
        fill: ' ',
        align: '>',
        sign: '-',
        width: 0,
        precision: None,
        kind: 'G',
        grouping: false,
        positive_zero: false,
        zero_padding: false,
    };
    let mut i = 0;
    parse_prefix(&chars, &mut i, &mut spec);
    spec.width = number(&chars, &mut i)?.unwrap_or(0);
    if chars.get(i) == Some(&',') {
        spec.grouping = true;
        i += 1;
    }
    if chars.get(i) == Some(&'.') {
        i += 1;
        spec.precision = Some(number(&chars, &mut i)?.ok_or_else(error)?);
    }
    parse_kind(&chars, &mut i, &mut spec)?;
    Ok(spec)
}

fn parse_kind(chars: &[char], i: &mut usize, spec: &mut Spec) -> Result<()> {
    if let Some(kind) = chars.get(*i) {
        if !"eEfFgGn%".contains(*kind) {
            return Err(error());
        }
        spec.kind = *kind;
        *i += 1;
    }
    if *i != chars.len() || (spec.kind == 'n' && spec.grouping) {
        return Err(error());
    }
    Ok(())
}

fn parse_prefix(chars: &[char], i: &mut usize, spec: &mut Spec) {
    if chars.get(1).is_some_and(|ch| "<>=^".contains(*ch)) {
        spec.fill = chars[0];
        spec.align = chars[1];
        *i = 2;
    } else if chars.first().is_some_and(|ch| "<>=^".contains(*ch)) {
        spec.align = chars[0];
        *i = 1;
    }
    if chars.get(*i).is_some_and(|ch| "+- ".contains(*ch)) {
        spec.sign = chars[*i];
        *i += 1;
    }
    if chars.get(*i) == Some(&'z') {
        spec.positive_zero = true;
        *i += 1;
    }
    if chars.get(*i) == Some(&'0') {
        spec.zero_padding = true;
        spec.fill = '0';
        spec.align = '=';
        *i += 1;
    }
}

fn fixed(coefficient: &BigInt, exponent: i32) -> String {
    let digits = coefficient.abs().to_str_radix(10);
    if exponent >= 0 {
        return format!("{digits}{}", "0".repeat(exponent as usize));
    }
    let point = digits.len() as i32 + exponent;
    if point <= 0 {
        format!("0.{}{digits}", "0".repeat((-point) as usize))
    } else {
        format!(
            "{}.{}",
            &digits[..point as usize],
            &digits[point as usize..]
        )
    }
}

fn scientific(value: &VmRawDecimal, precision: Option<usize>, uppercase: bool) -> String {
    let places = precision.unwrap_or((digits(&value.coefficient) - 1) as usize);
    let exponent = if value.is_zero() {
        value.exponent + places as i32
    } else {
        value.adjusted()
    };
    let coefficient = value.rescale(exponent - places as i32);
    let mut digits = coefficient.abs().to_str_radix(10);
    if value.is_zero() {
        digits = "0".repeat(places + 1);
    }
    let fraction = if places == 0 {
        String::new()
    } else {
        format!(".{}", &digits[1..])
    };
    format!(
        "{}{fraction}{}{exponent:+}",
        &digits[..1],
        if uppercase { 'E' } else { 'e' }
    )
}

fn magnitude(value: &VmRawDecimal, spec: &Spec) -> Result<String> {
    if !value.is_finite() {
        let text = value.to_string().trim_start_matches('-').to_string();
        return Ok(if spec.kind == '%' { text + "%" } else { text });
    }
    bound_output(value, spec)?;
    let mut value = value.clone();
    value.coefficient = value.coefficient.abs();
    value.negative_zero = false;
    if spec.kind == '%' {
        value.exponent += 2;
    }
    let rendered = match spec.kind {
        'f' | 'F' | '%' => {
            let exponent = spec
                .precision
                .map_or(value.exponent.min(0), |p| -(p as i32));
            fixed(&value.rescale(exponent), exponent)
        }
        'e' | 'E' => scientific(&value, spec.precision, spec.kind == 'E'),
        _ => general(&mut value, spec),
    };
    Ok(if spec.kind == '%' {
        rendered + "%"
    } else {
        rendered
    })
}

fn general(value: &mut VmRawDecimal, spec: &Spec) -> String {
    if let Some(precision) = spec.precision {
        let discarded = digits(&value.coefficient) - (precision.max(1) as i32);
        if discarded > 0 {
            let exponent = value.exponent + discarded;
            value.coefficient = value.rescale(exponent);
            value.exponent = exponent;
        }
    }
    let text = value.to_string();
    if spec.kind == 'G' {
        text
    } else {
        text.replace('E', "e")
    }
}

fn bound_output(value: &VmRawDecimal, spec: &Spec) -> Result<()> {
    // Bound output expansion before rescaling or allocating a padded coefficient.
    let places = spec
        .precision
        .unwrap_or(value.exponent.unsigned_abs() as usize);
    let whole = value.adjusted().max(0) as usize + 3;
    if matches!(spec.kind, 'f' | 'F' | '%') && whole.saturating_add(places) > LIMIT {
        return Err(error());
    }
    if spec.precision.is_some_and(|p| p >= LIMIT - 16) {
        return Err(error());
    }
    Ok(())
}

fn group(text: &str) -> String {
    let end = text.find(['.', 'e', 'E', '%']).unwrap_or(text.len());
    let mut output = String::new();
    for (i, ch) in text[..end].chars().enumerate() {
        if i > 0 && (end - i) % 3 == 0 {
            output.push(',');
        }
        output.push(ch);
    }
    output.push_str(&text[end..]);
    output
}

fn sign(value: &VmRawDecimal, spec: &Spec, body: &str) -> &'static str {
    let zero = body
        .split(['e', 'E', '%'])
        .next()
        .unwrap_or("")
        .chars()
        .all(|ch| ch == '0' || ch == '.');
    if value.negative() && !(spec.positive_zero && zero) {
        "-"
    } else {
        match spec.sign {
            '+' => "+",
            ' ' => " ",
            _ => "",
        }
    }
}

fn group_padding(mut body: String, sign: &str, spec: &Spec) -> String {
    if spec.align == '=' && spec.fill == '0' {
        let whole = body.find(['.', 'e', 'E', '%']).unwrap_or(body.len());
        let (mut low, mut high) = (0, spec.width);
        while low < high {
            let middle = (low + high) / 2;
            let width = sign.len() + body.len() + middle + (whole + middle - 1) / 3;
            if width < spec.width {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        body = format!("{}{body}", "0".repeat(low));
    }
    body
}

fn pad(body: &str, sign: &str, spec: &Spec) -> Result<String> {
    let padding = spec.width.saturating_sub(body.len() + sign.len());
    if padding * spec.fill.len_utf8() + body.len() + sign.len() > LIMIT {
        return Err(error());
    }
    let pad = |count| std::iter::repeat_n(spec.fill, count).collect::<String>();
    Ok(match spec.align {
        '<' => format!("{sign}{body}{}", pad(padding)),
        '=' => format!("{sign}{}{body}", pad(padding)),
        '^' => format!(
            "{}{sign}{body}{}",
            pad(padding / 2),
            pad(padding - padding / 2)
        ),
        _ => format!("{}{sign}{body}", pad(padding)),
    })
}

impl VmRawDecimal {
    pub(crate) fn format(&self, spec: &str) -> Result<String> {
        let mut spec = parse(spec)?;
        if !self.is_finite() && spec.zero_padding {
            spec.fill = ' ';
            spec.align = '>';
        }
        let mut body = magnitude(self, &spec)?;
        let sign = sign(self, &spec, &body);
        if spec.grouping && self.is_finite() {
            body = group_padding(body, sign, &spec);
            body = group(&body);
        }
        pad(&body, sign, &spec)
    }
}

pub(super) fn work_cost(text: &str) -> Result<u64> {
    let spec = parse(text)?;
    Ok((spec.width.max(spec.precision.unwrap_or(0)) as u64).saturating_mul(4))
}
