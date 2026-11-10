use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::DateTime;
use mongodb::bson::{Binary, Bson, Document, Regex, spec::BinarySubtype};

use crate::call::{hex, uuid};

const BREAK: usize = 80;
const COMPACT: usize = 3;
const DEPTH: usize = 6;
const ARRAY: usize = 100;
const STRING: usize = 10000;

struct Context {
    indentation: usize,
    current: usize,
}

pub fn inspect(value: &Bson) -> String {
    let mut context = Context {
        indentation: 0,
        current: 0,
    };
    format(&mut context, value, 0)
}

pub fn js_number(number: f64) -> String {
    if number.is_nan() {
        return "NaN".into();
    }
    if number.is_infinite() {
        return if number > 0.0 {
            "Infinity"
        } else {
            "-Infinity"
        }
        .into();
    }
    if number == 0.0 {
        return if number.is_sign_negative() { "-0" } else { "0" }.into();
    }
    let sign = if number < 0.0 { "-" } else { "" };
    let scientific = format!("{:e}", number.abs());
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let digits = mantissa.replace('.', "");
    let count = digits.len() as i64;
    let point = exponent.parse::<i64>().unwrap_or(0) + 1;
    let text = if count <= point && point <= 21 {
        format!("{digits}{}", "0".repeat((point - count) as usize))
    } else if 0 < point && point <= 21 {
        format!(
            "{}.{}",
            &digits[..point as usize],
            &digits[point as usize..]
        )
    } else if -6 < point && point <= 0 {
        format!("0.{}{digits}", "0".repeat((-point) as usize))
    } else {
        let rest = if count > 1 {
            format!(".{}", &digits[1..])
        } else {
            String::new()
        };
        let power = point - 1;
        let sign = if power >= 0 { "+" } else { "-" };
        format!("{}{rest}e{sign}{}", &digits[..1], power.abs())
    };
    format!("{sign}{text}")
}

pub fn quote(text: &str) -> String {
    let quote = if !text.contains('\'') {
        '\''
    } else if !text.contains('"') {
        '"'
    } else if !text.contains('`') && !text.contains("${") {
        '`'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        let code = character as u32;
        match character {
            '\'' if quote == '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            _ if code < 0x20 || (0x7f..=0x9f).contains(&code) => {
                out.push_str(&format!("\\x{code:02X}"));
            }
            _ => out.push(character),
        }
    }
    out.push(quote);
    out
}

fn format(context: &mut Context, value: &Bson, depth: usize) -> String {
    match value {
        Bson::String(text) => string(context, text),
        Bson::Int32(number) => number.to_string(),
        Bson::Double(number) => js_number(*number),
        Bson::Boolean(value) => value.to_string(),
        Bson::Null => "null".into(),
        Bson::Undefined => "undefined".into(),
        Bson::Int64(number) => format!("Long('{number}')"),
        Bson::Decimal128(number) => format!("Decimal128('{number}')"),
        Bson::ObjectId(id) => format!("ObjectId('{}')", id.to_hex()),
        Bson::DateTime(date) => format!("ISODate('{}')", iso(date.timestamp_millis())),
        Bson::Timestamp(stamp) => {
            format!("Timestamp({{ t: {}, i: {} }})", stamp.time, stamp.increment)
        }
        Bson::MinKey => "MinKey()".into(),
        Bson::MaxKey => "MaxKey()".into(),
        Bson::Binary(binary) => binary_text(binary),
        Bson::RegularExpression(regex) => regex_text(regex),
        Bson::JavaScriptCode(code) => format!("Code({})", quote(code)),
        Bson::JavaScriptCodeWithScope(code) => format!(
            "Code({}, {})",
            quote(&code.code),
            object(context, &code.scope, depth)
        ),
        Bson::Symbol(symbol) => format!("BSONSymbol({})", quote(symbol)),
        Bson::DbPointer(pointer) => format!("{pointer:?}"),
        Bson::Document(document) => object(context, document, depth),
        Bson::Array(items) => array(context, items, depth),
    }
}

fn string(context: &Context, text: &str) -> String {
    let mut length = width(text);
    let mut trailer = String::new();
    let mut text = text;
    if length > STRING {
        let mut units = 0;
        let end = text
            .char_indices()
            .find(|(_, character)| {
                units += character.len_utf16();
                units > STRING
            })
            .map_or(text.len(), |(index, _)| index);
        let remaining = length - width(&text[..end]);
        text = &text[..end];
        length = width(text);
        trailer = format!(
            "... {remaining} more character{}",
            if remaining > 1 { "s" } else { "" }
        );
    }
    if length > 16 && length as i64 > BREAK as i64 - context.indentation as i64 - 4 {
        let joint = format!(" +\n{}", " ".repeat(context.indentation + 2));
        return text
            .split_inclusive('\n')
            .map(quote)
            .collect::<Vec<_>>()
            .join(&joint)
            + &trailer;
    }
    quote(text) + &trailer
}

fn object(context: &mut Context, document: &Document, depth: usize) -> String {
    if document.is_empty() {
        return "{}".into();
    }
    if depth > DEPTH {
        return "[Object]".into();
    }
    let depth = depth + 1;
    context.current = depth;
    let mut output = Vec::with_capacity(document.len());
    for (key, value) in document {
        context.indentation += 2;
        let text = format(context, value, depth);
        context.indentation -= 2;
        output.push(format!("{}: {text}", name(key)));
    }
    reduce(context, output, ("{", "}"), None, depth)
}

fn array(context: &mut Context, items: &[Bson], depth: usize) -> String {
    if items.is_empty() {
        return "[]".into();
    }
    if depth > DEPTH {
        return "[Array]".into();
    }
    let depth = depth + 1;
    context.current = depth;
    let shown = items.len().min(ARRAY);
    let mut output = Vec::with_capacity(shown + 1);
    for item in &items[..shown] {
        context.indentation += 2;
        output.push(format(context, item, depth));
        context.indentation -= 2;
    }
    if items.len() > shown {
        let remaining = items.len() - shown;
        output.push(format!(
            "... {remaining} more item{}",
            if remaining > 1 { "s" } else { "" }
        ));
    }
    reduce(context, output, ("[", "]"), Some(items), depth)
}

fn reduce(
    context: &Context,
    mut output: Vec<String>,
    (open, close): (&str, &str),
    items: Option<&[Bson]>,
    depth: usize,
) -> String {
    let entries = output.len();
    if let Some(items) = items
        && entries > 6
    {
        output = group(context, output, items);
    }
    if context.current - depth < COMPACT && entries == output.len() {
        let start = output.len() + context.indentation + open.len() + 10;
        if below(&output, start) {
            let joined = output.join(", ");
            if !joined.contains('\n') {
                return format!("{open} {joined} {close}");
            }
        }
    }
    let indentation = format!("\n{}", " ".repeat(context.indentation));
    format!(
        "{open}{indentation}  {}{indentation}{close}",
        output.join(&format!(",{indentation}  "))
    )
}

fn below(output: &[String], start: usize) -> bool {
    let mut total = output.len() + start;
    if total + output.len() > BREAK {
        return false;
    }
    for entry in output {
        total += width(entry);
        if total > BREAK {
            return false;
        }
    }
    true
}

fn group(context: &Context, output: Vec<String>, items: &[Bson]) -> Vec<String> {
    let separator = 2;
    let mut length = output.len();
    if ARRAY < output.len() {
        length -= 1;
    }
    let lengths = output[..length]
        .iter()
        .map(|entry| width(entry))
        .collect::<Vec<_>>();
    let total = lengths
        .iter()
        .map(|length| length + separator)
        .sum::<usize>();
    let longest = lengths.iter().copied().max().unwrap_or(0);
    let actual = longest + separator;
    if actual * 3 + context.indentation >= BREAK
        || (total as f64 / actual as f64 <= 5.0 && longest > 6)
    {
        return output;
    }
    let bias = (actual as f64 - total as f64 / output.len() as f64).sqrt();
    let biased = (actual as f64 - 3.0 - bias).max(1.0);
    let columns = ((2.5 * biased * length as f64).sqrt() / biased + 0.5)
        .floor()
        .min(((BREAK - context.indentation) / actual) as f64)
        .min((COMPACT * 4) as f64)
        .min(15.0) as usize;
    if columns <= 1 {
        return output;
    }
    let widths = (0..columns)
        .map(|column| {
            lengths
                .iter()
                .skip(column)
                .step_by(columns)
                .copied()
                .max()
                .unwrap_or(0)
                + separator
        })
        .collect::<Vec<_>>();
    let numbers = items[..output.len()]
        .iter()
        .all(|item| matches!(item, Bson::Int32(_) | Bson::Double(_)));
    let mut grouped = Vec::new();
    for start in (0..length).step_by(columns) {
        let end = (start + columns).min(length);
        let mut line = String::new();
        for index in start..end - 1 {
            line.push_str(&pad(
                &format!("{}, ", output[index]),
                widths[index - start],
                numbers,
            ));
        }
        let last = end - 1;
        if numbers {
            line.push_str(&pad(&output[last], widths[last - start] - separator, true));
        } else {
            line.push_str(&output[last]);
        }
        grouped.push(line);
    }
    if ARRAY < output.len() {
        grouped.push(output[length].clone());
    }
    grouped
}

fn pad(text: &str, size: usize, start: bool) -> String {
    let fill = " ".repeat(size.saturating_sub(width(text)));
    if start {
        format!("{fill}{text}")
    } else {
        format!("{text}{fill}")
    }
}

fn width(text: &str) -> usize {
    text.encode_utf16().count()
}

fn name(key: &str) -> String {
    let mut characters = key.chars();
    let bare = characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_');
    if bare { key.to_string() } else { quote(key) }
}

fn iso(millis: i64) -> String {
    DateTime::from_timestamp_millis(millis).map_or_else(
        || "Invalid Date".into(),
        |date| date.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
    )
}

fn binary_text(binary: &Binary) -> String {
    match (
        binary.subtype,
        <[u8; 16]>::try_from(binary.bytes.as_slice()),
    ) {
        (BinarySubtype::Uuid, Ok(bytes)) => format!("UUID('{}')", uuid(&bytes)),
        (BinarySubtype::Md5, _) => format!("MD5('{}')", hex(&binary.bytes)),
        (subtype, _) => format!(
            "Binary.createFromBase64('{}', {})",
            STANDARD.encode(&binary.bytes),
            u8::from(subtype)
        ),
    }
}

fn regex_text(regex: &Regex) -> String {
    let pattern = regex.pattern.as_str();
    let options = regex.options.as_str();
    if !options
        .chars()
        .all(|flag| matches!(flag, 'i' | 'm' | 's' | 'u'))
    {
        return format!("BSONRegExp({}, {})", quote(pattern), quote(options));
    }
    let mut source = String::new();
    let mut escaped = false;
    for character in pattern.chars() {
        match character {
            '/' if !escaped => source.push_str("\\/"),
            '\n' => source.push_str("\\n"),
            _ => source.push(character),
        }
        escaped = character == '\\' && !escaped;
    }
    if source.is_empty() {
        source.push_str("(?:)");
    }
    format!("/{source}/{options}")
}
