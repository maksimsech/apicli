use std::net::{Ipv4Addr, Ipv6Addr};

use apicli::Failure;
use chrono::{DateTime, Duration, NaiveDate};
use unicode_width::UnicodeWidthStr;

const PRECISION: i32 = 5;

#[derive(Debug, Clone)]
pub enum Kind {
    Ascii,
    Bigint,
    Blob,
    Boolean,
    Counter,
    Decimal,
    Double,
    Float,
    Int,
    Timestamp,
    Uuid,
    Text,
    Varint,
    Timeuuid,
    Inet,
    Date,
    Time,
    Smallint,
    Tinyint,
    Duration,
    List(Box<Kind>),
    Set(Box<Kind>),
    Map(Box<Kind>, Box<Kind>),
    Udt(Vec<(String, Kind)>),
    Tuple(Vec<Kind>),
    Vector(Box<Kind>, usize),
    Custom,
}

pub struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, position: 0 }
    }

    pub fn take(&mut self, count: usize) -> Result<&'a [u8], Failure> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(bad)?;
        let slice = &self.data[self.position..end];
        self.position = end;
        Ok(slice)
    }

    pub fn short(&mut self) -> Result<u16, Failure> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| bad())?,
        ))
    }

    pub fn int(&mut self) -> Result<i32, Failure> {
        Ok(i32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| bad())?,
        ))
    }

    pub fn string(&mut self) -> Result<String, Failure> {
        let length = usize::from(self.short()?);
        Ok(String::from_utf8_lossy(self.take(length)?).into_owned())
    }

    pub fn bytes(&mut self) -> Result<Option<&'a [u8]>, Failure> {
        let length = self.int()?;
        if length < 0 {
            return Ok(None);
        }
        self.take(length as usize).map(Some)
    }

    pub fn strings(&mut self) -> Result<Vec<String>, Failure> {
        (0..self.short()?).map(|_| self.string()).collect()
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn done(&self) -> bool {
        self.position >= self.data.len()
    }

    pub fn kind(&mut self) -> Result<Kind, Failure> {
        Ok(match self.short()? {
            0x0000 => custom(&self.string()?),
            0x0001 => Kind::Ascii,
            0x0002 => Kind::Bigint,
            0x0003 => Kind::Blob,
            0x0004 => Kind::Boolean,
            0x0005 => Kind::Counter,
            0x0006 => Kind::Decimal,
            0x0007 => Kind::Double,
            0x0008 => Kind::Float,
            0x0009 => Kind::Int,
            0x000B => Kind::Timestamp,
            0x000C => Kind::Uuid,
            0x000D => Kind::Text,
            0x000E => Kind::Varint,
            0x000F => Kind::Timeuuid,
            0x0010 => Kind::Inet,
            0x0011 => Kind::Date,
            0x0012 => Kind::Time,
            0x0013 => Kind::Smallint,
            0x0014 => Kind::Tinyint,
            0x0015 => Kind::Duration,
            0x0020 => Kind::List(Box::new(self.kind()?)),
            0x0021 => Kind::Map(Box::new(self.kind()?), Box::new(self.kind()?)),
            0x0022 => Kind::Set(Box::new(self.kind()?)),
            0x0030 => {
                self.string()?;
                self.string()?;
                let count = self.short()?;
                let mut fields = Vec::new();
                for _ in 0..count {
                    let name = self.string()?;
                    fields.push((name, self.kind()?));
                }
                Kind::Udt(fields)
            }
            0x0031 => {
                let count = self.short()?;
                Kind::Tuple((0..count).map(|_| self.kind()).collect::<Result<_, _>>()?)
            }
            _ => Kind::Custom,
        })
    }

    fn vint(&mut self) -> Result<u64, Failure> {
        let first = self.take(1)?[0];
        let extra = first.leading_ones() as usize;
        let mut value = u64::from(first & (0xffu8.checked_shr(extra as u32).unwrap_or(0)));
        for byte in self.take(extra)? {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(value)
    }

    fn signed(&mut self) -> Result<i64, Failure> {
        let value = self.vint()?;
        Ok(((value >> 1) as i64) ^ -((value & 1) as i64))
    }
}

fn custom(class: &str) -> Kind {
    let class = class.trim();
    if let Some(inner) = class
        .strip_prefix("org.apache.cassandra.db.marshal.VectorType(")
        .and_then(|rest| rest.strip_suffix(')'))
        && let Some((element, size)) = inner.rsplit_once(',')
        && let Ok(size) = size.trim().parse()
    {
        return Kind::Vector(Box::new(custom(element)), size);
    }
    match class.rsplit('.').next().unwrap_or_default() {
        "DurationType" => Kind::Duration,
        "FloatType" => Kind::Float,
        "DoubleType" => Kind::Double,
        "Int32Type" => Kind::Int,
        "LongType" => Kind::Bigint,
        "UTF8Type" => Kind::Text,
        "AsciiType" => Kind::Ascii,
        "BooleanType" => Kind::Boolean,
        "UUIDType" => Kind::Uuid,
        "TimeUUIDType" => Kind::Timeuuid,
        "TimestampType" => Kind::Timestamp,
        "DecimalType" => Kind::Decimal,
        "IntegerType" => Kind::Varint,
        "ShortType" => Kind::Smallint,
        "ByteType" => Kind::Tinyint,
        "SimpleDateType" => Kind::Date,
        "TimeType" => Kind::Time,
        "InetAddressType" => Kind::Inet,
        _ => Kind::Custom,
    }
}

fn bad() -> Failure {
    Failure::Network("bad message from the server".into())
}

pub fn format(kind: &Kind, data: Option<&[u8]>, quote: bool) -> (String, usize) {
    match data {
        None => ("null".into(), 4),
        Some(data) => value(kind, data, quote).unwrap_or_else(|_| {
            let text = format!("0x{}", hex(data));
            let width = text.len();
            (text, width)
        }),
    }
}

pub fn text(data: Option<&[u8]>) -> String {
    data.map(|data| String::from_utf8_lossy(data).into_owned())
        .unwrap_or_default()
}

fn value(kind: &Kind, data: &[u8], quote: bool) -> Result<(String, usize), Failure> {
    let fixed = |size: usize| -> Result<&[u8], Failure> {
        if data.len() == size {
            Ok(data)
        } else {
            Err(bad())
        }
    };
    let collection = |items: Vec<(String, usize)>, open: &str, close: &str, joint: usize| {
        let width = items.iter().map(|(_, width)| width).sum::<usize>() + joint * items.len();
        let text = items
            .into_iter()
            .map(|(text, _)| text)
            .collect::<Vec<_>>()
            .join(", ");
        (format!("{open}{text}{close}"), width)
    };
    let pair = |(key, key_width): (String, usize), (item, item_width): (String, usize)| {
        (format!("{key}: {item}"), key_width + item_width)
    };
    let text = match kind {
        Kind::Ascii | Kind::Text => escape(&String::from_utf8_lossy(data), quote),
        Kind::Bigint | Kind::Counter => {
            i64::from_be_bytes(fixed(8)?.try_into().map_err(|_| bad())?).to_string()
        }
        Kind::Int => i32::from_be_bytes(fixed(4)?.try_into().map_err(|_| bad())?).to_string(),
        Kind::Smallint => i16::from_be_bytes(fixed(2)?.try_into().map_err(|_| bad())?).to_string(),
        Kind::Tinyint => (fixed(1)?[0] as i8).to_string(),
        Kind::Boolean => if fixed(1)?[0] != 0 { "True" } else { "False" }.into(),
        Kind::Blob | Kind::Custom => format!("0x{}", hex(data)),
        Kind::Double => float(f64::from_be_bytes(fixed(8)?.try_into().map_err(|_| bad())?)),
        Kind::Float => float(f64::from(f32::from_be_bytes(
            fixed(4)?.try_into().map_err(|_| bad())?,
        ))),
        Kind::Varint => varint(data),
        Kind::Decimal => {
            let scale = i32::from_be_bytes(
                data.get(..4)
                    .ok_or_else(bad)?
                    .try_into()
                    .map_err(|_| bad())?,
            );
            decimal(&varint(&data[4..]), scale)
        }
        Kind::Uuid | Kind::Timeuuid => {
            let hex = hex(fixed(16)?);
            format!(
                "{}-{}-{}-{}-{}",
                &hex[..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..]
            )
        }
        Kind::Inet => {
            let text = match data.len() {
                4 => Ipv4Addr::from(<[u8; 4]>::try_from(data).map_err(|_| bad())?).to_string(),
                16 => Ipv6Addr::from(<[u8; 16]>::try_from(data).map_err(|_| bad())?).to_string(),
                _ => return Err(bad()),
            };
            quoted(text, quote)
        }
        Kind::Timestamp => {
            let millis = i64::from_be_bytes(fixed(8)?.try_into().map_err(|_| bad())?);
            let text = DateTime::from_timestamp_millis(millis).map_or_else(
                || millis.to_string(),
                |date| date.format("%Y-%m-%d %H:%M:%S%.6f+0000").to_string(),
            );
            quoted(text, quote)
        }
        Kind::Date => {
            let days =
                i64::from(u32::from_be_bytes(fixed(4)?.try_into().map_err(|_| bad())?)) - (1 << 31);
            NaiveDate::from_ymd_opt(1970, 1, 1)
                .and_then(|epoch| epoch.checked_add_signed(Duration::days(days)))
                .map_or_else(
                    || days.to_string(),
                    |date| date.format("%Y-%m-%d").to_string(),
                )
        }
        Kind::Time => {
            let nanos = i64::from_be_bytes(fixed(8)?.try_into().map_err(|_| bad())?);
            let seconds = nanos / 1_000_000_000;
            format!(
                "{:02}:{:02}:{:02}.{:09}",
                seconds / 3600,
                seconds / 60 % 60,
                seconds % 60,
                nanos % 1_000_000_000
            )
        }
        Kind::Duration => {
            let mut reader = Reader::new(data);
            duration(reader.signed()?, reader.signed()?, reader.signed()?)
        }
        Kind::List(element) | Kind::Set(element) => {
            let mut reader = Reader::new(data);
            let mut items = (0..reader.int()?)
                .map(|_| reader.bytes())
                .collect::<Result<Vec<_>, Failure>>()?;
            if matches!(kind, Kind::Set(_)) {
                order(element, &mut items);
            }
            let items = items
                .into_iter()
                .map(|item| format(element, item, true))
                .collect();
            let (open, close) = if matches!(kind, Kind::List(_)) {
                ("[", "]")
            } else {
                ("{", "}")
            };
            return Ok(collection(items, open, close, 2));
        }
        Kind::Map(key, item) => {
            let mut reader = Reader::new(data);
            let mut pairs = (0..reader.int()?)
                .map(|_| Ok((reader.bytes()?, reader.bytes()?)))
                .collect::<Result<Vec<_>, Failure>>()?;
            if sortable(key) {
                pairs.sort_by_key(|(left, _)| sort_key(key, *left));
            }
            let pairs = pairs
                .into_iter()
                .map(|(left, right)| pair(format(key, left, true), format(item, right, true)))
                .collect();
            return Ok(collection(pairs, "{", "}", 4));
        }
        Kind::Udt(fields) => {
            let mut reader = Reader::new(data);
            let mut parts = Vec::new();
            for (name, kind) in fields {
                let value = if reader.done() { None } else { reader.bytes()? };
                let name = escape(name, false);
                let width = name.width();
                parts.push(pair((name, width), format(kind, value, true)));
            }
            return Ok(collection(parts, "{", "}", 4));
        }
        Kind::Tuple(kinds) => {
            let mut reader = Reader::new(data);
            let parts = kinds
                .iter()
                .map(|kind| {
                    Ok(format(
                        kind,
                        if reader.done() { None } else { reader.bytes()? },
                        true,
                    ))
                })
                .collect::<Result<Vec<_>, Failure>>()?;
            return Ok(collection(parts, "(", ")", 2));
        }
        Kind::Vector(element, size) => {
            let mut reader = Reader::new(data);
            let width = match **element {
                Kind::Float | Kind::Int | Kind::Date => Some(4),
                Kind::Double | Kind::Bigint | Kind::Timestamp | Kind::Time => Some(8),
                Kind::Boolean | Kind::Tinyint => Some(1),
                Kind::Smallint => Some(2),
                Kind::Uuid | Kind::Timeuuid => Some(16),
                _ => None,
            };
            let mut items = Vec::new();
            for _ in 0..*size {
                let length = match width {
                    Some(width) => width,
                    None => usize::try_from(reader.vint()?).map_err(|_| bad())?,
                };
                items.push(format(element, Some(reader.take(length)?), true));
            }
            return Ok(collection(items, "[", "]", 2));
        }
    };
    let width = text.width();
    Ok((text, width))
}

fn sortable(kind: &Kind) -> bool {
    matches!(kind, Kind::Inet | Kind::Uuid | Kind::Timeuuid)
}

fn sort_key(kind: &Kind, data: Option<&[u8]>) -> Vec<u8> {
    match kind {
        Kind::Inet => format(kind, data, false).0.into_bytes(),
        _ => data.unwrap_or_default().to_vec(),
    }
}

fn order(kind: &Kind, items: &mut [Option<&[u8]>]) {
    if sortable(kind) {
        items.sort_by_key(|item| sort_key(kind, *item));
    }
}

fn quoted(text: String, quote: bool) -> String {
    if quote { format!("'{text}'") } else { text }
}

fn escape(text: &str, quote: bool) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    if quote {
        out.push('\'');
    }
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\'' if quote => out.push_str("''"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{a0}' => {
                out.push_str(&format!("\\x{:02x}", character as u32))
            }
            _ => out.push(character),
        }
    }
    if quote {
        out.push('\'');
    }
    out
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    let exponent = if value.abs() > f64::EPSILON {
        value.abs().log10().trunc() as i32
    } else {
        i32::MIN
    };
    let precision = if (-4..PRECISION).contains(&exponent) {
        PRECISION + exponent + 1
    } else {
        PRECISION
    };
    general(value, precision.max(1) as usize)
}

fn general(value: f64, precision: usize) -> String {
    if value == 0.0 {
        return if value.is_sign_negative() { "-0" } else { "0" }.into();
    }
    let scientific = format!("{:.*e}", precision - 1, value);
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let exponent = exponent.parse::<i32>().unwrap_or(0);
    let trim = |text: &str| {
        if text.contains('.') {
            text.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            text.to_string()
        }
    };
    if (-4..precision as i32).contains(&exponent) {
        trim(&format!(
            "{:.*}",
            (precision as i32 - 1 - exponent).max(0) as usize,
            value
        ))
    } else {
        let sign = if exponent < 0 { '-' } else { '+' };
        format!("{}e{sign}{:02}", trim(mantissa), exponent.abs())
    }
}

fn varint(data: &[u8]) -> String {
    if data.is_empty() {
        return "0".into();
    }
    let negative = data[0] & 0x80 != 0;
    let mut magnitude = data.to_vec();
    if negative {
        for byte in &mut magnitude {
            *byte = !*byte;
        }
        for byte in magnitude.iter_mut().rev() {
            let (sum, carry) = byte.overflowing_add(1);
            *byte = sum;
            if !carry {
                break;
            }
        }
    }
    let mut digits = Vec::new();
    while magnitude.iter().any(|byte| *byte != 0) {
        let mut remainder = 0u32;
        for byte in &mut magnitude {
            let current = (remainder << 8) | u32::from(*byte);
            *byte = (current / 10) as u8;
            remainder = current % 10;
        }
        digits.push(char::from(b'0' + remainder as u8));
    }
    if digits.is_empty() {
        digits.push('0');
    }
    if negative {
        digits.push('-');
    }
    digits.iter().rev().collect()
}

fn decimal(unscaled: &str, scale: i32) -> String {
    let (sign, digits) = match unscaled.strip_prefix('-') {
        Some(digits) => ("-", digits),
        None => ("", unscaled),
    };
    let exponent = -i64::from(scale);
    let count = digits.len() as i64;
    let adjusted = exponent + count - 1;
    let body = if exponent <= 0 && adjusted >= -6 {
        if exponent == 0 {
            digits.to_string()
        } else if count > -exponent {
            let point = (count + exponent) as usize;
            format!("{}.{}", &digits[..point], &digits[point..])
        } else {
            format!("0.{}{digits}", "0".repeat((-exponent - count) as usize))
        }
    } else {
        let rest = if count > 1 {
            format!(".{}", &digits[1..])
        } else {
            String::new()
        };
        let sign = if adjusted >= 0 { "+" } else { "-" };
        format!("{}{rest}E{sign}{}", &digits[..1], adjusted.abs())
    };
    format!("{sign}{body}")
}

fn duration(months: i64, days: i64, nanos: i64) -> String {
    let mut out = String::new();
    if months < 0 || days < 0 || nanos < 0 {
        out.push('-');
    }
    let mut append = |value: u64, divisor: u64, unit: &str| -> u64 {
        if value == 0 || value < divisor {
            return value;
        }
        out.push_str(&format!("{}{unit}", value / divisor));
        value % divisor
    };
    let rest = append(months.unsigned_abs(), 12, "y");
    append(rest, 1, "mo");
    append(days.unsigned_abs(), 1, "d");
    if nanos != 0 {
        let mut rest = nanos.unsigned_abs();
        for (divisor, unit) in [
            (3_600_000_000_000, "h"),
            (60_000_000_000, "m"),
            (1_000_000_000, "s"),
            (1_000_000, "ms"),
            (1_000, "us"),
            (1, "ns"),
        ] {
            rest = append(rest, divisor, unit);
        }
    }
    out
}
