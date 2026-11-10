use apicli::Failure;
use chrono::{DateTime as Chrono, NaiveDate, NaiveDateTime};
use mongodb::bson::{
    Binary, Bson, DateTime, Decimal128, Document, Regex, Timestamp, Uuid, oid::ObjectId,
    raw::CString, spec::BinarySubtype,
};

pub enum Statement {
    Use(String),
    Show(String),
    Db(Vec<Segment>),
}

pub enum Segment {
    Property(String),
    Call(String, Vec<Bson>),
}

struct Parser {
    chars: Vec<char>,
    position: usize,
}

pub fn parse(source: &str) -> Result<Vec<Statement>, Failure> {
    let mut parser = Parser {
        chars: source.chars().collect(),
        position: 0,
    };
    let mut statements = Vec::new();
    loop {
        parser.space()?;
        if parser.peek().is_none() {
            break;
        }
        if parser.eat(';') {
            continue;
        }
        statements.push(parser.statement()?);
        parser.space()?;
        match parser.peek() {
            None => break,
            Some(';') => parser.position += 1,
            Some(_) => return Err(parser.unexpected()),
        }
    }
    if statements.is_empty() {
        return Err(Failure::Usage(
            "--eval is empty, pass an expression like db.orders.find()".into(),
        ));
    }
    Ok(statements)
}

impl Parser {
    fn statement(&mut self) -> Result<Statement, Failure> {
        let start = self.position;
        let word = self.name().ok_or_else(|| self.unexpected())?;
        match word.as_str() {
            "use" | "show" if self.peek().is_some_and(char::is_whitespace) => {
                self.space()?;
                let begin = self.position;
                while self
                    .peek()
                    .is_some_and(|character| !character.is_whitespace() && character != ';')
                {
                    self.position += 1;
                }
                let argument = self.chars[begin..self.position].iter().collect::<String>();
                if argument.is_empty() {
                    return Err(self.unexpected());
                }
                Ok(if word == "use" {
                    Statement::Use(argument)
                } else {
                    Statement::Show(argument)
                })
            }
            "db" => self.segments().map(Statement::Db),
            _ => {
                self.position = start;
                Err(self.unexpected())
            }
        }
    }

    fn segments(&mut self) -> Result<Vec<Segment>, Failure> {
        let mut segments = Vec::new();
        loop {
            self.space()?;
            let name = if self.eat('.') {
                self.space()?;
                self.name().ok_or_else(|| self.unexpected())?
            } else if self.eat('[') {
                self.space()?;
                let Some(Bson::String(name)) = self.string()? else {
                    return Err(self.unexpected());
                };
                self.space()?;
                self.expect(']')?;
                name
            } else {
                return Ok(segments);
            };
            self.space()?;
            if self.eat('(') {
                segments.push(Segment::Call(name, self.list(')')?));
            } else {
                segments.push(Segment::Property(name));
            }
        }
    }

    fn list(&mut self, close: char) -> Result<Vec<Bson>, Failure> {
        let mut values = Vec::new();
        loop {
            self.space()?;
            if self.eat(close) {
                return Ok(values);
            }
            values.push(self.value()?);
            self.space()?;
            if !self.eat(',') {
                self.space()?;
                self.expect(close)?;
                return Ok(values);
            }
        }
    }

    fn value(&mut self) -> Result<Bson, Failure> {
        self.space()?;
        let Some(character) = self.peek() else {
            return Err(self.unexpected());
        };
        match character {
            '{' => {
                self.position += 1;
                self.object().map(Bson::Document)
            }
            '[' => {
                self.position += 1;
                self.list(']').map(Bson::Array)
            }
            '\'' | '"' | '`' => self.string()?.ok_or_else(|| self.unexpected()),
            '/' => self.regex(),
            '-' | '+' => {
                self.position += 1;
                let value = self.value()?;
                let negative = character == '-';
                match value {
                    Bson::Int32(number) if negative && number == 0 => Ok(Bson::Double(-0.0)),
                    Bson::Int32(number) if negative => Ok(Bson::Int32(-number)),
                    Bson::Double(number) if negative => Ok(number_value(-number)),
                    Bson::Int32(_) | Bson::Double(_) => Ok(value),
                    _ => Err(self.unexpected()),
                }
            }
            '0'..='9' | '.' => self.number(),
            _ => self.word(),
        }
    }

    fn object(&mut self) -> Result<Document, Failure> {
        let mut document = Document::new();
        loop {
            self.space()?;
            if self.eat('}') {
                return Ok(document);
            }
            let key = match self.peek() {
                Some('\'' | '"' | '`') => match self.string()? {
                    Some(Bson::String(key)) => key,
                    _ => return Err(self.unexpected()),
                },
                Some('0'..='9') => match self.number()? {
                    Bson::Int32(number) => number.to_string(),
                    Bson::Double(number) => number.to_string(),
                    _ => return Err(self.unexpected()),
                },
                _ => self.name().ok_or_else(|| self.unexpected())?,
            };
            self.space()?;
            self.expect(':')?;
            let value = self.value()?;
            document.insert(key, value);
            self.space()?;
            if !self.eat(',') {
                self.space()?;
                self.expect('}')?;
                return Ok(document);
            }
        }
    }

    fn word(&mut self) -> Result<Bson, Failure> {
        let start = self.position;
        let mut name = self.name().ok_or_else(|| self.unexpected())?;
        let created = name == "new";
        if created {
            self.space()?;
            name = self.name().ok_or_else(|| self.unexpected())?;
        }
        match name.as_str() {
            "true" if !created => return Ok(Bson::Boolean(true)),
            "false" if !created => return Ok(Bson::Boolean(false)),
            "null" if !created => return Ok(Bson::Null),
            "NaN" if !created => return Ok(Bson::Double(f64::NAN)),
            "Infinity" if !created => return Ok(Bson::Double(f64::INFINITY)),
            "MinKey" | "MaxKey" => {
                self.space()?;
                if self.eat('(') {
                    self.space()?;
                    self.expect(')')?;
                }
                return Ok(if name == "MinKey" {
                    Bson::MinKey
                } else {
                    Bson::MaxKey
                });
            }
            _ => {}
        }
        self.space()?;
        if !self.eat('(') {
            self.position = start;
            return Err(self.unexpected());
        }
        let args = self.list(')')?;
        let invalid = |what: &str| Failure::Usage(format!("{name}() got an invalid {what}"));
        let text = |index: usize| match args.get(index) {
            Some(Bson::String(text)) => Some(text.clone()),
            Some(Bson::Int32(number)) => Some(number.to_string()),
            Some(Bson::Double(number)) => Some(number.to_string()),
            _ => None,
        };
        let value = match name.as_str() {
            "ObjectId" => match text(0) {
                None if args.is_empty() => Bson::ObjectId(ObjectId::new()),
                Some(hex) => {
                    Bson::ObjectId(ObjectId::parse_str(&hex).map_err(|_| invalid("hex string"))?)
                }
                None => return Err(invalid("argument")),
            },
            "ISODate" | "Date" => match args.first() {
                None => Bson::DateTime(DateTime::now()),
                Some(Bson::String(text)) => {
                    Bson::DateTime(date(text).ok_or_else(|| invalid("date"))?)
                }
                Some(Bson::Int32(number)) => {
                    Bson::DateTime(DateTime::from_millis(i64::from(*number)))
                }
                Some(Bson::Double(number)) if number.fract() == 0.0 => {
                    Bson::DateTime(DateTime::from_millis(*number as i64))
                }
                _ => return Err(invalid("date")),
            },
            "NumberLong" | "Long" => Bson::Int64(
                text(0)
                    .and_then(|text| text.parse().ok())
                    .ok_or_else(|| invalid("number"))?,
            ),
            "NumberInt" | "Int32" => Bson::Int32(
                text(0)
                    .and_then(|text| text.parse::<f64>().ok())
                    .filter(|number| number.fract() == 0.0 && number.abs() <= f64::from(i32::MAX))
                    .ok_or_else(|| invalid("number"))? as i32,
            ),
            "NumberDecimal" | "Decimal128" => Bson::Decimal128(
                text(0)
                    .and_then(|text| text.parse::<Decimal128>().ok())
                    .ok_or_else(|| invalid("number"))?,
            ),
            "UUID" => {
                let uuid = match text(0) {
                    None => Uuid::new(),
                    Some(text) => Uuid::parse_str(&text).map_err(|_| invalid("UUID"))?,
                };
                Bson::Binary(Binary::from_uuid(uuid))
            }
            "BinData" => match (args.first(), text(1)) {
                (Some(Bson::Int32(subtype)), Some(data)) => Bson::Binary(
                    Binary::from_base64(
                        &data,
                        BinarySubtype::from(
                            u8::try_from(*subtype).map_err(|_| invalid("subtype"))?,
                        ),
                    )
                    .map_err(|_| invalid("base64 string"))?,
                ),
                _ => return Err(invalid("argument")),
            },
            "Timestamp" => match (args.first(), args.get(1)) {
                (Some(Bson::Document(parts)), None) => {
                    timestamp(parts.get("t"), parts.get("i")).ok_or_else(|| invalid("timestamp"))?
                }
                (Some(time), Some(increment)) => {
                    timestamp(Some(time), Some(increment)).ok_or_else(|| invalid("timestamp"))?
                }
                _ => return Err(invalid("timestamp")),
            },
            "RegExp" => regex(
                &text(0).ok_or_else(|| invalid("pattern"))?,
                &text(1).unwrap_or_default(),
            )
            .ok_or_else(|| invalid("pattern"))?,
            _ => {
                self.position = start;
                return Err(self.unexpected());
            }
        };
        Ok(value)
    }

    fn number(&mut self) -> Result<Bson, Failure> {
        let start = self.position;
        if self.peek() == Some('0') && matches!(self.chars.get(self.position + 1), Some('x' | 'X'))
        {
            self.position += 2;
            let begin = self.position;
            while self
                .peek()
                .is_some_and(|character| character.is_ascii_hexdigit())
            {
                self.position += 1;
            }
            let digits = self.chars[begin..self.position].iter().collect::<String>();
            let number = i64::from_str_radix(&digits, 16).map_err(|_| self.unexpected())?;
            return Ok(number_value(number as f64));
        }
        while self
            .peek()
            .is_some_and(|character| character.is_ascii_digit() || character == '.')
        {
            self.position += 1;
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            self.position += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.position += 1;
            }
            while self
                .peek()
                .is_some_and(|character| character.is_ascii_digit())
            {
                self.position += 1;
            }
        }
        let text = self.chars[start..self.position].iter().collect::<String>();
        let number = text.parse::<f64>().map_err(|_| {
            self.position = start;
            self.unexpected()
        })?;
        Ok(number_value(number))
    }

    fn string(&mut self) -> Result<Option<Bson>, Failure> {
        let Some(quote) = self
            .peek()
            .filter(|character| matches!(character, '\'' | '"' | '`'))
        else {
            return Ok(None);
        };
        let start = self.position;
        self.position += 1;
        let mut text = String::new();
        loop {
            let Some(character) = self.peek() else {
                self.position = start;
                return Err(self.unexpected());
            };
            self.position += 1;
            match character {
                _ if character == quote => return Ok(Some(Bson::String(text))),
                '$' if quote == '`' && self.peek() == Some('{') => {
                    self.position = start;
                    return Err(self.unexpected());
                }
                '\\' => {
                    let Some(escaped) = self.peek() else {
                        return Err(self.unexpected());
                    };
                    self.position += 1;
                    match escaped {
                        'n' => text.push('\n'),
                        't' => text.push('\t'),
                        'r' => text.push('\r'),
                        'b' => text.push('\u{8}'),
                        'f' => text.push('\u{c}'),
                        'v' => text.push('\u{b}'),
                        '0' => text.push('\0'),
                        '\n' => {}
                        'x' => text.push(self.hex(2)?),
                        'u' if self.eat('{') => {
                            let begin = self.position;
                            while self.peek().is_some_and(|character| character != '}') {
                                self.position += 1;
                            }
                            let digits =
                                self.chars[begin..self.position].iter().collect::<String>();
                            self.expect('}')?;
                            text.push(
                                u32::from_str_radix(&digits, 16)
                                    .ok()
                                    .and_then(char::from_u32)
                                    .ok_or_else(|| self.unexpected())?,
                            );
                        }
                        'u' => {
                            let high = self.hex(4)? as u32;
                            if (0xd800..0xdc00).contains(&high) && self.peek() == Some('\\') {
                                self.position += 2;
                                let low = self.hex(4)? as u32;
                                let code = 0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00);
                                text.push(char::from_u32(code).ok_or_else(|| self.unexpected())?);
                            } else {
                                text.push(char::from_u32(high).unwrap_or('\u{fffd}'));
                            }
                        }
                        other => text.push(other),
                    }
                }
                _ => text.push(character),
            }
        }
    }

    fn hex(&mut self, count: usize) -> Result<char, Failure> {
        let end = self.position + count;
        let digits = self
            .chars
            .get(self.position..end)
            .ok_or_else(|| self.unexpected())?
            .iter()
            .collect::<String>();
        self.position = end;
        u32::from_str_radix(&digits, 16)
            .ok()
            .map(|code| char::from_u32(code).unwrap_or('\u{fffd}'))
            .ok_or_else(|| self.unexpected())
    }

    fn regex(&mut self) -> Result<Bson, Failure> {
        let start = self.position;
        self.position += 1;
        let mut pattern = String::new();
        let mut class = false;
        loop {
            let Some(character) = self.peek() else {
                self.position = start;
                return Err(self.unexpected());
            };
            self.position += 1;
            match character {
                '/' if !class => break,
                '\n' => {
                    self.position = start;
                    return Err(self.unexpected());
                }
                '\\' => {
                    pattern.push(character);
                    if let Some(next) = self.peek() {
                        pattern.push(next);
                        self.position += 1;
                    }
                    continue;
                }
                '[' => class = true,
                ']' => class = false,
                _ => {}
            }
            pattern.push(character);
        }
        let begin = self.position;
        while self
            .peek()
            .is_some_and(|character| character.is_ascii_alphabetic())
        {
            self.position += 1;
        }
        let flags = self.chars[begin..self.position].iter().collect::<String>();
        regex(&pattern, &flags).ok_or_else(|| {
            self.position = start;
            self.unexpected()
        })
    }

    fn name(&mut self) -> Option<String> {
        let start = self.position;
        while self.peek().is_some_and(|character| {
            character.is_alphanumeric() || character == '_' || character == '$'
        }) {
            if self.position == start
                && self
                    .peek()
                    .is_some_and(|character| character.is_ascii_digit())
            {
                return None;
            }
            self.position += 1;
        }
        (self.position > start).then(|| self.chars[start..self.position].iter().collect())
    }

    fn space(&mut self) -> Result<(), Failure> {
        loop {
            match (self.peek(), self.chars.get(self.position + 1)) {
                (Some(character), _) if character.is_whitespace() => self.position += 1,
                (Some('/'), Some('/')) => {
                    while self.peek().is_some_and(|character| character != '\n') {
                        self.position += 1;
                    }
                }
                (Some('/'), Some('*')) => {
                    let start = self.position;
                    self.position += 2;
                    loop {
                        match (self.peek(), self.chars.get(self.position + 1)) {
                            (Some('*'), Some('/')) => {
                                self.position += 2;
                                break;
                            }
                            (Some(_), _) => self.position += 1,
                            (None, _) => {
                                self.position = start;
                                return Err(self.unexpected());
                            }
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.position).copied()
    }

    fn eat(&mut self, expected: char) -> bool {
        let found = self.peek() == Some(expected);
        if found {
            self.position += 1;
        }
        found
    }

    fn expect(&mut self, expected: char) -> Result<(), Failure> {
        if self.eat(expected) {
            Ok(())
        } else {
            Err(self.unexpected())
        }
    }

    fn unexpected(&self) -> Failure {
        let near = self.chars[self.position.min(self.chars.len())..]
            .iter()
            .take(24)
            .collect::<String>();
        let near = if near.is_empty() {
            "the end of the expression".to_string()
        } else {
            format!("`{near}`")
        };
        Failure::Usage(format!(
            "dbcli runs mongosh expressions like db.orders.find({{status: 'paid'}}), not JavaScript: stopped at {near}"
        ))
    }
}

fn number_value(number: f64) -> Bson {
    let negative_zero = number == 0.0 && number.is_sign_negative();
    if !negative_zero
        && number.fract() == 0.0
        && number >= f64::from(i32::MIN)
        && number <= f64::from(i32::MAX)
    {
        Bson::Int32(number as i32)
    } else {
        Bson::Double(number)
    }
}

fn timestamp(time: Option<&Bson>, increment: Option<&Bson>) -> Option<Bson> {
    let part = |value: Option<&Bson>| match value {
        Some(Bson::Int32(number)) => u32::try_from(*number).ok(),
        Some(Bson::Double(number)) if number.fract() == 0.0 && *number >= 0.0 => {
            u32::try_from(*number as i64).ok()
        }
        Some(Bson::Int64(number)) => u32::try_from(*number).ok(),
        _ => None,
    };
    Some(Bson::Timestamp(Timestamp {
        time: part(time)?,
        increment: part(increment)?,
    }))
}

fn regex(pattern: &str, flags: &str) -> Option<Bson> {
    let mut options = flags.chars().collect::<Vec<_>>();
    if options.iter().any(|flag| {
        !matches!(
            flag,
            'i' | 'm' | 's' | 'u' | 'x' | 'l' | 'g' | 'y' | 'd' | 'v'
        )
    }) {
        return None;
    }
    options.retain(|flag| matches!(flag, 'i' | 'm' | 's' | 'u' | 'x' | 'l'));
    options.sort_unstable();
    Some(Bson::RegularExpression(Regex {
        pattern: CString::try_from(pattern.to_string()).ok()?,
        options: CString::try_from(options.into_iter().collect::<String>()).ok()?,
    }))
}

fn date(text: &str) -> Option<DateTime> {
    let millis = Chrono::parse_from_rfc3339(text)
        .map(|date| date.timestamp_millis())
        .or_else(|_| {
            NaiveDateTime::parse_from_str(&text.replace(' ', "T"), "%Y-%m-%dT%H:%M:%S%.f")
                .map(|date| date.and_utc().timestamp_millis())
        })
        .or_else(|_| {
            NaiveDateTime::parse_from_str(
                text.replace(' ', "T").trim_end_matches('Z'),
                "%Y-%m-%dT%H:%M",
            )
            .map(|date| date.and_utc().timestamp_millis())
        })
        .or_else(|_| {
            NaiveDate::parse_from_str(text, "%Y-%m-%d").map(|date| {
                date.and_hms_opt(0, 0, 0)
                    .unwrap_or_default()
                    .and_utc()
                    .timestamp_millis()
            })
        })
        .ok()?;
    Some(DateTime::from_millis(millis))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn javascript_is_refused() {
        for source in [
            "let x = 1",
            "const docs = db.orders.find().toArray()",
            "function f() { return 1 }",
            "db.orders.find().forEach(d => print(d))",
            "for (;;) {}",
            "while (true) db.orders.deleteOne({})",
            "load('/tmp/script.js')",
            "require('child_process').execSync('id')",
            "process.exit(0)",
            "db.orders.find({$where: function() { return true }})",
            "db.orders.insertOne({a: `${process.env.HOME}`})",
            "db = connect('mongodb://attacker.example')",
            "Mongo('mongodb://attacker.example')",
            "print(1)",
            "db.orders.find({a: 1 + 1})",
        ] {
            assert!(
                matches!(parse(source), Err(Failure::Usage(_))),
                "{source} was accepted"
            );
        }
    }
}
