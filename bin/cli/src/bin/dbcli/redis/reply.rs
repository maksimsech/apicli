use apicli::Failure;

#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    Status(Vec<u8>),
    Error(Vec<u8>),
    Integer(i64),
    Bulk(Vec<u8>),
    Nil,
    Array(Vec<Reply>),
    Double(Vec<u8>),
    Bool(bool),
    Big(Vec<u8>),
    Verbatim(Vec<u8>),
    Map(Vec<Reply>),
    Set(Vec<Reply>),
    Push(Vec<Reply>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Standard,
    Raw,
    Csv,
    Json,
}

enum Item {
    Done(Reply),
    Open(u8, usize),
}

struct Frame {
    kind: u8,
    left: usize,
    items: Vec<Reply>,
}

#[derive(Default)]
pub struct Parser {
    stack: Vec<Frame>,
    pub position: usize,
}

impl Parser {
    pub fn next(&mut self, buf: &[u8]) -> Result<Option<Reply>, Failure> {
        loop {
            let Some((item, used)) = item(&buf[self.position..])? else {
                return Ok(None);
            };
            self.position += used;
            let mut value = match item {
                Item::Done(reply) => Some(reply),
                Item::Open(kind, 0) => close(kind, Vec::new()),
                Item::Open(kind, count) => {
                    self.stack.push(Frame {
                        kind,
                        left: count,
                        items: Vec::with_capacity(count.min(1024)),
                    });
                    None
                }
            };
            while let Some(reply) = value.take() {
                let Some(frame) = self.stack.last_mut() else {
                    return Ok(Some(reply));
                };
                frame.items.push(reply);
                frame.left -= 1;
                if frame.left == 0 {
                    let frame = self.stack.pop().unwrap_or_else(|| unreachable!());
                    value = close(frame.kind, frame.items);
                }
            }
        }
    }
}

fn close(kind: u8, items: Vec<Reply>) -> Option<Reply> {
    match kind {
        b'%' => Some(Reply::Map(items)),
        b'~' => Some(Reply::Set(items)),
        b'>' => Some(Reply::Push(items)),
        b'|' => None,
        _ => Some(Reply::Array(items)),
    }
}

fn item(buf: &[u8]) -> Result<Option<(Item, usize)>, Failure> {
    let Some(end) = buf.windows(2).position(|pair| pair == b"\r\n") else {
        return Ok(None);
    };
    if end == 0 {
        return Err(bad());
    }
    let line = &buf[1..end];
    let used = end + 2;
    let done = |reply| Ok(Some((Item::Done(reply), used)));
    match buf[0] {
        b'+' => done(Reply::Status(line.to_vec())),
        b'-' => done(Reply::Error(line.to_vec())),
        b':' => done(Reply::Integer(number(line)?)),
        b',' => done(Reply::Double(line.to_vec())),
        b'(' => done(Reply::Big(line.to_vec())),
        b'_' => done(Reply::Nil),
        b'#' => done(Reply::Bool(line == b"t")),
        b'$' | b'!' | b'=' => {
            let length = number(line)?;
            if length < 0 {
                return done(Reply::Nil);
            }
            let length = usize::try_from(length).map_err(|_| bad())?;
            if buf.len() < used + length + 2 {
                return Ok(None);
            }
            let body = buf[used..used + length].to_vec();
            let used = used + length + 2;
            let reply = match buf[0] {
                b'!' => Reply::Error(body),
                b'=' => Reply::Verbatim(body.get(4..).unwrap_or_default().to_vec()),
                _ => Reply::Bulk(body),
            };
            Ok(Some((Item::Done(reply), used)))
        }
        kind @ (b'*' | b'%' | b'~' | b'>' | b'|') => {
            let count = number(line)?;
            if count < 0 {
                return done(Reply::Nil);
            }
            let count = usize::try_from(count).map_err(|_| bad())?;
            let count = if matches!(kind, b'%' | b'|') {
                count.checked_mul(2).ok_or_else(bad)?
            } else {
                count
            };
            Ok(Some((Item::Open(kind, count), used)))
        }
        _ => Err(bad()),
    }
}

fn number(line: &[u8]) -> Result<i64, Failure> {
    std::str::from_utf8(line)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or_else(bad)
}

fn bad() -> Failure {
    Failure::Network("bad reply from the server".into())
}

impl Reply {
    pub fn text(&self) -> Option<&[u8]> {
        match self {
            Reply::Status(text) | Reply::Bulk(text) | Reply::Verbatim(text) => Some(text),
            _ => None,
        }
    }

    pub fn items(&self) -> &[Reply] {
        match self {
            Reply::Array(items) | Reply::Set(items) | Reply::Map(items) | Reply::Push(items) => {
                items
            }
            _ => &[],
        }
    }
}

pub fn format(reply: &Reply, mode: Mode, verbatim: bool) -> Vec<u8> {
    if verbatim {
        return raw(reply);
    }
    let mut out = match mode {
        Mode::Standard => return standard(reply, b""),
        Mode::Raw => raw(reply),
        Mode::Csv => csv(reply),
        Mode::Json => json(reply),
    };
    out.push(b'\n');
    out
}

fn standard(reply: &Reply, prefix: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    match reply {
        Reply::Error(text) => {
            out.extend_from_slice(b"(error) ");
            out.extend_from_slice(text);
        }
        Reply::Status(text) | Reply::Verbatim(text) => out.extend_from_slice(text),
        Reply::Integer(number) => out.extend_from_slice(format!("(integer) {number}").as_bytes()),
        Reply::Double(text) => {
            out.extend_from_slice(b"(double) ");
            out.extend_from_slice(text);
        }
        Reply::Big(text) => {
            out.extend_from_slice(b"(big number) ");
            out.extend_from_slice(text);
        }
        Reply::Bulk(text) => out.extend_from_slice(&repr(text)),
        Reply::Nil => out.extend_from_slice(b"(nil)"),
        Reply::Bool(value) => out.extend_from_slice(if *value { b"(true)" } else { b"(false)" }),
        Reply::Array(items) | Reply::Map(items) | Reply::Set(items) | Reply::Push(items) => {
            let map = matches!(reply, Reply::Map(_));
            if items.is_empty() {
                out.extend_from_slice(match reply {
                    Reply::Map(_) => b"(empty hash)",
                    Reply::Set(_) => b"(empty set)",
                    Reply::Push(_) => b"(empty push)",
                    _ => b"(empty array)",
                });
                out.push(b'\n');
                return out;
            }
            let count = if map { items.len() / 2 } else { items.len() };
            let width = count.to_string().len();
            let mut nested = prefix.to_vec();
            nested.extend(std::iter::repeat_n(b' ', width + 2));
            let separator = match reply {
                Reply::Set(_) => '~',
                Reply::Map(_) => '#',
                _ => ')',
            };
            let step = if map { 2 } else { 1 };
            for (index, chunk) in items.chunks(step).enumerate() {
                if index > 0 {
                    out.extend_from_slice(prefix);
                }
                out.extend_from_slice(format!("{:>width$}{separator} ", index + 1).as_bytes());
                out.extend_from_slice(&standard(&chunk[0], &nested));
                if let Some(value) = chunk.get(1) {
                    out.pop();
                    out.extend_from_slice(b" => ");
                    out.extend_from_slice(&standard(value, &nested));
                }
            }
            return out;
        }
    }
    out.push(b'\n');
    out
}

fn raw(reply: &Reply) -> Vec<u8> {
    let mut out = Vec::new();
    match reply {
        Reply::Nil => {}
        Reply::Error(text) => {
            out.extend_from_slice(text);
            out.push(b'\n');
        }
        Reply::Status(text)
        | Reply::Bulk(text)
        | Reply::Verbatim(text)
        | Reply::Double(text)
        | Reply::Big(text) => out.extend_from_slice(text),
        Reply::Bool(value) => out.extend_from_slice(if *value { b"(true)" } else { b"(false)" }),
        Reply::Integer(number) => out.extend_from_slice(number.to_string().as_bytes()),
        Reply::Array(items) | Reply::Set(items) | Reply::Push(items) => {
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b'\n');
                }
                out.extend_from_slice(&raw(item));
            }
        }
        Reply::Map(items) => {
            for (index, pair) in items.chunks(2).enumerate() {
                if index > 0 {
                    out.push(b'\n');
                }
                out.extend_from_slice(&raw(&pair[0]));
                out.push(b' ');
                if let Some(value) = pair.get(1) {
                    out.extend_from_slice(&raw(value));
                }
            }
        }
    }
    out
}

fn csv(reply: &Reply) -> Vec<u8> {
    let mut out = Vec::new();
    match reply {
        Reply::Error(text) => {
            out.extend_from_slice(b"ERROR,");
            out.extend_from_slice(&repr(text));
        }
        Reply::Status(text) | Reply::Bulk(text) | Reply::Verbatim(text) => {
            out.extend_from_slice(&repr(text));
        }
        Reply::Integer(number) => out.extend_from_slice(number.to_string().as_bytes()),
        Reply::Double(text) | Reply::Big(text) => out.extend_from_slice(text),
        Reply::Nil => out.extend_from_slice(b"NULL"),
        Reply::Bool(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
        Reply::Array(items) | Reply::Map(items) | Reply::Set(items) | Reply::Push(items) => {
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(&csv(item));
            }
        }
    }
    out
}

fn json(reply: &Reply) -> Vec<u8> {
    let mut out = Vec::new();
    match reply {
        Reply::Error(text) => {
            out.extend_from_slice(b"error:");
            out.extend_from_slice(&repr(text));
        }
        Reply::Status(text) => out.extend_from_slice(&repr(text)),
        Reply::Bulk(text) | Reply::Verbatim(text) => out.extend_from_slice(&json_string(text)),
        Reply::Integer(number) => out.extend_from_slice(number.to_string().as_bytes()),
        Reply::Double(text) | Reply::Big(text) => out.extend_from_slice(text),
        Reply::Nil => out.extend_from_slice(b"null"),
        Reply::Bool(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
        Reply::Array(items) | Reply::Set(items) | Reply::Push(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(&json(item));
            }
            out.push(b']');
        }
        Reply::Map(items) => {
            out.push(b'{');
            for (index, pair) in items.chunks(2).enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                let key = json(&pair[0]);
                if key.first() == Some(&b'"') {
                    out.extend_from_slice(&key);
                } else {
                    out.extend_from_slice(&json_string(&key));
                }
                out.push(b':');
                if let Some(value) = pair.get(1) {
                    out.extend_from_slice(&json(value));
                }
            }
            out.push(b'}');
        }
    }
    out
}

pub fn repr(text: &[u8]) -> Vec<u8> {
    let mut out = vec![b'"'];
    for &byte in text {
        match byte {
            b'\\' | b'"' => out.extend_from_slice(&[b'\\', byte]),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x07 => out.extend_from_slice(b"\\a"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x20..=0x7e => out.push(byte),
            _ => out.extend_from_slice(format!("\\x{byte:02x}").as_bytes()),
        }
    }
    out.push(b'"');
    out
}

fn json_string(text: &[u8]) -> Vec<u8> {
    let mut out = vec![b'"'];
    for &byte in text {
        match byte {
            b'\\' | b'"' => out.extend_from_slice(&[b'\\', byte]),
            b'\n' => out.extend_from_slice(b"\\n"),
            0x0c => out.extend_from_slice(b"\\f"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x00..=0x1f => out.extend_from_slice(format!("\\u{byte:04x}").as_bytes()),
            _ => out.push(byte),
        }
    }
    out.push(b'"');
    out
}
