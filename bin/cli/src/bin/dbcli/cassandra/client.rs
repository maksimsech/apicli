use std::time::Duration;

use apicli::Failure;
use bytes::{Buf, Bytes, BytesMut};
use fieldkit_policy::Connection;
use secrecy::ExposeSecret;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

use super::value::{Kind, Reader};
use crate::shared::{ConnectionUrl, Io, Tls, dial, lost, rotate_hint, secure};

const VERSION: u8 = 0x04;
const PAGE: i32 = 5000;
const STARTUP: u8 = 0x01;
const READY: u8 = 0x02;
const AUTHENTICATE: u8 = 0x03;
const QUERY: u8 = 0x07;
const RESULT: u8 = 0x08;
const AUTH_RESPONSE: u8 = 0x0F;
const AUTH_SUCCESS: u8 = 0x10;
const ERROR: u8 = 0x00;
const BAD_CREDENTIALS: i32 = 0x0100;

pub struct Rows {
    pub columns: Vec<(String, Kind)>,
    pub rows: Vec<Vec<Option<Vec<u8>>>>,
}

pub struct Reply {
    pub rows: Option<Rows>,
    pub warnings: Vec<String>,
}

pub struct ServerError {
    pub code: i32,
    pub message: String,
}

pub struct Session {
    io: Box<dyn Io>,
    buf: BytesMut,
    limit: Duration,
}

struct Frame {
    opcode: u8,
    body: Bytes,
    warnings: Vec<String>,
}

impl Session {
    pub async fn open(
        connection: &Connection,
        url: &ConnectionUrl,
        connect: Duration,
        limit: Duration,
    ) -> Result<Session, Failure> {
        let mut last = None;
        for (host, port) in &url.hosts {
            match timeout(connect, reach(url, host, *port)).await {
                Ok(Ok(io)) => {
                    let mut session = Session {
                        io,
                        buf: BytesMut::with_capacity(8192),
                        limit,
                    };
                    timeout(connect, session.start(connection, url, host, *port))
                        .await
                        .map_err(|_| Failure::Timeout)??;
                    return Ok(session);
                }
                Ok(Err(failure)) => last = Some(failure),
                Err(_) => last = Some(Failure::Timeout),
            }
        }
        Err(last.unwrap_or_else(|| Failure::Connect("the URL has no hosts".into())))
    }

    async fn start(
        &mut self,
        connection: &Connection,
        url: &ConnectionUrl,
        host: &str,
        port: u16,
    ) -> Result<(), Failure> {
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_be_bytes());
        string(&mut body, "CQL_VERSION");
        string(&mut body, "3.0.0");
        let frame = self.call(STARTUP, &body).await?;
        match frame.opcode {
            READY => return Ok(()),
            AUTHENTICATE => {}
            ERROR => return Err(Failure::Connect(server_error(&frame.body)?.message)),
            _ => return Err(unexpected()),
        }
        let mut token = vec![0];
        token.extend_from_slice(url.user.as_bytes());
        token.push(0);
        token.extend_from_slice(connection.password.expose_secret().as_bytes());
        let mut body = Vec::new();
        body.extend_from_slice(&(token.len() as i32).to_be_bytes());
        body.extend_from_slice(&token);
        let frame = self.call(AUTH_RESPONSE, &body).await?;
        match frame.opcode {
            AUTH_SUCCESS => Ok(()),
            ERROR => {
                let error = server_error(&frame.body)?;
                let mut text = format!("{host}, port {port}: {}", error.message);
                if error.code == BAD_CREDENTIALS {
                    text.push_str(&format!("
{}", rotate_hint(&connection.name)));
                }
                Err(Failure::Connect(text))
            }
            _ => Err(Failure::Connect(
                "the server asks for an authenticator dbcli doesn't support, only PasswordAuthenticator works".into(),
            )),
        }
    }

    pub async fn query(
        &mut self,
        cql: &str,
        consistency: u16,
        serial: u16,
    ) -> Result<Result<Reply, ServerError>, Failure> {
        let mut reply = Reply {
            rows: None,
            warnings: Vec::new(),
        };
        let mut paging: Option<Vec<u8>> = None;
        loop {
            let mut body = Vec::new();
            body.extend_from_slice(&(cql.len() as i32).to_be_bytes());
            body.extend_from_slice(cql.as_bytes());
            body.extend_from_slice(&consistency.to_be_bytes());
            let flags = 0x04 | 0x10 | if paging.is_some() { 0x08 } else { 0 };
            body.push(flags);
            body.extend_from_slice(&PAGE.to_be_bytes());
            if let Some(state) = &paging {
                body.extend_from_slice(&(state.len() as i32).to_be_bytes());
                body.extend_from_slice(state);
            }
            body.extend_from_slice(&serial.to_be_bytes());
            let frame = timeout(self.limit, self.call(QUERY, &body))
                .await
                .map_err(|_| Failure::Timeout)??;
            reply.warnings.extend(frame.warnings);
            match frame.opcode {
                ERROR => return Ok(Err(server_error(&frame.body)?)),
                RESULT => {}
                _ => return Err(unexpected()),
            }
            let mut reader = Reader::new(&frame.body);
            if reader.int()? != 2 {
                return Ok(Ok(reply));
            }
            let flags = reader.int()?;
            let count = reader.int()?;
            paging = if flags & 0x02 != 0 {
                reader.bytes()?.map(<[u8]>::to_vec)
            } else {
                None
            };
            let global = flags & 0x01 != 0;
            if global {
                reader.string()?;
                reader.string()?;
            }
            let mut columns = Vec::new();
            for _ in 0..count {
                if !global {
                    reader.string()?;
                    reader.string()?;
                }
                let name = reader.string()?;
                columns.push((name, reader.kind()?));
            }
            let total = reader.int()?;
            let page = reply.rows.get_or_insert(Rows {
                columns,
                rows: Vec::new(),
            });
            for _ in 0..total {
                let row = (0..count)
                    .map(|_| Ok(reader.bytes()?.map(<[u8]>::to_vec)))
                    .collect::<Result<Vec<_>, Failure>>()?;
                page.rows.push(row);
            }
            if paging.is_none() {
                return Ok(Ok(reply));
            }
        }
    }

    pub async fn close(mut self) {
        let _ = self.io.shutdown().await;
    }

    async fn call(&mut self, opcode: u8, body: &[u8]) -> Result<Frame, Failure> {
        let mut out = vec![VERSION, 0, 0, 0, opcode];
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
        self.io.write_all(&out).await.map_err(lost)?;
        self.io.flush().await.map_err(lost)?;
        loop {
            if self.buf.len() >= 9 {
                let length =
                    u32::from_be_bytes([self.buf[5], self.buf[6], self.buf[7], self.buf[8]])
                        as usize;
                if self.buf.len() >= 9 + length {
                    let flags = self.buf[1];
                    let opcode = self.buf[4];
                    self.buf.advance(9);
                    let body = self.buf.split_to(length).freeze();
                    let mut reader = Reader::new(&body);
                    if flags & 0x02 != 0 {
                        reader.take(16)?;
                    }
                    let warnings = if flags & 0x08 != 0 {
                        reader.strings()?
                    } else {
                        Vec::new()
                    };
                    if flags & 0x04 != 0 {
                        for _ in 0..reader.short()? {
                            reader.string()?;
                            reader.bytes()?;
                        }
                    }
                    let start = reader.position();
                    return Ok(Frame {
                        opcode,
                        body: body.slice(start..),
                        warnings,
                    });
                }
            }
            self.buf.reserve(8192);
            if self.io.read_buf(&mut self.buf).await.map_err(lost)? == 0 {
                return Err(Failure::Network("the server closed the connection".into()));
            }
        }
    }
}

async fn reach(url: &ConnectionUrl, host: &str, port: u16) -> Result<Box<dyn Io>, Failure> {
    let stream = dial(host, port).await?;
    Ok(if url.tls == Tls::Require {
        Box::new(secure(host, url.root_cert.as_deref(), None, "cacert", stream).await?)
    } else {
        Box::new(stream)
    })
}

fn string(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(&(text.len() as u16).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
}

fn server_error(body: &[u8]) -> Result<ServerError, Failure> {
    let mut reader = Reader::new(body);
    Ok(ServerError {
        code: reader.int()?,
        message: reader.string()?,
    })
}

fn unexpected() -> Failure {
    Failure::Network("unexpected message from the server".into())
}
