use std::{collections::BTreeMap, io, time::Duration};

use apicli::Failure;
use bytes::BytesMut;
use fallible_iterator::FallibleIterator;
use fieldkit_policy::Connection;
use postgres_protocol::{
    IsNull,
    authentication::{
        md5_hash,
        sasl::{ChannelBinding, SCRAM_SHA_256, ScramSha256},
    },
    message::{
        backend::{ErrorFields, Message},
        frontend,
    },
};
use secrecy::ExposeSecret;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use unicode_width::UnicodeWidthStr;

use super::output::Column;
use crate::shared::{ConnectionUrl, Io, Tls, dial, lost, rotate_hint, secure};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const STATEMENT_TIMEOUT: &str = "60s";
pub const READ_ONLY: &str = "25006";

#[derive(Default)]
pub struct Reply {
    pub columns: Option<Vec<Column>>,
    pub rows: Vec<Vec<Option<String>>>,
    pub copy: Vec<u8>,
    pub copy_out: bool,
    pub tag: Option<String>,
    pub error: Option<ServerError>,
}

#[derive(Default)]
pub struct ServerError {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub detail: Option<String>,
    pub hint: Option<String>,
    pub context: Option<String>,
    pub position: Option<usize>,
}

pub struct Session {
    io: Box<dyn Io>,
    buf: BytesMut,
    status: u8,
    read_only: bool,
    pub tls: bool,
    pub pid: i32,
    pub parameters: BTreeMap<String, String>,
    pub notices: Vec<String>,
}

impl Session {
    pub async fn open(connection: &Connection, url: &ConnectionUrl) -> Result<Session, Failure> {
        timeout(CONNECT_TIMEOUT, Session::start(connection, url))
            .await
            .map_err(|_| Failure::Timeout)?
    }

    async fn start(connection: &Connection, url: &ConnectionUrl) -> Result<Session, Failure> {
        let mut stream = dial(&url.host, url.port).await?;
        let mut tls = false;
        let io: Box<dyn Io> = if url.tls == Tls::Disable {
            Box::new(stream)
        } else {
            let mut out = BytesMut::new();
            frontend::ssl_request(&mut out);
            stream.write_all(&out).await.map_err(lost)?;
            let mut answer = [0u8; 1];
            stream.read_exact(&mut answer).await.map_err(lost)?;
            match (answer[0], url.tls) {
                (b'S', _) => {
                    tls = true;
                    Box::new(
                        secure(
                            &url.host,
                            url.root_cert.as_deref(),
                            Some(b"postgresql"),
                            "sslrootcert",
                            stream,
                        )
                        .await?,
                    )
                }
                (b'N', Tls::Prefer) => Box::new(stream),
                (b'N', _) => {
                    return Err(Failure::Tls(format!(
                        "{} does not accept TLS, which sslmode=require needs",
                        url.host
                    )));
                }
                _ => {
                    return Err(Failure::Connect(format!(
                        "{} gave an unexpected answer to the TLS request",
                        url.host
                    )));
                }
            }
        };
        let mut session = Session {
            io,
            buf: BytesMut::with_capacity(8192),
            status: b'I',
            read_only: !connection.write,
            tls,
            pid: 0,
            parameters: BTreeMap::new(),
            notices: Vec::new(),
        };
        session.startup(connection, url).await?;
        Ok(session)
    }

    async fn startup(
        &mut self,
        connection: &Connection,
        url: &ConnectionUrl,
    ) -> Result<(), Failure> {
        let mut parameters = vec![
            ("user", url.user.as_str()),
            ("database", url.database.as_str()),
            ("application_name", "dbcli"),
            ("client_encoding", "UTF8"),
        ];
        if self.read_only {
            parameters.push(("default_transaction_read_only", "on"));
            parameters.push(("statement_timeout", STATEMENT_TIMEOUT));
        }
        let mut out = BytesMut::new();
        frontend::startup_message(parameters, &mut out).map_err(nul)?;
        self.send(&out).await?;
        let password = connection.password.expose_secret().as_bytes();
        let mut scram = None;
        loop {
            let mut out = BytesMut::new();
            match self.next().await? {
                Message::AuthenticationOk | Message::NoticeResponse(_) => {}
                Message::AuthenticationCleartextPassword => {
                    frontend::password_message(password, &mut out).map_err(nul)?;
                }
                Message::AuthenticationMd5Password(body) => {
                    let hash = md5_hash(url.user.as_bytes(), password, body.salt());
                    frontend::password_message(hash.as_bytes(), &mut out).map_err(nul)?;
                }
                Message::AuthenticationSasl(body) => {
                    let mechanisms = body
                        .mechanisms()
                        .map(|mechanism| Ok(mechanism.to_string()))
                        .collect::<Vec<_>>()
                        .map_err(protocol)?;
                    if !mechanisms
                        .iter()
                        .any(|mechanism| mechanism == SCRAM_SHA_256)
                    {
                        return Err(unsupported_auth());
                    }
                    let client = ScramSha256::new(password, ChannelBinding::unsupported());
                    frontend::sasl_initial_response(SCRAM_SHA_256, client.message(), &mut out)
                        .map_err(nul)?;
                    scram = Some(client);
                }
                Message::AuthenticationSaslContinue(body) => {
                    let client = scram.as_mut().ok_or_else(unexpected)?;
                    client.update(body.data()).map_err(refused)?;
                    frontend::sasl_response(client.message(), &mut out).map_err(nul)?;
                }
                Message::AuthenticationSaslFinal(body) => {
                    let client = scram.as_mut().ok_or_else(unexpected)?;
                    client.finish(body.data()).map_err(refused)?;
                }
                Message::BackendKeyData(body) => self.pid = body.process_id(),
                Message::ParameterStatus(body) => {
                    let name = body.name().map_err(protocol)?.to_string();
                    let value = body.value().map_err(protocol)?.to_string();
                    self.parameters.insert(name, value);
                }
                Message::ReadyForQuery(body) => {
                    self.status = body.status();
                    return Ok(());
                }
                Message::ErrorResponse(body) => {
                    let error = ServerError::parse(body.fields())?;
                    let mut text = format!(
                        "connection to server at \"{}\", port {} failed: {}:  {}",
                        url.host, url.port, error.severity, error.message
                    );
                    if error.code == "28P01" {
                        text.push_str(&format!(
                            "
{}",
                            rotate_hint(&connection.name)
                        ));
                    }
                    return Err(Failure::Connect(text));
                }
                _ => return Err(unsupported_auth()),
            }
            if !out.is_empty() {
                self.send(&out).await?;
            }
        }
    }

    pub async fn query(&mut self, sql: &str) -> Result<Reply, Failure> {
        if self.read_only {
            self.begin().await?;
        }
        let mut out = BytesMut::new();
        frontend::parse("", sql, [], &mut out).map_err(nul)?;
        frontend::bind("", "", [], [(); 0], |(), _| Ok(IsNull::No), [], &mut out)
            .map_err(|_| nul(io::Error::other("bind")))?;
        frontend::describe(b'P', "", &mut out).map_err(nul)?;
        frontend::execute("", 0, &mut out).map_err(nul)?;
        frontend::sync(&mut out);
        self.send(&out).await?;
        let reply = self.collect().await?;
        if self.read_only {
            self.control("ROLLBACK").await?;
        }
        Ok(reply)
    }

    pub fn major_version(&self) -> u32 {
        self.parameters
            .get("server_version")
            .and_then(|version| {
                version
                    .split(|character: char| !character.is_ascii_digit())
                    .next()?
                    .parse()
                    .ok()
            })
            .unwrap_or(0)
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    pub async fn close(mut self) {
        let mut out = BytesMut::new();
        frontend::terminate(&mut out);
        let _ = self.send(&out).await;
        let _ = self.io.shutdown().await;
    }

    async fn begin(&mut self) -> Result<(), Failure> {
        if self.status != b'I' {
            return Err(Failure::Integrity(
                "the connection was not idle before a read-only transaction".into(),
            ));
        }
        self.control("BEGIN READ ONLY").await?;
        if self.status != b'T' {
            return Err(Failure::Integrity(
                "could not start a read-only transaction".into(),
            ));
        }
        Ok(())
    }

    async fn control(&mut self, sql: &str) -> Result<(), Failure> {
        let mut out = BytesMut::new();
        frontend::query(sql, &mut out).map_err(nul)?;
        self.send(&out).await?;
        let count = self.notices.len();
        let reply = self.collect().await?;
        self.notices.truncate(count);
        match reply.error {
            Some(error) => Err(Failure::Database(error.render(None))),
            None => Ok(()),
        }
    }

    async fn collect(&mut self) -> Result<Reply, Failure> {
        let mut reply = Reply::default();
        loop {
            match self.next().await? {
                Message::RowDescription(body) => {
                    let columns = body
                        .fields()
                        .map(|field| {
                            Ok(Column {
                                name: field.name().to_string(),
                                type_oid: field.type_oid(),
                            })
                        })
                        .collect::<Vec<_>>()
                        .map_err(protocol)?;
                    reply.columns = Some(columns);
                }
                Message::DataRow(body) => {
                    let row = body
                        .ranges()
                        .map(|range| {
                            Ok(range.map(|range| {
                                String::from_utf8_lossy(&body.buffer()[range]).into_owned()
                            }))
                        })
                        .collect::<Vec<_>>()
                        .map_err(protocol)?;
                    reply.rows.push(row);
                }
                Message::CommandComplete(body) => {
                    reply.tag = Some(body.tag().map_err(protocol)?.to_string());
                }
                Message::CopyOutResponse(_) => reply.copy_out = true,
                Message::CopyData(body) => reply.copy.extend_from_slice(body.data()),
                Message::CopyInResponse(_) => {
                    let mut out = BytesMut::new();
                    frontend::copy_fail("dbcli does not send COPY data, use INSERT", &mut out)
                        .map_err(nul)?;
                    frontend::sync(&mut out);
                    self.send(&out).await?;
                }
                Message::ErrorResponse(body) => {
                    reply.error = Some(ServerError::parse(body.fields())?);
                }
                Message::NoticeResponse(body) => {
                    let mut notice = ServerError::parse(body.fields())?;
                    notice.context = None;
                    self.notices.push(notice.render(None));
                }
                Message::ParameterStatus(body) => {
                    let name = body.name().map_err(protocol)?.to_string();
                    let value = body.value().map_err(protocol)?.to_string();
                    self.parameters.insert(name, value);
                }
                Message::ReadyForQuery(body) => {
                    self.status = body.status();
                    return Ok(reply);
                }
                Message::ParseComplete
                | Message::BindComplete
                | Message::CloseComplete
                | Message::NoData
                | Message::EmptyQueryResponse
                | Message::PortalSuspended
                | Message::CopyDone
                | Message::NotificationResponse(_) => {}
                _ => return Err(unexpected()),
            }
        }
    }

    async fn send(&mut self, out: &[u8]) -> Result<(), Failure> {
        self.io.write_all(out).await.map_err(lost)?;
        self.io.flush().await.map_err(lost)
    }

    async fn next(&mut self) -> Result<Message, Failure> {
        loop {
            if let Some(message) = Message::parse(&mut self.buf).map_err(protocol)? {
                return Ok(message);
            }
            self.buf.reserve(8192);
            if self.io.read_buf(&mut self.buf).await.map_err(lost)? == 0 {
                return Err(Failure::Network("the server closed the connection".into()));
            }
        }
    }
}

impl ServerError {
    fn parse(mut fields: ErrorFields) -> Result<ServerError, Failure> {
        let mut error = ServerError::default();
        while let Some(field) = fields.next().map_err(protocol)? {
            let value = String::from_utf8_lossy(field.value_bytes()).into_owned();
            match field.type_() {
                b'S' => error.severity = value,
                b'V' if error.severity.is_empty() => error.severity = value,
                b'C' => error.code = value,
                b'M' => error.message = value,
                b'D' => error.detail = Some(value),
                b'H' => error.hint = Some(value),
                b'W' => error.context = Some(value),
                b'P' => error.position = value.parse().ok(),
                _ => {}
            }
        }
        Ok(error)
    }

    pub fn render(&self, sql: Option<&str>) -> String {
        let mut lines = vec![format!("{}:  {}", self.severity, self.message)];
        if let (Some(sql), Some(position)) = (sql, self.position)
            && let Some(location) = locate(sql, position)
        {
            lines.push(location);
        }
        for (label, value) in [
            ("DETAIL", &self.detail),
            ("HINT", &self.hint),
            ("CONTEXT", &self.context),
        ] {
            if let Some(value) = value {
                lines.push(format!("{label}:  {value}"));
            }
        }
        lines.join("\n")
    }
}

fn locate(sql: &str, position: usize) -> Option<String> {
    let index = position.checked_sub(1)?;
    let mut start = 0;
    for (number, line) in sql.split('\n').enumerate() {
        let line = line.trim_end_matches('\r');
        let length = line.chars().count();
        if index <= start + length {
            let prefix = format!("LINE {}: ", number + 1);
            let before = line.chars().take(index - start).collect::<String>();
            return Some(format!(
                "{prefix}{line}\n{}^",
                " ".repeat(prefix.len() + before.width())
            ));
        }
        start += length + 1;
    }
    None
}

fn protocol(error: io::Error) -> Failure {
    Failure::Network(format!("bad message from the server: {error}"))
}

fn nul(_: io::Error) -> Failure {
    Failure::Usage("the statement contains a NUL byte".into())
}

fn refused(error: io::Error) -> Failure {
    Failure::Connect(format!("password authentication failed: {error}"))
}

fn unexpected() -> Failure {
    Failure::Network("unexpected message from the server".into())
}

fn unsupported_auth() -> Failure {
    Failure::Connect(
        "the server asks for an authentication method dbcli doesn't support, only password, md5 and SCRAM-SHA-256 work".into(),
    )
}
