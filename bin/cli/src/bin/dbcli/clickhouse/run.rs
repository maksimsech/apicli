use std::{
    fmt::Display,
    fs,
    hash::{BuildHasher, RandomState},
    process,
    time::{Duration, SystemTime},
};

use apicli::Failure;
use apicli_policy::{Connection, Tls};
use bytes::Bytes;
use reqwest::{Certificate, Client, Error, redirect::Policy};
use secrecy::ExposeSecret;
use url::Url;

use super::args::{ClientArgs, parse};
use crate::shared::{
    Context, Dialect, Statement, mode, read_only, rotate_hint, split, tokens, word, writes,
};

const READONLY: &str = "164";
const AUTHENTICATION: &str = "516";
const TIMEOUT: &str = "60";

pub async fn run(
    connection: &Connection,
    args: &[String],
    context: &mut Context<'_>,
) -> Result<u8, Failure> {
    let (args, params) = parse(args)?;
    context.statements(&args.query);
    let statements = statements(connection, &args)?;
    context.entry.rule = Some(mode(connection).into());
    let client = client(connection)?;
    let [first, rest] = endpoints(connection, &format(&args, context.terminal), &params)?;
    for (index, statement) in statements.iter().enumerate() {
        context.take(connection, args.common.wait)?;
        let endpoint = if index == 0 { &first } else { &rest };
        let body = send(&client, connection, endpoint, statement).await?;
        context.print(&body)?;
    }
    Ok(0)
}

pub fn explain(connection: &Connection, args: &[String]) -> Result<Vec<String>, Failure> {
    let (args, _) = parse(args)?;
    Ok(writes(connection, statements(connection, &args)?.len()))
}

fn statements(connection: &Connection, args: &ClientArgs) -> Result<Vec<Statement>, Failure> {
    let statements = args
        .query
        .iter()
        .flat_map(|query| split(query, Dialect::ClickHouse))
        .collect::<Vec<_>>();
    if statements.is_empty() {
        return Err(Failure::Usage("-q holds no statement".into()));
    }
    if !connection.write {
        for statement in &statements {
            if tokens(&statement.text, Dialect::ClickHouse)
                .first()
                .is_some_and(|lexed| word(&lexed.token, "KILL"))
            {
                return Err(read_only(connection, ", and KILL stops other queries"));
            }
        }
    }
    Ok(statements)
}

fn client(connection: &Connection) -> Result<Client, Failure> {
    let mut builder = Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(10))
        .user_agent("dbcli");
    if let Some(path) = &connection.url.root_cert {
        let unreadable =
            |error: &dyn Display| Failure::Read(format!("the CA file {path}: {error}"));
        let pem = fs::read(path).map_err(|error| unreadable(&error))?;
        let certificates =
            Certificate::from_pem_bundle(&pem).map_err(|error| unreadable(&error))?;
        builder = builder.tls_certs_only(certificates);
    }
    builder
        .build()
        .map_err(|error| Failure::Tls(error.to_string()))
}

fn session() -> String {
    let random = RandomState::new().hash_one((process::id(), SystemTime::now()));
    format!("dbcli-{random:016x}")
}

fn format(args: &ClientArgs, terminal: bool) -> String {
    match &args.format {
        Some(format) => format.clone(),
        None if args.vertical => "Vertical".into(),
        None if terminal => "PrettyCompact".into(),
        None => "TabSeparated".into(),
    }
}

fn endpoints(
    connection: &Connection,
    format: &str,
    params: &[(String, String)],
) -> Result<[Url; 2], Failure> {
    let url = &connection.url;
    let scheme = if url.tls == Tls::Require {
        "https"
    } else {
        "http"
    };
    let host = if url.host.contains(':') {
        format!("[{}]", url.host)
    } else {
        url.host.clone()
    };
    let base = Url::parse(&format!("{scheme}://{host}:{}/", url.port))
        .map_err(|error| Failure::Url(format!("{host}: {error}")))?;
    let session = session();
    let build = |database: bool| {
        let mut endpoint = base.clone();
        {
            let mut pairs = endpoint.query_pairs_mut();
            pairs
                .append_pair("default_format", format)
                .append_pair("session_id", &session);
            if database {
                pairs.append_pair("database", &url.database);
            }
            if !connection.write {
                pairs
                    .append_pair("readonly", "1")
                    .append_pair("max_execution_time", TIMEOUT);
            }
            for (name, value) in params {
                pairs.append_pair(&format!("param_{name}"), value);
            }
        }
        endpoint
    };
    Ok([build(true), build(false)])
}

async fn send(
    client: &Client,
    connection: &Connection,
    endpoint: &Url,
    statement: &Statement,
) -> Result<Bytes, Failure> {
    let sql = statement.text.as_str();
    let url = &connection.url;
    let response = client
        .post(endpoint.clone())
        .header("X-ClickHouse-User", &url.user)
        .header("X-ClickHouse-Key", connection.password.expose_secret())
        .body(sql.to_string())
        .send()
        .await
        .map_err(network)?;
    let status = response.status();
    let code = response
        .headers()
        .get("X-ClickHouse-Exception-Code")
        .and_then(|value| value.to_str().ok())
        .map(String::from);
    let body = response.bytes().await.map_err(network)?;
    if status.is_success() && code.is_none() {
        return Ok(body);
    }
    let text = String::from_utf8_lossy(&body).trim_end().to_string();
    Err(match code.as_deref() {
        Some(READONLY) if !connection.write => read_only(connection, &format!("\n{text}")),
        Some(AUTHENTICATION) => Failure::Connect(format!(
            "{}, port {}: {text}\n{}",
            url.host,
            url.port,
            rotate_hint(&connection.name)
        )),
        _ => {
            let shown = if statement.terminated {
                format!("{sql};")
            } else {
                sql.to_string()
            };
            Failure::Database(received(&text, &shown, &url.host, url.port))
        }
    })
}

fn received(text: &str, sql: &str, host: &str, port: u16) -> String {
    let Some(rest) = text
        .strip_prefix("Code: ")
        .and_then(|rest| rest.split_once(". DB::Exception: "))
    else {
        return text.to_string();
    };
    let (code, message) = rest;
    let (message, version) = match message.rsplit_once(" (version ") {
        Some((message, version)) => (
            message,
            version
                .split([' ', ')'])
                .next()
                .unwrap_or_default()
                .split('.')
                .take(3)
                .collect::<Vec<_>>()
                .join("."),
        ),
        None => (message, String::new()),
    };
    if code == "62" {
        return format!("Code: {code}. DB::Exception: {message}\n");
    }
    format!(
        "Received exception from server (version {version}):\nCode: {code}. DB::Exception: Received from {host}:{port}. DB::Exception: {message}\n(query: {sql})"
    )
}

fn network(error: Error) -> Failure {
    if error.is_timeout() {
        Failure::Timeout
    } else if error.is_connect() {
        Failure::Connect(error.to_string())
    } else {
        Failure::Network(error.to_string())
    }
}
