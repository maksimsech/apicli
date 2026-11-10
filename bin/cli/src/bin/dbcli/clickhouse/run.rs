use std::{
    fs,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use apicli::Failure;
use apicli_policy::{Connection, Tls};
use reqwest::{Certificate, Client, Error, redirect::Policy};
use secrecy::ExposeSecret;
use url::Url;

use super::args::{ClientArgs, parse};
use crate::{
    call::Context,
    postgres::{describe, mode},
    split::{Statement, Token, split, tokens},
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
    let session = session();
    let format = format(&args, context.terminal);
    for (index, statement) in statements.iter().enumerate() {
        context.take(connection, args.wait)?;
        let request = Request {
            session: &session,
            format: &format,
            params: &params,
            first: index == 0,
        };
        let body = send(&client, connection, &request, statement).await?;
        context.print(&body)?;
    }
    Ok(0)
}

pub fn explain(connection: &Connection, args: &[String]) -> Result<Vec<String>, Failure> {
    let (args, _) = parse(args)?;
    let statements = statements(connection, &args)?;
    let mut lines = vec![
        format!("statements: {}", statements.len()),
        format!("mode: {}", clickhouse_mode(connection)),
    ];
    if !connection.write {
        lines.push(format!(
            "to allow writes, the user can run: dbcli allow add {} write",
            connection.name
        ));
    }
    Ok(lines)
}

fn clickhouse_mode(connection: &Connection) -> &'static str {
    if connection.write {
        describe(connection)
    } else {
        "read-only, the server runs each statement with readonly=1"
    }
}

fn statements(connection: &Connection, args: &ClientArgs) -> Result<Vec<Statement>, Failure> {
    let statements = args
        .query
        .iter()
        .flat_map(|query| split(query, true, false))
        .collect::<Vec<_>>();
    if statements.is_empty() {
        return Err(Failure::Usage("-q holds no statement".into()));
    }
    if !connection.write {
        for statement in &statements {
            let killing = matches!(
                tokens(&statement.text, true).first().map(|lexed| &lexed.token),
                Some(Token::Word(word)) if word.eq_ignore_ascii_case("KILL")
            );
            if killing {
                return Err(Failure::Denied(format!(
                    "denied: {name} is read-only, and KILL stops other queries\nto allow writes, the user can run: dbcli allow add {name} write",
                    name = connection.name
                )));
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
        let pem = fs::read(path)
            .map_err(|error| Failure::Read(format!("the CA file {path}: {error}")))?;
        let certificates = Certificate::from_pem_bundle(&pem)
            .map_err(|error| Failure::Read(format!("the CA file {path}: {error}")))?;
        builder = builder.tls_certs_only(certificates);
    }
    builder
        .build()
        .map_err(|error| Failure::Tls(error.to_string()))
}

fn session() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    format!("dbcli-{}-{nanos:x}", std::process::id())
}

fn format(args: &ClientArgs, terminal: bool) -> String {
    match &args.format {
        Some(format) => format.clone(),
        None if args.vertical => "Vertical".into(),
        None if terminal => "PrettyCompact".into(),
        None => "TabSeparated".into(),
    }
}

struct Request<'a> {
    session: &'a str,
    format: &'a str,
    params: &'a [(String, String)],
    first: bool,
}

async fn send(
    client: &Client,
    connection: &Connection,
    request: &Request<'_>,
    statement: &Statement,
) -> Result<Vec<u8>, Failure> {
    let sql = statement.text.as_str();
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
    let mut query = vec![
        ("default_format".to_string(), request.format.to_string()),
        ("session_id".into(), request.session.to_string()),
    ];
    if request.first {
        query.push(("database".into(), url.database.clone()));
    }
    if !connection.write {
        query.push(("readonly".into(), "1".into()));
        query.push(("max_execution_time".into(), TIMEOUT.into()));
    }
    query.extend(
        request
            .params
            .iter()
            .map(|(name, value)| (format!("param_{name}"), value.clone())),
    );
    let mut endpoint = Url::parse(&format!("{scheme}://{host}:{}/", url.port))
        .map_err(|error| Failure::Url(format!("{host}: {error}")))?;
    endpoint.query_pairs_mut().extend_pairs(&query);
    let response = client
        .post(endpoint)
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
    let body = response.bytes().await.map_err(network)?.to_vec();
    if status.is_success() && code.is_none() {
        return Ok(body);
    }
    let text = String::from_utf8_lossy(&body).trim_end().to_string();
    Err(match code.as_deref() {
        Some(READONLY) if !connection.write => Failure::Denied(format!(
            "denied: {name} is read-only\n{text}\nto allow writes, the user can run: dbcli allow add {name} write",
            name = connection.name
        )),
        Some(AUTHENTICATION) => Failure::Connect(format!(
            "{}, port {}: {text}\nif the password changed, the user can run: dbcli secret rotate {}",
            url.host, url.port, connection.name
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
