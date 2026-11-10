use std::{
    io::{IsTerminal, Write, stderr, stdout},
    iter::once,
    time::Instant,
};

use apicli::{Entry, Failure, Refused, record, take, usage};
use apicli_policy::{Connection, Engine, Redactor, Vault};
use apicli_vault::Store;
use clap::{ArgAction, Args, Parser, parser::ValueSource};

use crate::{
    cassandra, clickhouse, mongo, postgres, redis,
    secret::{add_hint, write_hint},
};

const MASK: &str = "[dbcli:redacted]";

#[derive(Debug, Args)]
pub struct Common {
    #[arg(
        long,
        value_name = "SECONDS",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "30",
        help = "Wait up to SECONDS (default 30) for the rate limit instead of failing"
    )]
    pub wait: Option<f64>,
    #[arg(long, action = ArgAction::Help, help = "Print help")]
    help: Option<bool>,
}

pub struct Context<'a> {
    pub store: &'a Store,
    pub redactor: Redactor,
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    pub entry: &'a mut Entry,
    pub terminal: bool,
}

impl<'a> Context<'a> {
    pub fn new(
        store: &'a Store,
        vault: &Vault,
        out: &'a mut dyn Write,
        err: &'a mut dyn Write,
        entry: &'a mut Entry,
        terminal: bool,
    ) -> Context<'a> {
        Context {
            store,
            redactor: redactor(vault),
            out,
            err,
            entry,
            terminal,
        }
    }

    pub fn take(&self, connection: &Connection, wait: Option<f64>) -> Result<(), Failure> {
        take(
            self.store,
            &key(&connection.name),
            &connection.name,
            &connection.limits(),
            wait,
        )
    }

    pub fn print(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        emit(self.out, &self.redactor, bytes)
    }

    pub fn warn(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        emit(self.err, &self.redactor, bytes)
    }

    pub fn clean(&self, text: &str) -> String {
        self.redactor.redact_str(text)
    }

    pub fn statements(&mut self, statements: &[String]) {
        self.entry.statements = statements
            .iter()
            .map(|statement| self.clean(statement))
            .collect();
    }
}

fn emit(out: &mut dyn Write, redactor: &Redactor, bytes: &[u8]) -> Result<(), Failure> {
    out.write_all(&redactor.redact(bytes))
        .and_then(|_| out.flush())
        .map_err(|error| Failure::Write(error.to_string()))
}

pub async fn send(name: &str, args: &[String]) -> Result<u8, Failure> {
    let store = Store::open()?;
    let vault = store.load()?;
    let mut entry = Entry::start();
    let started = Instant::now();
    let terminal = stdout().is_terminal();
    let mut out = stdout().lock();
    let mut err = stderr().lock();
    let mut context = Context::new(&store, &vault, &mut out, &mut err, &mut entry, terminal);
    let result = perform(name, args, &vault, &mut context).await;
    entry.ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match &result {
        Ok(_) => entry.outcome = "sent".into(),
        Err(failure) => {
            entry.outcome = failure.outcome().into();
            entry.error = failure.to_string().lines().next().map(String::from);
        }
    }
    record("dbcli", &store, &entry, vault.policy.log_limit_mb);
    result
}

pub async fn perform(
    name: &str,
    args: &[String],
    vault: &Vault,
    context: &mut Context<'_>,
) -> Result<u8, Failure> {
    context.entry.connection = Some(name.to_string());
    let connection = find(vault, name)?;
    let result = match connection.url.engine {
        Engine::Postgres => postgres::run(connection, args, context).await,
        Engine::Redis => redis::run(connection, args, context).await,
        Engine::Mongo => mongo::run(connection, args, context).await,
        Engine::Cassandra => cassandra::run(connection, args, context).await,
        Engine::ClickHouse => clickhouse::run(connection, args, context).await,
    };
    result.map_err(|failure| scrub(failure, &context.redactor))
}

pub async fn explain(connection: &Connection, args: &[String]) -> Result<Vec<String>, Failure> {
    match connection.url.engine {
        Engine::Postgres => postgres::explain(connection, args),
        Engine::Redis => redis::explain(connection, args).await,
        Engine::Mongo => mongo::explain(connection, args),
        Engine::Cassandra => cassandra::explain(connection, args),
        Engine::ClickHouse => clickhouse::explain(connection, args),
    }
}

pub fn engine_args<T: Parser>(args: &[String], refused: &[Refused]) -> Result<T, Failure> {
    let command = refused
        .iter()
        .fold(T::command(), |command, refused| command.arg(refused.arg()));
    let matches = command
        .try_get_matches_from(once("dbcli NAME".to_string()).chain(args.iter().cloned()))
        .map_err(|error| usage("dbcli NAME", error))?;
    if let Some(refused) = refused
        .iter()
        .find(|refused| matches.value_source(refused.long) == Some(ValueSource::CommandLine))
    {
        return Err(refused.failure());
    }
    T::from_arg_matches(&matches).map_err(|error| usage("dbcli NAME", error))
}

pub fn find<'a>(vault: &'a Vault, name: &str) -> Result<&'a Connection, Failure> {
    vault.connection(name).ok_or_else(|| {
        let names = vault
            .connections
            .iter()
            .map(|connection| connection.name.as_str())
            .collect::<Vec<_>>();
        let known = if names.is_empty() {
            "no connections are configured yet".to_string()
        } else {
            format!("configured: {}", names.join(", "))
        };
        Failure::Unconfigured(format!(
            "{name} is not configured\n{known}\nto add it, the user can run: {}",
            add_hint(name)
        ))
    })
}

pub fn key(name: &str) -> String {
    format!("db:{name}")
}

pub fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

pub fn mode(connection: &Connection) -> &'static str {
    match (connection.url.engine.write_flag(), connection.write) {
        (true, true) => "read-write",
        (true, false) => "read-only",
        _ if connection.allow.is_empty() => "read-only",
        _ => "rules",
    }
}

pub fn describe(connection: &Connection) -> &'static str {
    match connection.url.engine {
        engine if engine.write_flag() && connection.write => "read-write, each statement commits",
        Engine::Postgres => "read-only, each statement runs in a read-only transaction",
        Engine::ClickHouse => "read-only, the server runs each statement with readonly=1",
        _ if connection.allow.is_empty() => "read-only, other commands need an allow rule",
        _ => "reads, plus what the allow rules below match",
    }
}

pub fn writes(connection: &Connection, statements: usize) -> Vec<String> {
    let mut lines = vec![
        format!("statements: {statements}"),
        format!("mode: {}", describe(connection)),
    ];
    if !connection.write {
        lines.push(write_hint(&connection.name));
    }
    lines
}

pub fn read_only(connection: &Connection, detail: &str) -> Failure {
    Failure::Denied(format!(
        "denied: {} is read-only{detail}\n{}",
        connection.name,
        write_hint(&connection.name)
    ))
}

pub fn not_allowed(
    connection: &Connection,
    reads: &str,
    action: &str,
    on: Option<&str>,
    target: Option<&str>,
) -> Failure {
    let name = &connection.name;
    let on = on.map(|on| format!(" on {on}")).unwrap_or_default();
    let target = target
        .map(|target| format!(" {}", quote(target)))
        .unwrap_or_default();
    Failure::Denied(format!(
        "denied: {name} allows {reads} only, and no allow rule covers {action}{on}\nto allow it, the user can run: dbcli allow add {name} {}{target}",
        quote(action)
    ))
}

pub fn summary(rules: impl IntoIterator<Item = Option<String>>) -> String {
    let mut seen = Vec::new();
    for rule in rules {
        let rule = rule.unwrap_or_else(|| "read".into());
        if !seen.contains(&rule) {
            seen.push(rule);
        }
    }
    seen.join(", ")
}

pub fn hex(data: &[u8]) -> String {
    let mut text = String::with_capacity(data.len() * 2);
    for byte in data {
        text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        text.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    text
}

pub fn uuid(data: &[u8; 16]) -> String {
    let hex = hex(data);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

pub fn redactor(vault: &Vault) -> Redactor {
    Redactor::new(MASK, vault.secrets())
}

pub fn scrub(failure: Failure, redactor: &Redactor) -> Failure {
    let clean = |text: String| redactor.redact_str(&text);
    match failure {
        Failure::Connect(text) => Failure::Connect(clean(text)),
        Failure::Tls(text) => Failure::Tls(clean(text)),
        Failure::Network(text) => Failure::Network(clean(text)),
        Failure::Database(text) => Failure::Database(clean(text)),
        Failure::Denied(text) => Failure::Denied(clean(text)),
        Failure::Usage(text) => Failure::Usage(clean(text)),
        failure => failure,
    }
}
