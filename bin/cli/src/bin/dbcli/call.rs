use std::{
    io::{IsTerminal, Write, stderr, stdout},
    iter::once,
    time::Instant,
};

use apicli::{Entry, Failure, Refused, record, take, usage};
use apicli_policy::{Connection, Engine, Redactor, Vault};
use apicli_vault::Store;
use clap::{Parser, parser::ValueSource};

use crate::{cassandra, mongo, postgres, redis, secret::add_hint};

const MASK: &str = "[dbcli:redacted]";

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
        self.out
            .write_all(&self.redactor.redact(bytes))
            .and_then(|_| self.out.flush())
            .map_err(|error| Failure::Write(error.to_string()))
    }

    pub fn warn(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        self.err
            .write_all(&self.redactor.redact(bytes))
            .and_then(|_| self.err.flush())
            .map_err(|error| Failure::Write(error.to_string()))
    }

    pub fn clean(&self, text: &str) -> String {
        String::from_utf8_lossy(&self.redactor.redact(text.as_bytes())).into_owned()
    }

    pub fn statements(&mut self, statements: &[String]) {
        self.entry.statements = statements
            .iter()
            .map(|statement| self.clean(statement))
            .collect();
    }
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
        Engine::ClickHouse => Err(Failure::Usage("ClickHouse is not supported yet".into())),
    };
    result.map_err(|failure| scrub(failure, &context.redactor))
}

pub async fn explain(connection: &Connection, args: &[String]) -> Result<Vec<String>, Failure> {
    match connection.url.engine {
        Engine::Postgres => postgres::explain(connection, args),
        Engine::Redis => redis::explain(connection, args).await,
        Engine::Mongo => mongo::explain(connection, args),
        Engine::Cassandra => cassandra::explain(connection, args),
        Engine::ClickHouse => Err(Failure::Usage("ClickHouse is not supported yet".into())),
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

pub fn redactor(vault: &Vault) -> Redactor {
    Redactor::new(MASK, vault.secrets())
}

pub fn scrub(failure: Failure, redactor: &Redactor) -> Failure {
    let clean =
        |text: String| String::from_utf8_lossy(&redactor.redact(text.as_bytes())).into_owned();
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
