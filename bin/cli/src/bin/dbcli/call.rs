use std::{
    io::{IsTerminal, stderr, stdout},
    time::Instant,
};

use apicli::{Entry, Failure, record};
use apicli_policy::{Connection, Engine, Redactor, Vault};
use apicli_vault::Store;

use crate::{
    cassandra, clickhouse, mongo, postgres, redis,
    shared::{Context, add_hint},
};

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
