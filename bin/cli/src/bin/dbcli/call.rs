use std::{
    io::{Write, stderr, stdout},
    time::Instant,
};

use apicli::{Entry, Failure, record, take};
use apicli_policy::{Connection, Redactor, Vault};
use apicli_vault::Store;

use crate::{
    cli::RunArgs,
    meta::{Meta, parse, run},
    output::{Options, Table, render},
    postgres::{READ_ONLY, Reply, ServerError, Session},
    secret::add_hint,
};

const MASK: &str = "[dbcli:redacted]";
const TAGGED: [&str; 4] = ["INSERT", "UPDATE", "DELETE", "MERGE"];

pub enum Step {
    Sql(String),
    Meta(Meta),
}

pub async fn send(args: RunArgs) -> Result<u8, Failure> {
    let store = Store::open()?;
    let vault = store.load()?;
    let mut entry = Entry::start();
    let started = Instant::now();
    let result = perform(
        &args,
        &store,
        &vault,
        &mut stdout().lock(),
        &mut stderr().lock(),
        &mut entry,
    )
    .await;
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
    args: &RunArgs,
    store: &Store,
    vault: &Vault,
    out: &mut dyn Write,
    err: &mut dyn Write,
    entry: &mut Entry,
) -> Result<u8, Failure> {
    let redactor = Redactor::new(MASK, vault.secrets());
    let name = args.name.as_deref().unwrap_or_default();
    entry.connection = Some(name.to_string());
    entry.statements = args
        .commands
        .iter()
        .map(|command| clean(&redactor, command))
        .collect();
    let options = args.check()?;
    let steps = steps(args)?;
    let connection = find(vault, name)?;
    entry.rule = Some(mode(connection).into());
    let limits = connection.limits();
    let key = key(name);
    take(store, &key, name, &limits, args.wait)?;
    let mut session = Session::open(connection)
        .await
        .map_err(|failure| scrub(failure, &redactor))?;
    let mut result = Ok(0);
    for (index, step) in steps.iter().enumerate() {
        if index > 0
            && let Err(failure) = take(store, &key, name, &limits, args.wait)
        {
            result = Err(failure);
            break;
        }
        if let Err(failure) = run_step(
            &mut session,
            step,
            connection,
            &options,
            &redactor,
            out,
            err,
        )
        .await
        {
            result = Err(scrub(failure, &redactor));
            break;
        }
    }
    session.close().await;
    result
}

async fn run_step(
    session: &mut Session,
    step: &Step,
    connection: &Connection,
    options: &Options,
    redactor: &Redactor,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), Failure> {
    match step {
        Step::Sql(sql) => {
            let reply = session.query(sql).await;
            notices(session, redactor, err)?;
            let reply = reply?;
            if let Some(error) = &reply.error {
                return Err(server_failure(error, sql, connection));
            }
            write(out, redactor, &reply_text(reply, options))
        }
        Step::Meta(meta) => {
            let shown = run(session, meta, connection).await;
            notices(session, redactor, err)?;
            let shown = shown?;
            if let Some(message) = shown.message {
                write(err, redactor, format!("{message}\n").as_bytes())?;
            }
            for table in shown.tables {
                write(out, redactor, render(&table, options).as_bytes())?;
            }
            Ok(())
        }
    }
}

pub fn steps(args: &RunArgs) -> Result<Vec<Step>, Failure> {
    if args.commands.is_empty() {
        return Err(Failure::Usage(
            "pass SQL with -c, like: dbcli NAME -c 'select 1'. Interactive mode and stdin are not supported".into(),
        ));
    }
    args.commands
        .iter()
        .map(|command| {
            if command.trim_start().starts_with('\\') {
                parse(command).map(Step::Meta)
            } else {
                Ok(Step::Sql(command.clone()))
            }
        })
        .collect()
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

pub fn mode(connection: &Connection) -> &'static str {
    if connection.write {
        "read-write"
    } else {
        "read-only"
    }
}

fn reply_text(reply: Reply, options: &Options) -> Vec<u8> {
    if reply.copy_out {
        return reply.copy;
    }
    let tag = reply.tag.unwrap_or_default();
    let mut show_tag = !options.quiet && !tag.is_empty();
    let mut text = String::new();
    if let Some(columns) = reply.columns {
        let table = Table {
            title: None,
            columns,
            rows: reply.rows,
            footers: Vec::new(),
            count: true,
        };
        text.push_str(&render(&table, options));
        show_tag = show_tag && TAGGED.iter().any(|word| tag.starts_with(word));
    }
    if show_tag {
        text.push_str(&tag);
        text.push('\n');
    }
    text.into_bytes()
}

fn server_failure(error: &ServerError, sql: &str, connection: &Connection) -> Failure {
    let text = error.render(Some(sql));
    if error.code == READ_ONLY && !connection.write {
        Failure::Denied(format!(
            "denied: {name} is read-only\n{text}\nto allow writes, the user can run: dbcli allow add {name} write",
            name = connection.name
        ))
    } else {
        Failure::Database(text)
    }
}

fn notices(session: &mut Session, redactor: &Redactor, err: &mut dyn Write) -> Result<(), Failure> {
    for notice in session.notices.drain(..) {
        write(err, redactor, format!("{notice}\n").as_bytes())?;
    }
    Ok(())
}

fn write(out: &mut dyn Write, redactor: &Redactor, bytes: &[u8]) -> Result<(), Failure> {
    out.write_all(&redactor.redact(bytes))
        .and_then(|_| out.flush())
        .map_err(|error| Failure::Write(error.to_string()))
}

fn clean(redactor: &Redactor, text: &str) -> String {
    String::from_utf8_lossy(&redactor.redact(text.as_bytes())).into_owned()
}

fn scrub(failure: Failure, redactor: &Redactor) -> Failure {
    let clean = |text: String| clean(redactor, &text);
    match failure {
        Failure::Connect(text) => Failure::Connect(clean(text)),
        Failure::Tls(text) => Failure::Tls(clean(text)),
        Failure::Network(text) => Failure::Network(clean(text)),
        Failure::Database(text) => Failure::Database(clean(text)),
        Failure::Denied(text) => Failure::Denied(clean(text)),
        failure => failure,
    }
}
