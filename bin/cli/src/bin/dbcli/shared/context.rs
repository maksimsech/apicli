use std::{io::Write, iter::once};

use apicli::{Entry, Failure, Refused, take, usage};
use apicli_policy::{Connection, Redactor, Vault};
use apicli_vault::Store;
use clap::{ArgAction, Args, Parser, parser::ValueSource};

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

pub fn key(name: &str) -> String {
    format!("db:{name}")
}

pub fn redactor(vault: &Vault) -> Redactor {
    Redactor::new(MASK, vault.secrets())
}
