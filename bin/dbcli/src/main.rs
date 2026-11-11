#[cfg(test)]
mod bypass;
mod call;
mod cassandra;
mod cli;
mod clickhouse;
mod commands;
mod mongo;
mod postgres;
mod redis;
mod shared;

use std::{env, process::ExitCode};

use cli::{Command, parse};
use commands::{allow, connections, explain, limit, secret};
use fieldkit_common::{
    Failure, LogCommand, disable_core_dumps, exit, log, log_limit, password, skill,
};

const TOOL: &str = "dbcli";
const SKILL: &str = include_str!("../SKILL.md");

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    disable_core_dumps();
    exit(TOOL, run().await)
}

async fn run() -> Result<u8, Failure> {
    let cli = parse(env::args().collect())?;
    match cli.command {
        Some(Command::Connections { json }) => connections(json),
        Some(Command::Explain { json, name, args }) => explain(&name, &args, json).await,
        Some(Command::Secret { command }) => secret(command),
        Some(Command::Allow { command }) => allow(command),
        Some(Command::Limit { command }) => limit(command),
        Some(Command::Log {
            command: Some(LogCommand::Limit { mb }),
            ..
        }) => log_limit(TOOL, mb),
        Some(Command::Log {
            command: None,
            tail,
            json,
        }) => log(tail, json),
        Some(Command::Password { command }) => password(TOOL, command),
        Some(Command::Skill { command }) => skill(TOOL, SKILL, command),
        None => call::send(&cli.name.unwrap_or_default(), &cli.args).await,
    }
}
