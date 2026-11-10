#[cfg(test)]
mod bypass;
mod call;
mod cli;
mod info;
mod postgres;
mod redis;
mod rules;
mod secret;
mod tls;

use std::{env, process::ExitCode};

use apicli::{Failure, LogCommand, disable_core_dumps, exit, log, log_limit, password, skill};
use cli::{Command, parse};

const TOOL: &str = "dbcli";
const SKILL: &str = include_str!("../../../skill/dbcli/SKILL.md");

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    disable_core_dumps();
    exit(TOOL, run().await)
}

async fn run() -> Result<u8, Failure> {
    let cli = parse(env::args().collect())?;
    match cli.command {
        Some(Command::Connections { json }) => info::connections(json),
        Some(Command::Explain { json, name, args }) => info::explain(&name, &args, json).await,
        Some(Command::Secret { command }) => secret::secret(command),
        Some(Command::Allow { command }) => rules::allow(command),
        Some(Command::Limit { command }) => rules::limit(command),
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
