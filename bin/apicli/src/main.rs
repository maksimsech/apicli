mod access;
#[cfg(test)]
mod bypass;
mod cli;
mod config;
mod info;
mod network;
mod origin;
mod request;
mod response;
mod rules;
mod secret;

use std::{env, process::ExitCode};

use cli::{Command, parse};
use fieldkit_common::{
    Failure, LogCommand, disable_core_dumps, exit, log, log_limit, password, skill,
};

const TOOL: &str = "apicli";
const SKILL: &str = include_str!("../SKILL.md");

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    disable_core_dumps();
    exit(TOOL, run().await)
}

async fn run() -> Result<u8, Failure> {
    let mut args: Vec<String> = env::args().collect();
    if args.get(1).is_some_and(|arg| arg == "curl") {
        args.remove(1);
    }
    let cli = parse(args)?;
    match cli.command {
        Some(Command::Hosts { json }) => info::hosts(json),
        Some(Command::Explain { method, url, json }) => info::explain(&method, &url, json),
        Some(Command::Secret { command }) => secret::secret(command),
        Some(Command::Password { command }) => password(TOOL, command),
        Some(Command::Allow { command }) => rules::allow(command),
        Some(Command::Deny { command }) => rules::deny(command),
        Some(Command::Policy { command }) => rules::policy(command),
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
        Some(Command::Skill { command }) => skill(TOOL, SKILL, command),
        None => request::send(cli.request).await,
    }
}
