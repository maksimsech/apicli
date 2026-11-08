mod admin;
mod cli;
mod failure;
mod info;
mod request;
mod response;
mod rules;
mod skill;

use std::{env, process::ExitCode};

use cli::{Command, parse};
use failure::Failure;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    disable_core_dumps();
    match run().await {
        Ok(code) => ExitCode::from(code),
        Err(failure) => {
            for line in failure.to_string().lines() {
                eprintln!("apicli: {line}");
            }
            ExitCode::from(failure.code())
        }
    }
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
        Some(Command::Secret { command }) => admin::secret(command),
        Some(Command::Password { command }) => admin::password(command),
        Some(Command::Allow { command }) => rules::allow(command),
        Some(Command::Deny { command }) => rules::deny(command),
        Some(Command::Policy { command }) => rules::policy(command),
        Some(Command::Skill { command }) => skill::skill(command),
        None => request::send(cli.request).await,
    }
}

#[cfg(unix)]
fn disable_core_dumps() {
    use libc::{RLIMIT_CORE, rlimit, setrlimit};

    let limit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        setrlimit(RLIMIT_CORE, &limit);
    }
}

#[cfg(not(unix))]
fn disable_core_dumps() {}
