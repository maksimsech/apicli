mod admin;
mod cli;
mod failure;
mod request;
mod response;

use std::{env, process::ExitCode};

use cli::{Command, SkillCommand, parse};
use failure::Failure;

const SKILL: &str = include_str!("../skill/SKILL.md");

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    disable_core_dumps();
    match run().await {
        Ok(code) => ExitCode::from(code),
        Err(failure) => {
            eprintln!("apicli: {failure}");
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
        Some(Command::Hosts { json }) => admin::hosts(json),
        Some(Command::Secret { command }) => admin::secret(command),
        Some(Command::Skill {
            command: SkillCommand::Print,
        }) => {
            print!("{SKILL}");
            Ok(0)
        }
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
