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
    match run().await {
        Ok(code) => code,
        Err(failure) => {
            eprintln!("apicli: {failure}");
            ExitCode::from(failure.code())
        }
    }
}

async fn run() -> Result<ExitCode, Failure> {
    let mut args: Vec<String> = env::args().collect();
    if args.get(1).is_some_and(|arg| arg == "curl") {
        args.remove(1);
    }
    let cli = parse(args)?;
    match cli.command {
        Some(Command::Skill {
            command: SkillCommand::Print,
        }) => {
            print!("{SKILL}");
            Ok(ExitCode::SUCCESS)
        }
        None => request::send(cli.request).await,
    }
}
