use std::path::PathBuf;

use clap::{Arg, ArgAction, Error, Subcommand, ValueEnum, error::ErrorKind, value_parser};

use crate::Failure;

#[derive(Debug, Subcommand)]
pub enum LogCommand {
    #[command(
        about = "Keep the audit log under MB megabytes, dropping the oldest entries (run by the user in a terminal)"
    )]
    Limit {
        #[arg(value_parser = value_parser!(u32).range(1..))]
        mb: u32,
    },
}

#[derive(Debug, Subcommand)]
pub enum PasswordCommand {
    #[command(about = "Set or change the admin password")]
    Set,
    #[command(about = "Remove the admin password")]
    Remove,
}

#[derive(Debug, Subcommand)]
pub enum SkillCommand {
    #[command(about = "Print SKILL.md to stdout")]
    Print,
    #[command(about = "Install SKILL.md for one agent or into a skills directory")]
    Install {
        #[arg(
            long,
            value_enum,
            help = "Install into this agent's skills directory in your home directory"
        )]
        agent: Option<Agent>,
        #[arg(
            long,
            value_name = "DIR",
            conflicts_with = "agent",
            help = "Install into this skills directory, like ~/.claude/skills or .claude/skills"
        )]
        path: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Agent {
    Claude,
    Codex,
    Opencode,
}

pub struct Refused {
    pub short: Option<char>,
    pub long: &'static str,
    pub value: bool,
    pub reason: &'static str,
}

impl Refused {
    pub const fn new(
        short: Option<char>,
        long: &'static str,
        value: bool,
        reason: &'static str,
    ) -> Refused {
        Refused {
            short,
            long,
            value,
            reason,
        }
    }

    pub fn arg(&self) -> Arg {
        let action = if self.value {
            ArgAction::Set
        } else {
            ArgAction::SetTrue
        };
        let arg = Arg::new(self.long)
            .long(self.long)
            .action(action)
            .hide(true);
        match self.short {
            Some(short) => arg.short(short),
            None => arg,
        }
    }

    pub fn name(&self) -> String {
        match self.short {
            Some(short) => format!("-{short}/--{}", self.long),
            None => format!("--{}", self.long),
        }
    }

    pub fn failure(&self) -> Failure {
        Failure::Refused {
            flag: self.name(),
            reason: self.reason,
        }
    }
}

pub fn usage(tool: &str, error: Error) -> Failure {
    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    ) {
        error.exit();
    }
    let text = error.to_string();
    let summary = text.split("\n\n").next().unwrap_or_default();
    let summary = summary.split_whitespace().collect::<Vec<_>>().join(" ");
    Failure::Usage(format!(
        "{} (see {tool} --help)",
        summary.trim_start_matches("error: ")
    ))
}
