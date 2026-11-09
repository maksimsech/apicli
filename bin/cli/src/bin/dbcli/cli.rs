use apicli::{Failure, LogCommand, PasswordCommand, Refused, SkillCommand, usage};
use clap::{
    ArgAction, ArgMatches, Args, ColorChoice, Command as ClapCommand, CommandFactory,
    FromArgMatches, Parser, Subcommand, parser::ValueSource,
};

use crate::output::{Format, Options};

#[derive(Debug, Parser)]
#[command(
    name = "dbcli",
    version,
    about = "psql for databases that need credentials",
    color = ColorChoice::Never,
    args_override_self = true,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    disable_help_subcommand = true,
    disable_help_flag = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[command(flatten)]
    pub run: RunArgs,
    #[arg(long, action = ArgAction::Help, global = true, help = "Print help")]
    help: Option<bool>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "List configured connections and what is allowed on them")]
    Connections {
        #[arg(long, help = "Print JSON")]
        json: bool,
    },
    #[command(about = "Check whether a call would be allowed, without connecting")]
    Explain {
        #[command(flatten)]
        run: RunArgs,
        #[arg(long, help = "Print JSON")]
        json: bool,
    },
    #[command(about = "Manage stored connections (run by the user in a terminal)")]
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    #[command(about = "Allow writes on a connection (run by the user in a terminal)")]
    Allow {
        #[command(subcommand)]
        command: AllowCommand,
    },
    #[command(about = "Set per-connection rate limits (run by the user in a terminal)")]
    Limit {
        #[command(subcommand)]
        command: LimitCommand,
    },
    #[command(about = "Show recent calls from the audit log")]
    Log {
        #[command(subcommand)]
        command: Option<LogCommand>,
        #[arg(
            long,
            value_name = "COUNT",
            default_value_t = 20,
            help = "How many entries to show"
        )]
        tail: usize,
        #[arg(long, help = "Print JSON lines")]
        json: bool,
    },
    #[command(about = "Set or remove the admin password (run by the user in a terminal)")]
    Password {
        #[command(subcommand)]
        command: PasswordCommand,
    },
    #[command(about = "The agent skill for dbcli")]
    Skill {
        #[command(subcommand)]
        command: SkillCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    #[command(about = "Store a connection, asking for its password")]
    Add {
        name: String,
        #[arg(
            long,
            help = "Connection URL without the password, like postgres://agent@db.example.com:5432/app?sslmode=require"
        )]
        url: String,
    },
    #[command(about = "Replace a connection's password")]
    Rotate { name: String },
    #[command(about = "Delete a connection")]
    Rm { name: String },
}

#[derive(Debug, Subcommand)]
pub enum AllowCommand {
    #[command(about = "Allow ACTION on NAME. Postgres connections take only `write`")]
    Add {
        name: String,
        action: String,
        target: Option<String>,
    },
    #[command(about = "Remove an allow rule")]
    Rm {
        name: String,
        action: String,
        target: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum LimitCommand {
    #[command(about = "Limit NAME to RATE statements, like 30/min")]
    Set {
        name: String,
        rate: String,
        #[arg(
            long,
            help = "Statements allowed at once, defaults to the rate's count"
        )]
        burst: Option<u32>,
        #[arg(long, help = "Statements allowed per UTC day")]
        daily: Option<u32>,
    },
    #[command(about = "Remove the limits on NAME")]
    Rm { name: String },
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(
        value_name = "NAME",
        required = true,
        help = "The connection to use, from dbcli connections"
    )]
    pub name: Option<String>,
    #[arg(hide = true)]
    pub extra: Vec<String>,
    #[arg(
        short = 'c',
        long = "command",
        value_name = "SQL",
        allow_hyphen_values = true,
        help = "One SQL statement or one \\d command. Repeat for more, each runs separately"
    )]
    pub commands: Vec<String>,
    #[arg(long, help = "CSV output")]
    pub csv: bool,
    #[arg(short = 'A', long = "no-align", help = "Unaligned output")]
    pub no_align: bool,
    #[arg(short = 't', long = "tuples-only", help = "Print rows only")]
    pub tuples_only: bool,
    #[arg(short = 'x', long, help = "Expanded output, one line per column")]
    pub expanded: bool,
    #[arg(
        short = 'F',
        long = "field-separator",
        value_name = "SEP",
        allow_hyphen_values = true,
        help = "Field separator for unaligned output, | by default"
    )]
    pub field_separator: Option<String>,
    #[arg(short = 'q', long, help = "Don't print command tags like UPDATE 3")]
    pub quiet: bool,
    #[arg(
        short = 'P',
        long = "pset",
        value_name = "NAME=VALUE",
        help = "Output option: footer=on|off, null=TEXT, pager (ignored)"
    )]
    pub pset: Vec<String>,
    #[arg(
        short = 'v',
        long = "set",
        visible_alias = "variable",
        value_name = "NAME=VALUE",
        help = "Only ON_ERROR_STOP is accepted, dbcli always stops at the first error"
    )]
    pub variables: Vec<String>,
    #[arg(short = 'X', long = "no-psqlrc", hide = true)]
    pub no_psqlrc: bool,
    #[arg(
        long,
        value_name = "SECONDS",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "30",
        help = "Wait up to SECONDS (default 30) for the rate limit instead of failing"
    )]
    pub wait: Option<f64>,
}

pub const REFUSED: &[Refused] = &[
    Refused {
        short: Some('h'),
        long: "host",
        value: true,
        reason: "the connection name picks the host",
    },
    Refused {
        short: Some('p'),
        long: "port",
        value: true,
        reason: "the connection name picks the port",
    },
    Refused {
        short: Some('U'),
        long: "username",
        value: true,
        reason: "the connection name picks the user",
    },
    Refused {
        short: Some('d'),
        long: "dbname",
        value: true,
        reason: "the connection name picks the database",
    },
    Refused {
        short: Some('W'),
        long: "password",
        value: false,
        reason: "dbcli sends the stored password itself",
    },
    Refused {
        short: Some('w'),
        long: "no-password",
        value: false,
        reason: "dbcli sends the stored password itself",
    },
    Refused {
        short: Some('f'),
        long: "file",
        value: true,
        reason: "scripts are not supported yet, pass each statement with -c",
    },
    Refused {
        short: Some('o'),
        long: "output",
        value: true,
        reason: "redirect stdout instead",
    },
    Refused {
        short: Some('L'),
        long: "log-file",
        value: true,
        reason: "dbcli keeps its own log, see dbcli log",
    },
    Refused {
        short: Some('1'),
        long: "single-transaction",
        value: false,
        reason: "each -c runs in its own transaction",
    },
    Refused {
        short: Some('l'),
        long: "list",
        value: false,
        reason: "use -c '\\l'",
    },
];

impl RunArgs {
    pub fn check(&self) -> Result<Options, Failure> {
        if let Some(extra) = self.extra.first() {
            return Err(Failure::Refused {
                flag: extra.clone(),
                reason: "the connection name picks the database and user, pass SQL with -c",
            });
        }
        for variable in &self.variables {
            if variable.split('=').next() != Some("ON_ERROR_STOP") {
                return Err(Failure::Refused {
                    flag: format!("-v {variable}"),
                    reason: "psql variables are not supported, only -v ON_ERROR_STOP=1",
                });
            }
        }
        let mut options = Options {
            format: if self.csv {
                Format::Csv
            } else if self.no_align {
                Format::Unaligned
            } else {
                Format::Aligned
            },
            expanded: self.expanded,
            tuples_only: self.tuples_only,
            footer: true,
            null: String::new(),
            field_separator: self.field_separator.clone().unwrap_or_else(|| "|".into()),
            quiet: self.quiet,
        };
        for setting in &self.pset {
            let (name, value) = setting.split_once('=').unwrap_or((setting, ""));
            match name {
                "pager" => {}
                "footer" => options.footer = !matches!(value, "off" | "false" | "0"),
                "null" => options.null = value.to_string(),
                _ => {
                    return Err(Failure::Refused {
                        flag: format!("-P {setting}"),
                        reason: "only -P footer=on|off, null=TEXT and pager are supported",
                    });
                }
            }
        }
        Ok(options)
    }
}

pub fn parse(args: Vec<String>) -> Result<Cli, Failure> {
    let command = refusing(Cli::command()).mut_subcommand("explain", refusing);
    let matches = command
        .try_get_matches_from(args)
        .map_err(|error| usage("dbcli", error))?;
    let explain = matches.subcommand_matches("explain");
    if let Some(refused) = REFUSED
        .iter()
        .find(|refused| given(&matches, refused) || explain.is_some_and(|sub| given(sub, refused)))
    {
        return Err(refused.failure());
    }
    Cli::from_arg_matches(&matches).map_err(|error| usage("dbcli", error))
}

pub fn reserved(name: &str) -> bool {
    name == "help"
        || Cli::command()
            .get_subcommands()
            .any(|command| command.get_name() == name)
}

fn refusing(command: ClapCommand) -> ClapCommand {
    REFUSED
        .iter()
        .fold(command, |command, refused| command.arg(refused.arg()))
}

fn given(matches: &ArgMatches, refused: &Refused) -> bool {
    matches.value_source(refused.long) == Some(ValueSource::CommandLine)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(list: &[&str]) -> Result<Cli, Failure> {
        parse(
            ["dbcli"]
                .iter()
                .chain(list)
                .map(|arg| arg.to_string())
                .collect(),
        )
    }

    #[test]
    fn rejects_every_refused_flag() {
        for refused in REFUSED {
            for explain in [false, true] {
                let mut list = Vec::new();
                if explain {
                    list.push("explain".to_string());
                }
                list.push("prod".into());
                list.push(format!("--{}", refused.long));
                if refused.value {
                    list.push("value".into());
                }
                list.push("-c".into());
                list.push("select 1".into());

                let result = parse(["dbcli".to_string()].into_iter().chain(list).collect());

                assert!(
                    matches!(result, Err(Failure::Refused { .. })),
                    "--{} was accepted",
                    refused.long
                );
            }
        }
    }

    #[test]
    fn rejects_refused_flags_in_short_form() {
        for args in [
            &["prod", "-hattacker.example", "-c", "select 1"][..],
            &["prod", "-p", "6543", "-c", "select 1"],
            &["prod", "-qU", "postgres", "-c", "select 1"],
            &["prod", "-d", "other", "-c", "select 1"],
            &["prod", "-At1", "-c", "select 1"],
        ] {
            assert!(
                matches!(parse_args(args), Err(Failure::Refused { .. })),
                "{args:?} was accepted"
            );
        }
    }

    #[test]
    fn rejects_a_connection_uri_or_database_argument() {
        for extra in ["postgres://postgres@attacker.example/x", "otherdb"] {
            let cli = parse_args(&["prod", extra, "-c", "select 1"]).unwrap();

            assert!(matches!(cli.run.check(), Err(Failure::Refused { .. })));
        }
    }

    #[test]
    fn rejects_variables_other_than_on_error_stop() {
        let cli = parse_args(&["prod", "-v", "ON_ERROR_STOP=1", "-c", "select 1"]).unwrap();
        assert!(cli.run.check().is_ok());

        let cli = parse_args(&["prod", "-v", "HISTFILE=/tmp/x", "-c", "select 1"]).unwrap();
        assert!(matches!(cli.run.check(), Err(Failure::Refused { .. })));
    }

    #[test]
    fn accepts_psql_style_flags() {
        let cli = parse_args(&[
            "prod",
            "-XAtq",
            "-F,",
            "-c",
            "-- note\nselect 1",
            "-c",
            "\\dt",
        ])
        .unwrap();

        assert_eq!(cli.run.commands.len(), 2);
        assert_eq!(cli.run.field_separator.as_deref(), Some(","));
        assert!(cli.run.check().is_ok());
    }

    #[test]
    fn subcommand_names_are_reserved() {
        assert!(reserved("secret"));
        assert!(reserved("connections"));
        assert!(!reserved("prod-pg"));
    }
}
