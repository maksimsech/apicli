use clap::{ColorChoice, Parser};
use fieldkit_common::{Failure, Refused};

use super::output::{Format, Options};
use crate::shared::{Common, engine_args};

#[derive(Debug, Parser)]
#[command(
    name = "dbcli NAME",
    about = "Run SQL on a Postgres connection, like psql -c",
    color = ColorChoice::Never,
    args_override_self = true,
    disable_help_flag = true,
    disable_version_flag = true
)]
pub struct PsqlArgs {
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
    #[command(flatten)]
    pub common: Common,
}

const REFUSED: &[Refused] = &[
    Refused::new(
        Some('h'),
        "host",
        true,
        "the connection name picks the host",
    ),
    Refused::new(
        Some('p'),
        "port",
        true,
        "the connection name picks the port",
    ),
    Refused::new(
        Some('U'),
        "username",
        true,
        "the connection name picks the user",
    ),
    Refused::new(
        Some('d'),
        "dbname",
        true,
        "the connection name picks the database",
    ),
    Refused::new(
        Some('W'),
        "password",
        false,
        "dbcli sends the stored password itself",
    ),
    Refused::new(
        Some('w'),
        "no-password",
        false,
        "dbcli sends the stored password itself",
    ),
    Refused::new(
        Some('f'),
        "file",
        true,
        "scripts are not supported yet, pass each statement with -c",
    ),
    Refused::new(Some('o'), "output", true, "redirect stdout instead"),
    Refused::new(
        Some('L'),
        "log-file",
        true,
        "dbcli keeps its own log, see dbcli log",
    ),
    Refused::new(
        Some('1'),
        "single-transaction",
        false,
        "each -c runs in its own transaction",
    ),
    Refused::new(Some('l'), "list", false, "use -c '\\l'"),
];

pub fn parse(args: &[String]) -> Result<PsqlArgs, Failure> {
    engine_args(args, REFUSED)
}

impl PsqlArgs {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(list: &[&str]) -> Result<PsqlArgs, Failure> {
        parse(&list.iter().map(|arg| arg.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn rejects_every_refused_flag() {
        for refused in REFUSED {
            let mut list = vec![format!("--{}", refused.long)];
            if refused.value {
                list.push("value".into());
            }
            list.push("-c".into());
            list.push("select 1".into());

            let result = parse(&list);

            assert!(
                matches!(result, Err(Failure::Refused { .. })),
                "--{} was accepted",
                refused.long
            );
        }
    }

    #[test]
    fn rejects_refused_flags_in_short_form() {
        for args in [
            &["-hattacker.example", "-c", "select 1"][..],
            &["-p", "6543", "-c", "select 1"],
            &["-qU", "postgres", "-c", "select 1"],
            &["-d", "other", "-c", "select 1"],
            &["-At1", "-c", "select 1"],
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
            let args = parse_args(&[extra, "-c", "select 1"]).unwrap();

            assert!(matches!(args.check(), Err(Failure::Refused { .. })));
        }
    }

    #[test]
    fn rejects_variables_other_than_on_error_stop() {
        let args = parse_args(&["-v", "ON_ERROR_STOP=1", "-c", "select 1"]).unwrap();
        assert!(args.check().is_ok());

        let args = parse_args(&["-v", "HISTFILE=/tmp/x", "-c", "select 1"]).unwrap();
        assert!(matches!(args.check(), Err(Failure::Refused { .. })));
    }

    #[test]
    fn accepts_psql_style_flags() {
        let args = parse_args(&["-XAtq", "-F,", "-c", "-- note\nselect 1", "-c", "\\dt"]).unwrap();

        assert_eq!(args.commands.len(), 2);
        assert_eq!(args.field_separator.as_deref(), Some(","));
        assert!(args.check().is_ok());
    }
}
