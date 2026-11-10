use apicli::{Failure, Refused};
use clap::{ArgAction, ColorChoice, Parser};

use crate::call::engine_args;

#[derive(Debug, Parser)]
#[command(
    name = "dbcli NAME",
    about = "Run CQL on a Cassandra connection, like cqlsh -e",
    color = ColorChoice::Never,
    args_override_self = true,
    disable_help_flag = true,
    disable_version_flag = true
)]
pub struct CqlshArgs {
    #[arg(
        short = 'e',
        long = "execute",
        value_name = "CQL",
        allow_hyphen_values = true,
        help = "CQL statements separated by ;"
    )]
    pub execute: Vec<String>,
    #[arg(short = 'k', long, value_name = "KEYSPACE", help = "Keyspace to use")]
    pub keyspace: Option<String>,
    #[arg(
        long = "request-timeout",
        value_name = "SECONDS",
        default_value_t = 10.0,
        help = "Timeout for each statement"
    )]
    pub request_timeout: f64,
    #[arg(
        long = "connect-timeout",
        value_name = "SECONDS",
        default_value_t = 5.0,
        hide = true
    )]
    pub connect_timeout: f64,
    #[arg(long = "no-color", hide = true)]
    pub no_color: bool,
    #[arg(short = 'C', long = "color", hide = true)]
    pub color: bool,
    #[arg(
        long,
        value_name = "SECONDS",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "30",
        help = "Wait up to SECONDS (default 30) for the rate limit instead of failing"
    )]
    pub wait: Option<f64>,
    #[arg(hide = true)]
    pub extra: Vec<String>,
    #[arg(long, action = ArgAction::Help, help = "Print help")]
    help: Option<bool>,
}

const AUTH: &str = "the connection name picks the user and dbcli sends the stored password";

const fn refused(
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

pub const REFUSED: &[Refused] = &[
    refused(Some('u'), "username", true, AUTH),
    refused(Some('p'), "password", true, AUTH),
    refused(None, "ssl", false, "the connection URL sets TLS"),
    refused(None, "cqlshrc", true, "dbcli reads no cqlshrc"),
    refused(None, "credentials", true, AUTH),
    refused(
        Some('f'),
        "file",
        true,
        "scripts are not supported, pass statements with -e",
    ),
    refused(
        Some('b'),
        "secure-connect-bundle",
        true,
        "the connection URL picks the server",
    ),
    refused(None, "cqlversion", true, "dbcli picks the protocol"),
    refused(None, "protocol-version", true, "dbcli picks the protocol"),
    refused(
        Some('t'),
        "tty",
        false,
        "output follows cqlsh without a terminal",
    ),
];

pub fn parse(args: &[String]) -> Result<CqlshArgs, Failure> {
    let args = engine_args::<CqlshArgs>(args, REFUSED)?;
    if let Some(extra) = args.extra.first() {
        return Err(Failure::Refused {
            flag: extra.clone(),
            reason: "the connection name picks the hosts and port, pass CQL with -e",
        });
    }
    if args.execute.is_empty() {
        return Err(Failure::Usage(
            "pass CQL with -e, like: dbcli NAME -e 'SELECT * FROM shop.orders LIMIT 5'. Interactive mode is not supported".into(),
        ));
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_every_refused_flag_and_hosts() {
        for refused in REFUSED {
            let mut list = vec![format!("--{}", refused.long)];
            if refused.value {
                list.push("value".into());
            }
            list.extend(["-e".into(), "SELECT * FROM system.local".into()]);

            assert!(
                matches!(parse(&list), Err(Failure::Refused { .. })),
                "--{} was accepted",
                refused.long
            );
        }
        for list in [
            &["10.0.0.9", "-e", "SELECT * FROM system.local"][..],
            &["-u", "cassandra", "-e", "SELECT * FROM system.local"],
            &["-pcassandra", "-e", "SELECT * FROM system.local"],
        ] {
            let list = list.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();

            assert!(
                matches!(parse(&list), Err(Failure::Refused { .. })),
                "{list:?}"
            );
        }
    }
}
