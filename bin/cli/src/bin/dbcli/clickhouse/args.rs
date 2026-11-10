use apicli::{Failure, Refused};
use clap::{ArgAction, ColorChoice, Parser};

use crate::call::engine_args;

#[derive(Debug, Parser)]
#[command(
    name = "dbcli NAME",
    about = "Run SQL on a ClickHouse connection, like clickhouse-client --query",
    after_help = "Query parameters: --param_NAME=VALUE fills {NAME:Type} in the query.",
    color = ColorChoice::Never,
    args_override_self = true,
    disable_help_flag = true,
    disable_version_flag = true
)]
pub struct ClientArgs {
    #[arg(
        short = 'q',
        long,
        value_name = "SQL",
        allow_hyphen_values = true,
        help = "SQL statements separated by ;. Repeat for more"
    )]
    pub query: Vec<String>,
    #[arg(
        short = 'f',
        long,
        value_name = "FORMAT",
        help = "Output format, TabSeparated by default, PrettyCompact in a terminal"
    )]
    pub format: Option<String>,
    #[arg(short = 'E', long, help = "Vertical output")]
    pub vertical: bool,
    #[arg(short = 'm', long, hide = true)]
    pub multiline: bool,
    #[arg(short = 'n', long, hide = true)]
    pub multiquery: bool,
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

const SERVER: &str = "the connection name picks the server";
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
    refused(Some('h'), "host", true, SERVER),
    refused(None, "port", true, SERVER),
    refused(None, "connection", true, SERVER),
    refused(Some('u'), "user", true, AUTH),
    refused(None, "password", true, AUTH),
    refused(None, "ask-password", false, AUTH),
    refused(None, "jwt", true, AUTH),
    refused(None, "ssh-key-file", true, AUTH),
    refused(Some('s'), "secure", false, "the connection URL sets TLS"),
    refused(
        None,
        "accept-invalid-certificate",
        false,
        "the connection URL sets TLS",
    ),
    refused(
        Some('C'),
        "config-file",
        true,
        "dbcli reads no client config",
    ),
    refused(
        Some('d'),
        "database",
        true,
        "the connection name picks the database, qualify tables as db.table instead",
    ),
    refused(
        None,
        "queries-file",
        true,
        "scripts are not supported, pass SQL with -q",
    ),
    refused(
        Some('i'),
        "interactive",
        false,
        "there is no interactive mode",
    ),
];

pub fn parse(args: &[String]) -> Result<(ClientArgs, Vec<(String, String)>), Failure> {
    let mut rest = Vec::new();
    let mut params = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(param) = arg.strip_prefix("--param_") else {
            rest.push(arg.clone());
            continue;
        };
        let (name, value) = match param.split_once('=') {
            Some((name, value)) => (name.to_string(), value.to_string()),
            None => {
                let value = iter
                    .next()
                    .ok_or_else(|| Failure::Usage(format!("--param_{param} needs a value")))?;
                (param.to_string(), value.clone())
            }
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(Failure::Usage(format!(
                "--param_{name} is not a valid parameter name"
            )));
        }
        params.push((name, value));
    }
    let args = engine_args::<ClientArgs>(&rest, REFUSED)?;
    if let Some(extra) = args.extra.first() {
        return Err(Failure::Refused {
            flag: extra.clone(),
            reason: "the connection name picks the server, pass SQL with -q",
        });
    }
    if args.query.is_empty() {
        return Err(Failure::Usage(
            "pass SQL with -q, like: dbcli NAME -q 'SELECT 1'. Interactive mode and stdin are not supported".into(),
        ));
    }
    Ok((args, params))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(list: &[&str]) -> Result<(ClientArgs, Vec<(String, String)>), Failure> {
        parse(&list.iter().map(|arg| arg.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn rejects_every_refused_flag_and_hosts() {
        for refused in REFUSED {
            let mut list = vec![format!("--{}", refused.long)];
            if refused.value {
                list.push("value".into());
            }
            list.extend(["-q".into(), "SELECT 1".into()]);

            assert!(
                matches!(parse(&list), Err(Failure::Refused { .. })),
                "--{} was accepted",
                refused.long
            );
        }
        for list in [
            &["-h", "attacker.example", "-q", "SELECT 1"][..],
            &["-u", "default", "-q", "SELECT 1"],
            &["--secure", "-q", "SELECT 1"],
            &["clickhouse://attacker.example", "-q", "SELECT 1"],
        ] {
            assert!(
                matches!(parse_args(list), Err(Failure::Refused { .. })),
                "{list:?}"
            );
        }
    }

    #[test]
    fn parameters_must_have_plain_names() {
        let (_, params) =
            parse_args(&["--param_id=5", "--param_name", "x", "-q", "SELECT 1"]).unwrap();
        assert_eq!(
            params,
            [("id".into(), "5".into()), ("name".into(), "x".into())]
        );

        assert!(parse_args(&["--param_a&readonly=0", "-q", "SELECT 1"]).is_err());
    }
}
