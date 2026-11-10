use apicli::{Failure, Refused};
use clap::{ColorChoice, Parser};

use crate::shared::{Common, engine_args};

#[derive(Debug, Parser)]
#[command(
    name = "dbcli NAME",
    about = "Run one command on a Redis connection, like redis-cli",
    color = ColorChoice::Never,
    args_override_self = true,
    disable_help_flag = true,
    disable_version_flag = true
)]
pub struct RedisArgs {
    #[arg(short = 'n', value_name = "DB", help = "Database number")]
    pub db: Option<u32>,
    #[arg(
        long,
        overrides_with_all = ["no_raw", "csv", "json"],
        help = "Print replies as they are, the default when stdout isn't a terminal"
    )]
    pub raw: bool,
    #[arg(
        long = "no-raw",
        overrides_with_all = ["raw", "csv", "json"],
        help = "Print replies as redis-cli does in a terminal"
    )]
    pub no_raw: bool,
    #[arg(long, overrides_with_all = ["raw", "no_raw", "json"], help = "CSV output")]
    pub csv: bool,
    #[arg(long, overrides_with_all = ["raw", "no_raw", "csv"], help = "JSON output, over RESP3")]
    pub json: bool,
    #[arg(short = 'x', help = "Read the last argument from stdin")]
    pub stdin: bool,
    #[arg(short = 'e', help = "Exit 1 when the server returns an error")]
    pub errors: bool,
    #[arg(long, help = "List keys with SCAN, one per line")]
    pub scan: bool,
    #[arg(
        long,
        value_name = "PATTERN",
        requires = "scan",
        help = "Keys to list with --scan"
    )]
    pub pattern: Option<String>,
    #[arg(
        long,
        value_name = "COUNT",
        requires = "scan",
        default_value_t = 10,
        help = "SCAN's COUNT hint with --scan"
    )]
    pub count: u32,
    #[arg(long = "no-auth-warning", hide = true)]
    pub no_auth_warning: bool,
    #[arg(
        value_name = "COMMAND",
        trailing_var_arg = true,
        help = "The command and its arguments, like GET key"
    )]
    pub command: Vec<String>,
    #[command(flatten)]
    pub common: Common,
}

const SERVER: &str = "the connection name picks the server";
const PASSWORD: &str = "dbcli sends the stored password itself";
const TLS: &str = "the connection URL sets TLS";
const ONE_SHOT: &str = "dbcli runs one command per call, or --scan";

const REFUSED: &[Refused] = &[
    Refused::new(Some('h'), "host", true, SERVER),
    Refused::new(Some('p'), "port", true, SERVER),
    Refused::new(Some('s'), "socket", true, SERVER),
    Refused::new(Some('u'), "uri", true, SERVER),
    Refused::new(None, "user", true, "the connection name picks the user"),
    Refused::new(Some('a'), "pass", true, PASSWORD),
    Refused::new(None, "askpass", false, PASSWORD),
    Refused::new(None, "tls", false, TLS),
    Refused::new(None, "sni", true, TLS),
    Refused::new(None, "cacert", true, TLS),
    Refused::new(None, "cacertdir", true, TLS),
    Refused::new(None, "insecure", false, TLS),
    Refused::new(None, "cert", true, TLS),
    Refused::new(None, "key", true, TLS),
    Refused::new(None, "tls-ciphers", true, TLS),
    Refused::new(None, "tls-ciphersuites", true, TLS),
    Refused::new(
        Some('c'),
        "cluster-mode",
        false,
        "cluster mode is not supported",
    ),
    Refused::new(None, "cluster", true, "cluster mode is not supported"),
    Refused::new(Some('r'), "repeat", true, ONE_SHOT),
    Refused::new(Some('i'), "interval", true, ONE_SHOT),
    Refused::new(None, "pipe", false, ONE_SHOT),
    Refused::new(None, "rdb", true, ONE_SHOT),
    Refused::new(None, "functions-rdb", true, ONE_SHOT),
    Refused::new(None, "replica", false, ONE_SHOT),
    Refused::new(None, "slave", false, ONE_SHOT),
    Refused::new(None, "stat", false, ONE_SHOT),
    Refused::new(None, "latency", false, ONE_SHOT),
    Refused::new(None, "latency-history", false, ONE_SHOT),
    Refused::new(None, "latency-dist", false, ONE_SHOT),
    Refused::new(None, "intrinsic-latency", true, ONE_SHOT),
    Refused::new(None, "lru-test", true, ONE_SHOT),
    Refused::new(None, "bigkeys", false, ONE_SHOT),
    Refused::new(None, "memkeys", false, ONE_SHOT),
    Refused::new(None, "hotkeys", false, ONE_SHOT),
    Refused::new(None, "keystats", false, ONE_SHOT),
    Refused::new(
        None,
        "eval",
        true,
        "it reads a local file, pass the script to EVAL instead",
    ),
    Refused::new(None, "ldb", false, "the Lua debugger is not supported"),
];

const COMMANDS: &[(&str, &str)] = &[
    ("MONITOR", "it streams every command on the server"),
    ("SUBSCRIBE", "it waits for messages without end"),
    ("PSUBSCRIBE", "it waits for messages without end"),
    ("SSUBSCRIBE", "it waits for messages without end"),
    ("MULTI", "dbcli runs one command per call"),
    ("EXEC", "dbcli runs one command per call"),
    ("DISCARD", "dbcli runs one command per call"),
    ("WATCH", "dbcli runs one command per call"),
    ("AUTH", "dbcli logs in with the stored user and password"),
    ("HELLO", "dbcli logs in with the stored user and password"),
    ("SYNC", "it streams the whole dataset"),
    ("PSYNC", "it streams the whole dataset"),
    ("REPLCONF", "it is for replicas"),
];

pub fn parse(args: &[String]) -> Result<RedisArgs, Failure> {
    let args = engine_args::<RedisArgs>(args, REFUSED)?;
    if let Some(name) = args.command.first()
        && let Some((command, reason)) = COMMANDS
            .iter()
            .find(|(command, _)| command.eq_ignore_ascii_case(name))
    {
        return Err(Failure::Refused {
            flag: command.to_string(),
            reason,
        });
    }
    if args.command.is_empty() && !args.scan {
        return Err(Failure::Usage(
            "pass a command, like: dbcli NAME GET key. Interactive mode is not supported".into(),
        ));
    }
    if args.scan && !args.command.is_empty() {
        return Err(Failure::Usage(
            "--scan takes no command, use --pattern to pick keys".into(),
        ));
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(list: &[&str]) -> Result<RedisArgs, Failure> {
        parse(&list.iter().map(|arg| arg.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn rejects_every_refused_flag() {
        for refused in REFUSED {
            let mut list = vec![format!("--{}", refused.long)];
            if refused.value {
                list.push("value".into());
            }
            list.push("GET".into());
            list.push("key".into());

            assert!(
                matches!(parse(&list), Err(Failure::Refused { .. })),
                "--{} was accepted",
                refused.long
            );
        }
    }

    #[test]
    fn rejects_refused_flags_in_short_form() {
        for args in [
            &["-h", "attacker.example", "GET", "key"][..],
            &["-p6380", "GET", "key"],
            &["-a", "guess", "GET", "key"],
            &["-u", "redis://attacker.example", "GET", "key"],
            &["-c", "GET", "key"],
            &["-r", "1000", "INCR", "key"],
        ] {
            assert!(
                matches!(parse_args(args), Err(Failure::Refused { .. })),
                "{args:?} was accepted"
            );
        }
    }

    #[test]
    fn rejects_commands_that_change_the_session_or_stream() {
        for command in [
            "MONITOR",
            "subscribe",
            "PSubscribe",
            "MULTI",
            "exec",
            "auth",
            "HELLO",
            "SYNC",
            "psync",
        ] {
            assert!(
                matches!(parse_args(&[command, "x"]), Err(Failure::Refused { .. })),
                "{command} was accepted"
            );
        }
    }

    #[test]
    fn flags_after_the_command_are_its_arguments() {
        let args = parse_args(&["-n", "2", "--no-raw", "SET", "key", "-h", "--pass"]).unwrap();

        assert_eq!(args.db, Some(2));
        assert!(args.no_raw);
        assert_eq!(args.command, ["SET", "key", "-h", "--pass"]);
    }

    #[test]
    fn needs_a_command_or_scan() {
        assert!(matches!(parse_args(&[]), Err(Failure::Usage(_))));
        assert!(matches!(
            parse_args(&["--scan", "GET"]),
            Err(Failure::Usage(_))
        ));
        assert!(parse_args(&["--scan", "--pattern", "cache:*"]).is_ok());
    }
}
