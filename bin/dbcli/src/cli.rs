use clap::{ArgAction, ColorChoice, CommandFactory, Parser, Subcommand};
use fieldkit_common::{Failure, LogCommand, PasswordCommand, SkillCommand, usage};

#[derive(Debug, Parser)]
#[command(
    name = "dbcli",
    version,
    about = "psql, redis-cli, mongosh, cqlsh and clickhouse-client for databases that need credentials",
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
    #[arg(
        value_name = "NAME",
        required = true,
        help = "The connection to use, from dbcli connections"
    )]
    pub name: Option<String>,
    #[arg(
        value_name = "ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        help = "Flags as for the engine's own CLI: psql -c SQL, redis-cli COMMAND, mongosh --eval EXPR, cqlsh -e CQL, clickhouse-client -q SQL. See dbcli NAME --help"
    )]
    pub args: Vec<String>,
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
        #[arg(long, help = "Print JSON, goes before NAME")]
        json: bool,
        #[arg(value_name = "NAME", help = "The connection to use")]
        name: String,
        #[arg(
            value_name = "ARGS",
            trailing_var_arg = true,
            allow_hyphen_values = true,
            help = "The call's flags, as for dbcli NAME"
        )]
        args: Vec<String>,
    },
    #[command(about = "Manage stored connections (run by the user in a terminal)")]
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    #[command(about = "Allow writes or commands on a connection (run by the user in a terminal)")]
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
            help = "Connection URL without the password, like postgres://agent@db.example.com:5432/app?sslmode=require, redis://agent@cache.example.com:6379/0, mongodb://agent@db.example.com:27017/shop, cassandra://agent@10.0.0.1,10.0.0.2:9042/shop or clickhouse://agent@ch.example.com:8123/default"
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
    #[command(
        about = "Allow ACTION on NAME: `write` on Postgres and ClickHouse, a command and key glob on Redis (SET 'cache:*'), a command and namespace on MongoDB (insert 'shop.*'), a keyword and table on Cassandra (INSERT 'shop.*')"
    )]
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

pub fn parse(args: Vec<String>) -> Result<Cli, Failure> {
    match args.get(1) {
        Some(name) if !name.starts_with('-') && !reserved(name) => Ok(Cli {
            command: None,
            name: Some(name.clone()),
            args: args[2..].to_vec(),
            help: None,
        }),
        _ => Cli::try_parse_from(args).map_err(|error| usage("dbcli", error)),
    }
}

pub fn reserved(name: &str) -> bool {
    name == "help"
        || Cli::command()
            .get_subcommands()
            .any(|command| command.get_name() == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(list: &[&str]) -> Cli {
        parse(
            ["dbcli"]
                .iter()
                .chain(list)
                .map(|arg| arg.to_string())
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn everything_after_the_name_goes_to_the_engine() {
        for list in [
            &["prod", "-c", "select 1", "-h", "attacker.example"][..],
            &["cache", "-n", "2", "GET", "-h"],
            &["shop", "--eval", "db.orders.find()", "--help"],
            &["prod", "--help"],
            &["prod", "--wait=5", "explain"],
        ] {
            let cli = parse_args(list);

            assert!(cli.command.is_none());
            assert_eq!(cli.name.as_deref(), Some(list[0]));
            assert_eq!(cli.args, list[1..]);
        }

        let cli = parse_args(&["explain", "--json", "cache", "SET", "k", "--json"]);

        assert!(matches!(
            cli.command,
            Some(Command::Explain { json: true, name, args }) if name == "cache" && args == ["SET", "k", "--json"]
        ));
    }

    #[test]
    fn subcommand_names_are_reserved() {
        assert!(reserved("secret"));
        assert!(reserved("connections"));
        assert!(!reserved("prod-pg"));
    }
}
