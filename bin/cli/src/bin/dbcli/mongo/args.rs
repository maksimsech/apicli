use apicli::{Failure, Refused};
use clap::{ArgAction, ColorChoice, Parser};

use crate::call::engine_args;

#[derive(Debug, Parser)]
#[command(
    name = "dbcli NAME",
    about = "Run mongosh expressions on a MongoDB connection, like mongosh --eval",
    color = ColorChoice::Never,
    args_override_self = true,
    disable_help_flag = true,
    disable_version_flag = true
)]
pub struct MongoArgs {
    #[arg(
        long,
        value_name = "EXPR",
        allow_hyphen_values = true,
        help = "A mongosh expression like db.orders.find({status: 'paid'}). Repeat for more, only the last result prints"
    )]
    pub eval: Vec<String>,
    #[arg(
        long,
        value_name = "FORMAT",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "canonical",
        value_parser = ["canonical", "relaxed"],
        help = "Print the result as Extended JSON, canonical or relaxed"
    )]
    pub json: Option<String>,
    #[arg(long, hide = true)]
    pub quiet: bool,
    #[arg(long, hide = true)]
    pub norc: bool,
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
const AUTH: &str = "the connection URL sets the user and how to log in";
const TLS: &str = "the connection URL sets TLS";

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
    refused(None, "host", true, SERVER),
    refused(None, "port", true, SERVER),
    refused(Some('u'), "username", true, AUTH),
    refused(
        Some('p'),
        "password",
        true,
        "dbcli sends the stored password itself",
    ),
    refused(None, "authenticationDatabase", true, AUTH),
    refused(None, "authenticationMechanism", true, AUTH),
    refused(None, "awsIamSessionToken", true, AUTH),
    refused(None, "gssapiServiceName", true, AUTH),
    refused(None, "tls", false, TLS),
    refused(None, "tlsCAFile", true, TLS),
    refused(None, "tlsCertificateKeyFile", true, TLS),
    refused(None, "tlsCertificateKeyFilePassword", true, TLS),
    refused(None, "tlsAllowInvalidCertificates", false, TLS),
    refused(None, "tlsAllowInvalidHostnames", false, TLS),
    refused(None, "tlsUseSystemCA", false, TLS),
    refused(None, "tlsCRLFile", true, TLS),
    refused(None, "tlsDisabledProtocols", true, TLS),
    refused(None, "tlsFIPSMode", false, TLS),
    refused(
        Some('f'),
        "file",
        true,
        "scripts are not supported, pass each expression with --eval",
    ),
    refused(
        None,
        "nodb",
        false,
        "dbcli always connects to the named connection",
    ),
    refused(None, "shell", false, "there is no interactive mode"),
];

pub fn parse(args: &[String]) -> Result<MongoArgs, Failure> {
    let args = engine_args::<MongoArgs>(args, REFUSED)?;
    if let Some(extra) = args.extra.first() {
        return Err(Failure::Refused {
            flag: extra.clone(),
            reason: "the connection name picks the server and database, pass expressions with --eval",
        });
    }
    if args.eval.is_empty() {
        return Err(Failure::Usage(
            "pass an expression with --eval, like: dbcli NAME --eval 'db.orders.find()'. Interactive mode is not supported".into(),
        ));
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(list: &[&str]) -> Result<MongoArgs, Failure> {
        parse(&list.iter().map(|arg| arg.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn rejects_every_refused_flag() {
        for refused in REFUSED {
            let mut list = vec![format!("--{}", refused.long)];
            if refused.value {
                list.push("value".into());
            }
            list.push("--eval".into());
            list.push("db.orders.find()".into());

            assert!(
                matches!(parse(&list), Err(Failure::Refused { .. })),
                "--{} was accepted",
                refused.long
            );
        }
    }

    #[test]
    fn rejects_a_connection_uri_file_or_missing_eval() {
        for args in [
            &[
                "mongodb://agent@attacker.example/shop",
                "--eval",
                "db.x.find()",
            ][..],
            &["script.js"],
            &["-u", "root", "--eval", "db.x.find()"],
            &["-pguess", "--eval", "db.x.find()"],
        ] {
            assert!(
                matches!(parse_args(args), Err(Failure::Refused { .. })),
                "{args:?} was accepted"
            );
        }
        assert!(matches!(parse_args(&[]), Err(Failure::Usage(_))));
    }
}
