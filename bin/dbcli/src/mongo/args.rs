use clap::{ColorChoice, Parser};
use fieldkit_common::{Failure, Refused};

use crate::shared::{Common, engine_args};

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
    #[arg(hide = true)]
    pub extra: Vec<String>,
    #[command(flatten)]
    pub common: Common,
}

const SERVER: &str = "the connection name picks the server";
const AUTH: &str = "the connection URL sets the user and how to log in";
const TLS: &str = "the connection URL sets TLS";

const REFUSED: &[Refused] = &[
    Refused::new(None, "host", true, SERVER),
    Refused::new(None, "port", true, SERVER),
    Refused::new(Some('u'), "username", true, AUTH),
    Refused::new(
        Some('p'),
        "password",
        true,
        "dbcli sends the stored password itself",
    ),
    Refused::new(None, "authenticationDatabase", true, AUTH),
    Refused::new(None, "authenticationMechanism", true, AUTH),
    Refused::new(None, "awsIamSessionToken", true, AUTH),
    Refused::new(None, "gssapiServiceName", true, AUTH),
    Refused::new(None, "tls", false, TLS),
    Refused::new(None, "tlsCAFile", true, TLS),
    Refused::new(None, "tlsCertificateKeyFile", true, TLS),
    Refused::new(None, "tlsCertificateKeyFilePassword", true, TLS),
    Refused::new(None, "tlsAllowInvalidCertificates", false, TLS),
    Refused::new(None, "tlsAllowInvalidHostnames", false, TLS),
    Refused::new(None, "tlsUseSystemCA", false, TLS),
    Refused::new(None, "tlsCRLFile", true, TLS),
    Refused::new(None, "tlsDisabledProtocols", true, TLS),
    Refused::new(None, "tlsFIPSMode", false, TLS),
    Refused::new(
        Some('f'),
        "file",
        true,
        "scripts are not supported, pass each expression with --eval",
    ),
    Refused::new(
        None,
        "nodb",
        false,
        "dbcli always connects to the named connection",
    ),
    Refused::new(None, "shell", false, "there is no interactive mode"),
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
