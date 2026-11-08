use std::path::PathBuf;

use clap::{
    Arg, ArgAction, Args, ColorChoice, CommandFactory, Error, FromArgMatches, Parser, Subcommand,
    ValueEnum, error::ErrorKind, parser::ValueSource,
};

use crate::failure::Failure;

#[derive(Debug, Parser)]
#[command(
    name = "apicli",
    version,
    about = "curl for APIs that need credentials",
    color = ColorChoice::Never,
    args_override_self = true,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[command(flatten)]
    pub request: RequestArgs,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "List configured hosts and what is allowed on them")]
    Hosts {
        #[arg(long, help = "Print JSON")]
        json: bool,
    },
    #[command(about = "Check whether a request would be allowed, without sending it")]
    Explain {
        method: String,
        url: String,
        #[arg(long, help = "Print JSON")]
        json: bool,
    },
    #[command(about = "Manage stored secrets (run by the user in a terminal)")]
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    #[command(about = "Allow a method on a path (run by the user in a terminal)")]
    Allow {
        #[command(subcommand)]
        command: AllowCommand,
    },
    #[command(about = "Deny a method on a path (run by the user in a terminal)")]
    Deny {
        #[command(subcommand)]
        command: DenyCommand,
    },
    #[command(about = "Show, edit or verify policy.toml")]
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    #[command(about = "Set or remove the admin password (run by the user in a terminal)")]
    Password {
        #[command(subcommand)]
        command: PasswordCommand,
    },
    #[command(about = "The agent skill for apicli")]
    Skill {
        #[command(subcommand)]
        command: SkillCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum SecretCommand {
    #[command(about = "Store a secret bound to one host")]
    Add {
        name: String,
        #[arg(long, help = "Host the secret is sent to, like api.example.com")]
        host: String,
        #[arg(long, help = "Header template, like 'Authorization: Bearer {secret}'")]
        header: String,
    },
    #[command(about = "Replace a stored secret")]
    Rotate { name: String },
    #[command(about = "Delete a stored secret")]
    Rm { name: String },
}

#[derive(Debug, Subcommand)]
pub enum AllowCommand {
    #[command(about = "Allow METHOD on paths matching PATH, like '/v1/orders/*/notes'")]
    Add {
        host: String,
        method: String,
        path: String,
        #[arg(long, value_name = "BYTES", help = "Largest body allowed")]
        max_body: Option<usize>,
        #[arg(long, value_name = "TYPE", help = "Required Content-Type")]
        content_type: Option<String>,
        #[arg(long, help = "Allow a body on GET, HEAD or OPTIONS")]
        allow_body: bool,
    },
    #[command(about = "Remove an allow rule")]
    Rm {
        host: String,
        method: String,
        path: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum DenyCommand {
    #[command(about = "Deny METHOD on paths matching PATH, like '/v1/exports/**'")]
    Add {
        host: String,
        method: String,
        path: String,
    },
    #[command(about = "Remove a deny rule")]
    Rm {
        host: String,
        method: String,
        path: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    #[command(about = "Print policy.toml")]
    Show,
    #[command(about = "Edit policy.toml in $EDITOR and accept the result")]
    Edit,
    #[command(about = "Check that policy.toml is intact")]
    Verify,
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
    #[command(about = "Install SKILL.md for the agent tools on this machine")]
    Install {
        #[arg(long, value_enum, help = "Install for one tool only")]
        target: Option<Target>,
        #[arg(long, value_name = "DIR", help = "Install into this skills directory")]
        path: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Target {
    Claude,
    Opencode,
    Codex,
    Agents,
}

#[derive(Debug, Args)]
pub struct RequestArgs {
    #[arg(value_name = "URL", required = true, help = "The URL to request")]
    pub url: Option<String>,
    #[arg(hide = true)]
    pub extra_urls: Vec<String>,
    #[arg(
        short = 'X',
        long = "request",
        value_name = "METHOD",
        help = "Request method"
    )]
    pub method: Option<String>,
    #[arg(
        short = 'H',
        long = "header",
        value_name = "HEADER",
        help = "Header as 'Name: value'"
    )]
    pub headers: Vec<String>,
    #[arg(
        short = 'd',
        long,
        value_name = "DATA",
        help = "Form data, @file or @- to read it"
    )]
    pub data: Vec<String>,
    #[arg(long, value_name = "DATA", help = "Form data, sent as is")]
    pub data_raw: Vec<String>,
    #[arg(
        long,
        value_name = "DATA",
        help = "Binary data, @file or @- to read it"
    )]
    pub data_binary: Vec<String>,
    #[arg(
        long,
        value_name = "DATA",
        help = "URL-encoded data: content, name=content, @file, name@file"
    )]
    pub data_urlencode: Vec<String>,
    #[arg(long, value_name = "JSON", help = "JSON body, @file or @- to read it")]
    pub json: Vec<String>,
    #[arg(short = 'G', long, help = "Send data in the query string with GET")]
    pub get: bool,
    #[arg(short = 'I', long, help = "Send HEAD and show headers")]
    pub head: bool,
    #[arg(short = 'i', long, help = "Show response headers before the body")]
    pub include: bool,
    #[arg(short = 'f', long, help = "Exit 22 without a body on HTTP 4xx and 5xx")]
    pub fail: bool,
    #[arg(long, help = "Exit 22 on HTTP 4xx and 5xx, keep the body")]
    pub fail_with_body: bool,
    #[arg(
        short = 'o',
        long,
        value_name = "FILE",
        help = "Write the body to a file"
    )]
    pub output: Option<PathBuf>,
    #[arg(
        short = 'w',
        long,
        value_name = "FORMAT",
        help = "Print after the body: %{http_code} %{time_total} %{size_download} %{content_type} %{url_effective} %{method}"
    )]
    pub write_out: Option<String>,
    #[arg(
        short = 'm',
        long,
        value_name = "SECONDS",
        help = "Maximum seconds for the whole request"
    )]
    pub max_time: Option<f64>,
    #[arg(long, value_name = "SECONDS", help = "Maximum seconds to connect")]
    pub connect_timeout: Option<f64>,
    #[arg(long, help = "Ask for a compressed response and decompress it")]
    pub compressed: bool,
    #[arg(short = 'A', long, value_name = "NAME", help = "User-Agent header")]
    pub user_agent: Option<String>,
    #[arg(short = 'e', long, value_name = "URL", help = "Referer header")]
    pub referer: Option<String>,
    #[arg(short = 'L', long, help = "Follow redirects, checking every hop")]
    pub location: bool,
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = 50,
        help = "Maximum redirects to follow"
    )]
    pub max_redirs: u32,
    #[arg(
        short = 'v',
        long,
        help = "Show request and response headers on stderr"
    )]
    pub verbose: bool,
    #[arg(short = 's', long, hide = true)]
    pub silent: bool,
    #[arg(short = 'S', long, hide = true)]
    pub show_error: bool,
    #[arg(short = 'g', long, hide = true)]
    pub globoff: bool,
}

struct Refused {
    short: Option<char>,
    long: &'static str,
    value: bool,
    reason: &'static str,
}

const REFUSED: &[Refused] = &[
    Refused {
        short: Some('k'),
        long: "insecure",
        value: false,
        reason: "certificate checks are always on",
    },
    Refused {
        short: None,
        long: "resolve",
        value: true,
        reason: "requests always go to the host in the URL",
    },
    Refused {
        short: None,
        long: "connect-to",
        value: true,
        reason: "requests always go to the host in the URL",
    },
    Refused {
        short: Some('x'),
        long: "proxy",
        value: true,
        reason: "requests never go through a proxy",
    },
    Refused {
        short: None,
        long: "noproxy",
        value: true,
        reason: "requests never go through a proxy",
    },
    Refused {
        short: Some('K'),
        long: "config",
        value: true,
        reason: "options can't come from a file",
    },
    Refused {
        short: None,
        long: "libcurl",
        value: true,
        reason: "apicli is not built on libcurl",
    },
    Refused {
        short: None,
        long: "trace",
        value: true,
        reason: "use -v instead",
    },
    Refused {
        short: None,
        long: "trace-ascii",
        value: true,
        reason: "use -v instead",
    },
    Refused {
        short: Some('u'),
        long: "user",
        value: true,
        reason: "apicli adds credentials itself",
    },
    Refused {
        short: None,
        long: "location-trusted",
        value: false,
        reason: "credentials never follow redirects to other hosts",
    },
    Refused {
        short: None,
        long: "next",
        value: false,
        reason: "apicli sends one request per call",
    },
    Refused {
        short: Some('T'),
        long: "upload-file",
        value: true,
        reason: "send the file with --data-binary @file",
    },
    Refused {
        short: Some('b'),
        long: "cookie",
        value: true,
        reason: "cookies are not kept or sent",
    },
    Refused {
        short: Some('c'),
        long: "cookie-jar",
        value: true,
        reason: "cookies are not kept or sent",
    },
    Refused {
        short: Some('F'),
        long: "form",
        value: true,
        reason: "multipart forms are not supported yet",
    },
];

impl Refused {
    fn arg(&self) -> Arg {
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

    fn name(&self) -> String {
        match self.short {
            Some(short) => format!("-{short}/--{}", self.long),
            None => format!("--{}", self.long),
        }
    }
}

pub fn parse(args: Vec<String>) -> Result<Cli, Failure> {
    let command = REFUSED.iter().fold(Cli::command(), |command, refused| {
        command.arg(refused.arg())
    });
    let matches = command.try_get_matches_from(args).map_err(usage)?;
    if let Some(refused) = REFUSED
        .iter()
        .find(|refused| matches.value_source(refused.long) == Some(ValueSource::CommandLine))
    {
        return Err(Failure::Refused {
            flag: refused.name(),
            reason: refused.reason,
        });
    }
    let cli = Cli::from_arg_matches(&matches).map_err(usage)?;
    if !cli.request.extra_urls.is_empty() {
        return Err(Failure::Usage(format!(
            "one URL per call, got {}",
            cli.request.extra_urls.len() + 1
        )));
    }
    Ok(cli)
}

fn usage(error: Error) -> Failure {
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
        "{} (see apicli --help)",
        summary.trim_start_matches("error: ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(list: &[&str]) -> Result<Cli, Failure> {
        parse(
            ["apicli"]
                .iter()
                .chain(list)
                .map(|arg| arg.to_string())
                .collect(),
        )
    }

    #[test]
    fn rejects_second_url() {
        let error = parse_args(&["https://api.example.com/v1/me", "https://attacker.example/"])
            .unwrap_err();

        assert_eq!(error.code(), 2);
    }

    #[test]
    fn rejects_every_refused_flag() {
        for refused in REFUSED {
            let mut list = vec![format!("--{}", refused.long)];
            if refused.value {
                list.push("value".into());
            }
            list.push("https://api.example.com/".into());

            let result = parse(["apicli".to_string()].into_iter().chain(list).collect());

            assert!(
                matches!(result, Err(Failure::Refused { .. })),
                "--{} was accepted",
                refused.long
            );
        }
    }

    #[test]
    fn rejects_refused_flag_inside_short_cluster() {
        let error = parse_args(&["-sSk", "https://api.example.com/"]).unwrap_err();

        assert_eq!(
            error.to_string(),
            "-k/--insecure is not supported: certificate checks are always on"
        );
    }

    #[test]
    fn rejects_refused_flag_with_attached_value() {
        let error =
            parse_args(&["-xhttp://127.0.0.1:8080", "https://api.example.com/"]).unwrap_err();

        assert!(matches!(error, Failure::Refused { .. }));
    }

    #[test]
    fn rejects_unknown_flag() {
        let error = parse_args(&["--proxy-insecure", "https://api.example.com/"]).unwrap_err();

        assert_eq!(error.code(), 2);
    }

    #[test]
    fn accepts_curl_style_clusters() {
        let cli = parse_args(&["-sSi", "-XPOST", "https://api.example.com/"]).unwrap();

        assert!(cli.request.include);
        assert_eq!(cli.request.method.as_deref(), Some("POST"));
    }
}
