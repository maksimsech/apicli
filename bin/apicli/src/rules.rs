use std::{
    env, fs,
    io::{Write, stdin, stdout},
    path::Path,
    process::{self, Command},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

use fieldkit_common::{Failure, finish, open_for_change};
use fieldkit_policy::{Origin, Policy, Rate, Rule, Vault};
use fieldkit_vault::Store;

use crate::cli::{AllowCommand, DenyCommand, LimitCommand, PolicyCommand};

const DEFAULT_EDITOR: &str = if cfg!(windows) { "notepad" } else { "vi" };

pub fn allow(command: AllowCommand) -> Result<u8, Failure> {
    let (store, mut vault) = open_for_change("apicli")?;
    let policy = &mut vault.policy;
    let message = match command {
        AllowCommand::Add {
            host,
            method,
            path,
            max_body,
            content_type,
            allow_body,
        } => {
            let origin = Origin::parse(&host).map_err(Failure::Usage)?;
            let rule = Rule {
                method: method.to_ascii_uppercase(),
                path,
                max_body,
                content_type,
                allow_body,
            };
            rule.validate().map_err(Failure::Usage)?;
            let message = format!("Allowed {rule} on {origin}");
            let rules = &mut policy.hosts.entry(origin).or_default().allow;
            rules.retain(|existing| !same(existing, &rule.method, &rule.path));
            rules.push(rule);
            message
        }
        AllowCommand::Rm { host, method, path } => {
            let origin = Origin::parse(&host).map_err(Failure::Usage)?;
            remove(
                policy.hosts.get_mut(&origin).map(|host| &mut host.allow),
                &method,
                &path,
            )?;
            format!(
                "Removed allow {} {path} on {origin}",
                method.to_ascii_uppercase()
            )
        }
    };
    finish(&store, &vault, &message)
}

pub fn deny(command: DenyCommand) -> Result<u8, Failure> {
    let (store, mut vault) = open_for_change("apicli")?;
    let policy = &mut vault.policy;
    let message = match command {
        DenyCommand::Add { host, method, path } => {
            let origin = Origin::parse(&host).map_err(Failure::Usage)?;
            let rule = Rule {
                method: method.to_ascii_uppercase(),
                path,
                max_body: None,
                content_type: None,
                allow_body: false,
            };
            rule.validate().map_err(Failure::Usage)?;
            let message = format!("Denied {rule} on {origin}");
            let rules = &mut policy.hosts.entry(origin).or_default().deny;
            rules.retain(|existing| !same(existing, &rule.method, &rule.path));
            rules.push(rule);
            message
        }
        DenyCommand::Rm { host, method, path } => {
            let origin = Origin::parse(&host).map_err(Failure::Usage)?;
            remove(
                policy.hosts.get_mut(&origin).map(|host| &mut host.deny),
                &method,
                &path,
            )?;
            format!(
                "Removed deny {} {path} on {origin}",
                method.to_ascii_uppercase()
            )
        }
    };
    finish(&store, &vault, &message)
}

pub fn limit(command: LimitCommand) -> Result<u8, Failure> {
    let (store, mut vault) = open_for_change("apicli")?;
    let policy = &mut vault.policy;
    let message = match command {
        LimitCommand::Set {
            host,
            rate,
            burst,
            daily,
        } => {
            let origin = Origin::parse(&host).map_err(Failure::Usage)?;
            let rate = Rate::parse(&rate).map_err(Failure::Usage)?;
            let host = policy.hosts.entry(origin.clone()).or_default();
            host.rate = Some(rate);
            host.burst = burst;
            host.daily = daily;
            format!("Limited {origin} to {}", host.limits())
        }
        LimitCommand::Rm { host } => {
            let origin = Origin::parse(&host).map_err(Failure::Usage)?;
            let host = policy
                .hosts
                .get_mut(&origin)
                .filter(|host| host.rate.is_some() || host.burst.is_some() || host.daily.is_some())
                .ok_or_else(|| {
                    Failure::Usage(format!(
                        "{origin} has no limits, run apicli hosts to list them"
                    ))
                })?;
            host.rate = None;
            host.burst = None;
            host.daily = None;
            format!("Removed the limits on {origin}")
        }
    };
    finish(&store, &vault, &message)
}

pub fn policy(command: PolicyCommand) -> Result<u8, Failure> {
    match command {
        PolicyCommand::Show => {
            let vault = Store::open()?.load()?;
            print!(
                "{}",
                effective(&vault).to_toml().map_err(Failure::Integrity)?
            );
            Ok(0)
        }
        PolicyCommand::Edit => {
            let (store, mut vault) = open_for_change("apicli")?;
            vault.policy = edit(&effective(&vault))?;
            finish(&store, &vault, "Saved the policy")
        }
    }
}

fn same(rule: &Rule, method: &str, path: &str) -> bool {
    rule.method.eq_ignore_ascii_case(method) && rule.path == path
}

fn remove(rules: Option<&mut Vec<Rule>>, method: &str, path: &str) -> Result<(), Failure> {
    let rules = rules
        .filter(|rules| rules.iter().any(|rule| same(rule, method, path)))
        .ok_or_else(|| {
            Failure::Usage(format!(
                "no rule for {method} {path}, run apicli hosts to list them"
            ))
        })?;
    rules.retain(|rule| !same(rule, method, path));
    Ok(())
}

fn effective(vault: &Vault) -> Policy {
    let mut policy = vault.policy.clone();
    for credential in &vault.credentials {
        policy.hosts.entry(credential.origin.clone()).or_default();
    }
    policy
}

fn edit(policy: &Policy) -> Result<Policy, Failure> {
    let draft = env::temp_dir().join(format!("apicli-policy-{}.toml", process::id()));
    let text = policy.to_toml().map_err(Failure::Integrity)?;
    fs::write(&draft, text).map_err(|error| Failure::Write(error.to_string()))?;
    let result = edit_loop(&draft);
    let _ = fs::remove_file(&draft);
    result
}

fn edit_loop(draft: &Path) -> Result<Policy, Failure> {
    let editor = env::var("VISUAL")
        .or_else(|_| env::var("EDITOR"))
        .unwrap_or_else(|_| DEFAULT_EDITOR.into());
    loop {
        let status = editor_command(&editor, draft)
            .status()
            .map_err(|error| Failure::Usage(format!("could not start {editor}: {error}")))?;
        if !status.success() {
            return Err(Failure::Usage(
                "the editor failed, the policy was not changed".into(),
            ));
        }
        let text = fs::read_to_string(draft).map_err(|error| Failure::Read(error.to_string()))?;
        match Policy::parse(text.trim_start_matches('\u{feff}')) {
            Ok(policy) => return Ok(policy),
            Err(error) => {
                eprintln!("apicli: the policy is invalid: {error}");
                if !confirm("Edit again? [Y/n] ")? {
                    return Err(Failure::Usage("the policy was not changed".into()));
                }
            }
        }
    }
}

#[cfg(not(windows))]
fn editor_command(editor: &str, draft: &Path) -> Command {
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("sh")
        .arg(draft);
    command
}

#[cfg(windows)]
fn editor_command(editor: &str, draft: &Path) -> Command {
    let mut command = Command::new("cmd");
    command.raw_arg(format!("/S /C \"{editor} \"{}\"\"", draft.display()));
    command
}

fn confirm(question: &str) -> Result<bool, Failure> {
    print!("{question}");
    stdout()
        .flush()
        .map_err(|error| Failure::Write(error.to_string()))?;
    let mut answer = String::new();
    stdin()
        .read_line(&mut answer)
        .map_err(|error| Failure::Read(error.to_string()))?;
    Ok(!answer.trim().eq_ignore_ascii_case("n"))
}
