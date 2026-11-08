use std::{
    env, fs,
    io::{Write, stdin, stdout},
    path::Path,
    process::{self, Command},
};

use apicli_core::{HostPolicy, Origin, Policy, READ_METHODS, Rate, Rule, Vault};
use apicli_vault::Store;

use crate::{
    admin::authenticate,
    cli::{AllowCommand, DenyCommand, LimitCommand, PolicyCommand},
    failure::Failure,
};

pub fn load_policy(store: &Store, vault: &Vault) -> Result<Policy, Failure> {
    match store.read_policy(vault)? {
        Some(text) => Policy::parse(&text)
            .map_err(|error| Failure::Integrity(format!("policy.toml is invalid: {error}"))),
        None => Ok(Policy::default()),
    }
}

pub fn allow(command: AllowCommand) -> Result<u8, Failure> {
    let (store, mut vault, mut policy) = open_for_change()?;
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
                &mut policy.hosts.entry(origin.clone()).or_default().allow,
                &method,
                &path,
            )?;
            format!(
                "Removed allow {} {path} on {origin}",
                method.to_ascii_uppercase()
            )
        }
    };
    finish(&store, &mut vault, &policy, &message)
}

pub fn deny(command: DenyCommand) -> Result<u8, Failure> {
    let (store, mut vault, mut policy) = open_for_change()?;
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
                &mut policy.hosts.entry(origin.clone()).or_default().deny,
                &method,
                &path,
            )?;
            format!(
                "Removed deny {} {path} on {origin}",
                method.to_ascii_uppercase()
            )
        }
    };
    finish(&store, &mut vault, &policy, &message)
}

pub fn limit(command: LimitCommand) -> Result<u8, Failure> {
    let (store, mut vault, mut policy) = open_for_change()?;
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
            let host = policy.hosts.entry(origin.clone()).or_default();
            host.rate = None;
            host.burst = None;
            host.daily = None;
            format!("Removed the limits on {origin}")
        }
    };
    finish(&store, &mut vault, &policy, &message)
}

pub fn policy(command: PolicyCommand) -> Result<u8, Failure> {
    let store = Store::open()?;
    let mut vault = store.load()?;
    match command {
        PolicyCommand::Show => match store.read_policy(&vault)? {
            Some(text) => print!("{text}"),
            None => println!(
                "No policy.toml yet. Every configured host allows {}.",
                READ_METHODS.join(", ")
            ),
        },
        PolicyCommand::Verify => {
            load_policy(&store, &vault)?;
            println!("{} is intact", store.policy_path().display());
        }
        PolicyCommand::Edit => {
            authenticate(&store, &mut vault)?;
            edit(&store, &mut vault)?;
        }
    }
    Ok(0)
}

fn open_for_change() -> Result<(Store, Vault, Policy), Failure> {
    let store = Store::open()?;
    let mut vault = store.load()?;
    authenticate(&store, &mut vault)?;
    let policy = load_policy(&store, &vault)?;
    Ok((store, vault, policy))
}

fn finish(store: &Store, vault: &mut Vault, policy: &Policy, message: &str) -> Result<u8, Failure> {
    let text = policy.to_toml().map_err(Failure::Integrity)?;
    store.write_policy(vault, &text)?;
    store.save(vault)?;
    println!("{message}");
    Ok(0)
}

fn same(rule: &Rule, method: &str, path: &str) -> bool {
    rule.method.eq_ignore_ascii_case(method) && rule.path == path
}

fn remove(rules: &mut Vec<Rule>, method: &str, path: &str) -> Result<(), Failure> {
    let count = rules.len();
    rules.retain(|rule| !same(rule, method, path));
    if rules.len() == count {
        Err(Failure::Usage(format!(
            "no rule for {method} {path}, run apicli hosts to list them"
        )))
    } else {
        Ok(())
    }
}

fn edit(store: &Store, vault: &mut Vault) -> Result<(), Failure> {
    let current = match store.read_policy_unchecked()? {
        Some(text) => text,
        None => starter(vault)?,
    };
    let draft = env::temp_dir().join(format!("apicli-policy-{}.toml", process::id()));
    fs::write(&draft, current).map_err(|error| Failure::Write(error.to_string()))?;
    let result = edit_loop(store, vault, &draft);
    let _ = fs::remove_file(&draft);
    result
}

fn edit_loop(store: &Store, vault: &mut Vault, draft: &Path) -> Result<(), Failure> {
    let editor = env::var("VISUAL")
        .or_else(|_| env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".into());
    loop {
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("{editor} \"$1\""))
            .arg("sh")
            .arg(draft)
            .status()
            .map_err(|error| Failure::Usage(format!("could not start {editor}: {error}")))?;
        if !status.success() {
            return Err(Failure::Usage(
                "the editor failed, policy.toml was not changed".into(),
            ));
        }
        let text = fs::read_to_string(draft).map_err(|error| Failure::Read(error.to_string()))?;
        match Policy::parse(&text) {
            Ok(_) => {
                store.write_policy(vault, &text)?;
                store.save(vault)?;
                println!("Saved {}", store.policy_path().display());
                return Ok(());
            }
            Err(error) => {
                eprintln!("apicli: policy.toml is invalid: {error}");
                if !confirm("Edit again? [Y/n] ")? {
                    return Err(Failure::Usage("policy.toml was not changed".into()));
                }
            }
        }
    }
}

fn starter(vault: &Vault) -> Result<String, Failure> {
    let mut policy = Policy::default();
    for credential in &vault.credentials {
        policy
            .hosts
            .insert(credential.origin.clone(), HostPolicy::default());
    }
    policy.to_toml().map_err(Failure::Integrity)
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
