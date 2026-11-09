use std::{
    io::{IsTerminal, stdin},
    thread::sleep,
    time::Duration,
};

use apicli_core::{Admin, Credential, Origin, Vault, validate_path};
use apicli_vault::{Store, hash_password, verify_password};
use reqwest::header::{HeaderName, HeaderValue};
use rpassword::prompt_password;
use secrecy::{ExposeSecret, SecretString};

use crate::{
    cli::{PasswordCommand, SecretCommand},
    failure::Failure,
};

pub fn add_hint(host: &str) -> String {
    format!("apicli secret add NAME --host {host} --header 'Authorization: Bearer {{secret}}'")
}

pub fn secret(command: SecretCommand) -> Result<u8, Failure> {
    require_terminal()?;
    let store = Store::open()?;
    let mut vault = store.load()?;
    authenticate(&store, &mut vault)?;
    let message = match command {
        SecretCommand::Add {
            name,
            host,
            header,
            paths,
        } => {
            let origin = Origin::parse(&host).map_err(Failure::Usage)?;
            let (header, template) = parse_template(&header)?;
            for path in &paths {
                validate_path(path).map_err(Failure::Usage)?;
            }
            if vault.find(&name).is_some() {
                return Err(Failure::Usage(format!(
                    "{name} already exists, use apicli secret rotate {name}"
                )));
            }
            if paths.is_empty()
                && let Some(existing) = vault
                    .credentials
                    .iter()
                    .find(|credential| credential.origin == origin && credential.paths.is_empty())
            {
                return Err(Failure::Usage(format!(
                    "{origin} already uses {} for every path, add --path to use this one on some paths only",
                    existing.name
                )));
            }
            let secret = prompt_secret(&name, &template)?;
            let scope = if paths.is_empty() {
                String::new()
            } else {
                format!(" on {}", paths.join(", "))
            };
            vault.credentials.push(Credential {
                name: name.clone(),
                origin: origin.clone(),
                paths,
                header,
                template,
                secret,
            });
            format!("Added {name} for {origin}{scope}")
        }
        SecretCommand::Rotate { name } => {
            let credential = vault.find_mut(&name).ok_or_else(|| unknown(&name))?;
            credential.secret = prompt_secret(&name, &credential.template)?;
            format!("Rotated {name}")
        }
        SecretCommand::Rm { name } => {
            let count = vault.credentials.len();
            vault
                .credentials
                .retain(|credential| credential.name != name);
            if vault.credentials.len() == count {
                return Err(unknown(&name));
            }
            format!("Removed {name}")
        }
    };
    store.save(&vault)?;
    println!("{message}");
    Ok(0)
}

pub fn password(command: PasswordCommand) -> Result<u8, Failure> {
    require_terminal()?;
    let store = Store::open()?;
    let mut vault = store.load()?;
    let message = match command {
        PasswordCommand::Set => {
            if vault.admin.is_some() {
                authenticate(&store, &mut vault)?;
            }
            let first = read_secret("New admin password: ")?;
            let second = read_secret("Repeat it: ")?;
            if first.expose_secret() != second.expose_secret() {
                return Err(Failure::Usage("the passwords don't match".into()));
            }
            if first.expose_secret().chars().count() < 8 {
                return Err(Failure::Usage("use at least 8 characters".into()));
            }
            vault.admin = Some(Admin {
                hash: hash_password(first.expose_secret())?,
                failures: 0,
            });
            "Admin password set"
        }
        PasswordCommand::Remove => {
            if vault.admin.is_none() {
                return Err(Failure::Usage("no admin password is set".into()));
            }
            authenticate(&store, &mut vault)?;
            vault.admin = None;
            "Admin password removed"
        }
    };
    store.save(&vault)?;
    println!("{message}");
    Ok(0)
}

pub fn authenticate(store: &Store, vault: &mut Vault) -> Result<(), Failure> {
    let Some(admin) = vault.admin.clone() else {
        eprintln!(
            "apicli: warning: no admin password is set, so anyone at this terminal can change apicli. Set one with: apicli password set"
        );
        return Ok(());
    };
    if admin.failures > 0 {
        let wait = 2u64.pow(admin.failures.min(6));
        eprintln!(
            "apicli: {} failed attempts, waiting {wait}s",
            admin.failures
        );
        sleep(Duration::from_secs(wait));
    }
    let password = read_secret("Admin password: ")?;
    let valid = verify_password(password.expose_secret(), &admin.hash);
    if let Some(admin) = &mut vault.admin {
        admin.failures = if valid { 0 } else { admin.failures + 1 };
    }
    if !valid || admin.failures > 0 {
        store.save(vault)?;
    }
    if valid {
        Ok(())
    } else {
        Err(Failure::Denied("wrong admin password".into()))
    }
}

pub fn require_terminal() -> Result<(), Failure> {
    if stdin().is_terminal() {
        Ok(())
    } else {
        Err(Failure::NeedsTerminal)
    }
}

fn parse_template(header: &str) -> Result<(String, String), Failure> {
    let invalid = || {
        Failure::Usage(format!(
            "--header must look like 'X-API-Key: {{secret}}' or 'Authorization: Bearer {{secret}}', got '{header}'"
        ))
    };
    let (name, template) = header.split_once(':').ok_or_else(invalid)?;
    let name = name.trim();
    let template = template.trim();
    HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid())?;
    if !template.contains("{secret}") {
        return Err(invalid());
    }
    Ok((name.to_string(), template.to_string()))
}

fn prompt_secret(name: &str, template: &str) -> Result<SecretString, Failure> {
    let secret = read_secret(&format!("Secret for {name}: "))?;
    if secret.expose_secret().chars().count() < 8 {
        return Err(Failure::Usage(
            "the secret must be at least 8 characters".into(),
        ));
    }
    let value = SecretString::from(template.replace("{secret}", secret.expose_secret()));
    HeaderValue::from_str(value.expose_secret()).map_err(|_| {
        Failure::Usage("the secret has characters that can't go in a header".into())
    })?;
    Ok(secret)
}

fn read_secret(label: &str) -> Result<SecretString, Failure> {
    prompt_password(label)
        .map(SecretString::from)
        .map_err(|error| Failure::Read(format!("the input: {error}")))
}

fn unknown(name: &str) -> Failure {
    Failure::Usage(format!(
        "no secret named {name}, run apicli hosts to list them"
    ))
}
