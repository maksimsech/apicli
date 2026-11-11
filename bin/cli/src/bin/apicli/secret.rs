use apicli::{Failure, authenticate, read_secret, require_terminal};
use fieldkit_policy::{Credential, Origin, validate_path};
use fieldkit_vault::Store;
use reqwest::header::{HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretString};

use crate::cli::SecretCommand;

pub fn add_hint(host: &str) -> String {
    format!("apicli secret add NAME --host {host} --header 'Authorization: Bearer {{secret}}'")
}

pub fn secret(command: SecretCommand) -> Result<u8, Failure> {
    require_terminal()?;
    let store = Store::open()?;
    let mut vault = store.load()?;
    authenticate("apicli", &store, &mut vault)?;
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

fn unknown(name: &str) -> Failure {
    Failure::Usage(format!(
        "no secret named {name}, run apicli hosts to list them"
    ))
}
