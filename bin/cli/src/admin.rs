use std::io::{IsTerminal, stdin};

use apicli_core::{Credential, Origin, READ_METHODS};
use apicli_vault::Store;
use reqwest::header::{HeaderName, HeaderValue};
use rpassword::prompt_password;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use crate::{cli::SecretCommand, failure::Failure};

#[derive(Serialize)]
struct Host {
    host: String,
    credential: String,
    header: String,
    methods: Vec<&'static str>,
}

pub fn hosts(json: bool) -> Result<u8, Failure> {
    let vault = Store::open()?.load()?;
    let hosts = vault
        .credentials
        .iter()
        .map(|credential| Host {
            host: credential.origin.to_string(),
            credential: credential.name.clone(),
            header: credential.header.clone(),
            methods: READ_METHODS.to_vec(),
        })
        .collect::<Vec<_>>();
    if json {
        println!(
            "{}",
            serde_json::to_string(&hosts).map_err(|error| Failure::Write(error.to_string()))?
        );
    } else if hosts.is_empty() {
        println!(
            "No hosts are configured. The user can add one with: {}",
            add_hint("api.example.com")
        );
    } else {
        for host in hosts {
            println!("{}", host.host);
            println!("  credential: {} ({})", host.credential, host.header);
            println!("  allowed: {}", host.methods.join(", "));
        }
    }
    Ok(0)
}

pub fn add_hint(host: &str) -> String {
    format!("apicli secret add NAME --host {host} --header 'Authorization: Bearer {{secret}}'")
}

pub fn secret(command: SecretCommand) -> Result<u8, Failure> {
    require_terminal()?;
    let store = Store::open()?;
    let mut vault = store.load()?;
    match command {
        SecretCommand::Add { name, host, header } => {
            let origin = Origin::parse(&host).map_err(Failure::Usage)?;
            let (header, template) = parse_template(&header)?;
            if vault.find(&name).is_some() {
                return Err(Failure::Usage(format!(
                    "{name} already exists, use apicli secret rotate {name}"
                )));
            }
            if let Some(existing) = vault
                .credentials
                .iter()
                .find(|credential| credential.origin == origin)
            {
                return Err(Failure::Usage(format!(
                    "{origin} already uses {}",
                    existing.name
                )));
            }
            let secret = prompt_secret(&name, &template)?;
            vault.credentials.push(Credential {
                name: name.clone(),
                origin: origin.clone(),
                header,
                template,
                secret,
            });
            store.save(&vault)?;
            println!("Added {name} for {origin}");
        }
        SecretCommand::Rotate { name } => {
            let credential = vault.find_mut(&name).ok_or_else(|| unknown(&name))?;
            credential.secret = prompt_secret(&name, &credential.template)?;
            store.save(&vault)?;
            println!("Rotated {name}");
        }
        SecretCommand::Rm { name } => {
            let count = vault.credentials.len();
            vault
                .credentials
                .retain(|credential| credential.name != name);
            if vault.credentials.len() == count {
                return Err(unknown(&name));
            }
            store.save(&vault)?;
            println!("Removed {name}");
        }
    }
    Ok(0)
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
    let secret = SecretString::from(
        prompt_password(format!("Secret for {name}: "))
            .map_err(|error| Failure::Read(format!("the secret: {error}")))?,
    );
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
