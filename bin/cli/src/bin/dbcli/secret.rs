use apicli::{Failure, finish, open_for_change, read_secret};
use apicli_policy::{Connection, ConnectionUrl};
use secrecy::{ExposeSecret, SecretString};

use crate::cli::{SecretCommand, reserved};

pub fn add_hint(name: &str) -> String {
    format!("dbcli secret add {name} --url 'postgres://USER@HOST:5432/DATABASE'")
}

pub fn unknown(name: &str) -> Failure {
    Failure::Usage(format!(
        "no connection named {name}, run dbcli connections to list them"
    ))
}

pub fn secret(command: SecretCommand) -> Result<u8, Failure> {
    let (store, mut vault) = open_for_change("dbcli")?;
    let message = match command {
        SecretCommand::Add { name, url } => {
            validate(&name)?;
            let url = ConnectionUrl::parse(&url).map_err(Failure::Usage)?;
            if vault.connection(&name).is_some() {
                return Err(Failure::Usage(format!(
                    "{name} already exists, use dbcli secret rotate {name}"
                )));
            }
            let password = prompt(&name)?;
            let message = format!("Added {name} for {url}, read-only");
            vault.connections.push(Connection {
                name,
                url,
                password,
                write: false,
                rate: None,
                burst: None,
                daily: None,
            });
            message
        }
        SecretCommand::Rotate { name } => {
            let password = prompt(&name)?;
            let connection = vault.connection_mut(&name).ok_or_else(|| unknown(&name))?;
            connection.password = password;
            format!("Rotated {name}")
        }
        SecretCommand::Rm { name } => {
            let count = vault.connections.len();
            vault
                .connections
                .retain(|connection| connection.name != name);
            if vault.connections.len() == count {
                return Err(unknown(&name));
            }
            format!("Removed {name}")
        }
    };
    finish(&store, &vault, &message)
}

fn validate(name: &str) -> Result<(), Failure> {
    let valid = name
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character));
    if !valid {
        return Err(Failure::Usage(
            "connection names use letters, digits, -, _ and ., and start with a letter or digit"
                .into(),
        ));
    }
    if reserved(name) {
        return Err(Failure::Usage(format!(
            "{name} is a dbcli command, pick another name"
        )));
    }
    Ok(())
}

fn prompt(name: &str) -> Result<SecretString, Failure> {
    let password = read_secret(&format!("Password for {name}: "))?;
    if password.expose_secret().chars().count() < 8 {
        return Err(Failure::Usage(
            "the password must be at least 8 characters, so dbcli can mask it in output".into(),
        ));
    }
    Ok(password)
}
