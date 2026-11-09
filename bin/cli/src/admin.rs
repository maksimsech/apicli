use std::{
    io::{IsTerminal, stdin},
    thread::sleep,
    time::Duration,
};

use apicli_policy::{Admin, Vault};
use apicli_vault::{Store, hash_password, verify_password};
use rpassword::prompt_password;
use secrecy::{ExposeSecret, SecretString};

use crate::{Failure, PasswordCommand};

pub fn password(tool: &str, command: PasswordCommand) -> Result<u8, Failure> {
    require_terminal()?;
    let store = Store::open()?;
    let mut vault = store.load()?;
    let message = match command {
        PasswordCommand::Set => {
            if vault.admin.is_some() {
                authenticate(tool, &store, &mut vault)?;
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
            authenticate(tool, &store, &mut vault)?;
            vault.admin = None;
            "Admin password removed"
        }
    };
    finish(&store, &vault, message)
}

pub fn authenticate(tool: &str, store: &Store, vault: &mut Vault) -> Result<(), Failure> {
    let Some(admin) = vault.admin.clone() else {
        eprintln!(
            "{tool}: warning: no admin password is set, so anyone at this terminal can change {tool}. Set one with: {tool} password set"
        );
        return Ok(());
    };
    if admin.failures > 0 {
        let wait = 2u64.pow(admin.failures.min(6));
        eprintln!(
            "{tool}: {} failed attempts, waiting {wait}s",
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

pub fn open_for_change(tool: &str) -> Result<(Store, Vault), Failure> {
    require_terminal()?;
    let store = Store::open()?;
    let mut vault = store.load()?;
    authenticate(tool, &store, &mut vault)?;
    Ok((store, vault))
}

pub fn finish(store: &Store, vault: &Vault, message: &str) -> Result<u8, Failure> {
    store.save(vault)?;
    println!("{message}");
    Ok(0)
}

pub fn require_terminal() -> Result<(), Failure> {
    if stdin().is_terminal() {
        Ok(())
    } else {
        Err(Failure::NeedsTerminal)
    }
}

pub fn read_secret(label: &str) -> Result<SecretString, Failure> {
    prompt_password(label)
        .map(SecretString::from)
        .map_err(|error| Failure::Read(format!("the input: {error}")))
}
