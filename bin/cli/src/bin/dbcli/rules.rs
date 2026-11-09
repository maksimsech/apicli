use apicli::{Failure, finish, open_for_change};
use apicli_policy::Rate;

use crate::{
    cli::{AllowCommand, LimitCommand},
    secret::unknown,
};

pub fn allow(command: AllowCommand) -> Result<u8, Failure> {
    let (store, mut vault) = open_for_change("dbcli")?;
    let (name, action, target, write) = match command {
        AllowCommand::Add {
            name,
            action,
            target,
        } => (name, action, target, true),
        AllowCommand::Rm {
            name,
            action,
            target,
        } => (name, action, target, false),
    };
    if !action.eq_ignore_ascii_case("write") || target.is_some() {
        return Err(Failure::Usage(format!(
            "Postgres connections take only `dbcli allow add {name} write`, limits on tables belong in Postgres GRANTs"
        )));
    }
    let connection = vault.connection_mut(&name).ok_or_else(|| unknown(&name))?;
    if !write && !connection.write {
        return Err(Failure::Usage(format!("{name} does not allow writes")));
    }
    connection.write = write;
    let message = if write {
        format!("Allowed writes on {name}, each statement now commits")
    } else {
        format!("Removed writes on {name}, it is read-only again")
    };
    finish(&store, &vault, &message)
}

pub fn limit(command: LimitCommand) -> Result<u8, Failure> {
    let (store, mut vault) = open_for_change("dbcli")?;
    let message = match command {
        LimitCommand::Set {
            name,
            rate,
            burst,
            daily,
        } => {
            let rate = Rate::parse(&rate).map_err(Failure::Usage)?;
            let connection = vault.connection_mut(&name).ok_or_else(|| unknown(&name))?;
            connection.rate = Some(rate);
            connection.burst = burst;
            connection.daily = daily;
            format!("Limited {name} to {}", connection.limits())
        }
        LimitCommand::Rm { name } => {
            let connection = vault.connection_mut(&name).ok_or_else(|| unknown(&name))?;
            if connection.rate.is_none() && connection.daily.is_none() {
                return Err(Failure::Usage(format!(
                    "{name} has no limits, run dbcli connections to list them"
                )));
            }
            connection.rate = None;
            connection.burst = None;
            connection.daily = None;
            format!("Removed the limits on {name}")
        }
    };
    finish(&store, &vault, &message)
}
