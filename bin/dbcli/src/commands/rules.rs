use fieldkit_common::{Failure, Rate, finish, open_for_change};

use super::secret::unknown;
use crate::{
    call::Engine,
    cli::{AllowCommand, LimitCommand},
    shared::Config,
};

pub fn allow(command: AllowCommand) -> Result<u8, Failure> {
    let (store, mut vault) = open_for_change("dbcli")?;
    let mut config = Config::load(&vault)?;
    let (name, action, target, add) = match command {
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
    let connection = config.connection_mut(&name).ok_or_else(|| unknown(&name))?;
    let engine = Engine::of(&connection.url).map_err(Failure::Integrity)?;
    let rule = engine.rule(&name, &action, target.as_deref());
    let message = if engine.write_flag() {
        if !action.eq_ignore_ascii_case("write") || target.is_some() {
            return Err(Failure::Usage(rule.err().unwrap_or_default()));
        }
        if !add && !connection.write {
            return Err(Failure::Usage(format!("{name} does not allow writes")));
        }
        connection.write = add;
        if add {
            format!("Allowed writes on {name}, each statement now commits")
        } else {
            format!("Removed writes on {name}, it is read-only again")
        }
    } else {
        let rule = rule.map_err(Failure::Usage)?;
        let found = connection.allow.iter().position(|existing| {
            existing.action.eq_ignore_ascii_case(&rule.action) && existing.target == rule.target
        });
        match (add, found) {
            (true, Some(_)) => {
                return Err(Failure::Usage(format!("{name} already allows {rule}")));
            }
            (true, None) => {
                let message = format!("Allowed {rule} on {name}");
                connection.allow.push(rule);
                message
            }
            (false, Some(index)) => {
                connection.allow.remove(index);
                format!("Removed {rule} on {name}")
            }
            (false, None) => {
                return Err(Failure::Usage(format!(
                    "{name} has no rule {rule}, run dbcli connections to list them"
                )));
            }
        }
    };
    config.save(&mut vault)?;
    finish(&store, &vault, &message)
}

pub fn limit(command: LimitCommand) -> Result<u8, Failure> {
    let (store, mut vault) = open_for_change("dbcli")?;
    let mut config = Config::load(&vault)?;
    let message = match command {
        LimitCommand::Set {
            name,
            rate,
            burst,
            daily,
        } => {
            let rate = Rate::parse(&rate).map_err(Failure::Usage)?;
            let connection = config.connection_mut(&name).ok_or_else(|| unknown(&name))?;
            connection.rate = Some(rate);
            connection.burst = burst;
            connection.daily = daily;
            format!("Limited {name} to {}", connection.limits())
        }
        LimitCommand::Rm { name } => {
            let connection = config.connection_mut(&name).ok_or_else(|| unknown(&name))?;
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
    config.save(&mut vault)?;
    finish(&store, &vault, &message)
}
