use apicli::{Failure, now, print_json};
use apicli_policy::Connection;
use apicli_vault::Store;
use serde::Serialize;

use crate::{
    call::{self, describe, find, key, mode, redactor, scrub},
    secret::add_hint,
};

#[derive(Serialize)]
struct Listed {
    name: String,
    url: String,
    engine: &'static str,
    mode: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allow: Vec<String>,
    limit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining: Option<u32>,
}

#[derive(Serialize)]
struct Explanation {
    allowed: bool,
    connection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    engine: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    checks: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

pub fn connections(json: bool) -> Result<u8, Failure> {
    let store = Store::open()?;
    let vault = store.load()?;
    if json {
        let listed = vault
            .connections
            .iter()
            .map(|connection| Listed {
                name: connection.name.clone(),
                url: connection.url.to_string(),
                engine: connection.url.engine.name(),
                mode: mode(connection),
                allow: connection.allow.iter().map(ToString::to_string).collect(),
                limit: connection.limits().to_string(),
                remaining: remaining(&store, connection),
            })
            .collect::<Vec<_>>();
        print_json(&listed)?;
    } else if vault.connections.is_empty() {
        println!(
            "No connections are configured. The user can add one with: {}",
            add_hint("NAME")
        );
    } else {
        for connection in &vault.connections {
            println!("{}", connection.name);
            println!("  url: {}", connection.url);
            println!("  engine: {}", connection.url.engine.name());
            println!("  mode: {}", describe(connection));
            for rule in &connection.allow {
                println!("  allow: {rule}");
            }
            println!(
                "  limit: {}",
                limit_line(
                    connection.limits().to_string(),
                    remaining(&store, connection)
                )
            );
        }
    }
    Ok(0)
}

pub async fn explain(name: &str, args: &[String], json: bool) -> Result<u8, Failure> {
    let store = Store::open()?;
    let vault = store.load()?;
    let mut explanation = Explanation {
        allowed: false,
        connection: name.to_string(),
        url: None,
        engine: None,
        checks: Vec::new(),
        limit: None,
        remaining: None,
        reason: None,
    };
    let code = match find(&vault, name) {
        Ok(connection) => {
            explanation.url = Some(connection.url.to_string());
            explanation.engine = Some(connection.url.engine.name());
            match call::explain(connection, args).await {
                Ok(checks) => {
                    explanation.allowed = true;
                    explanation.checks = checks;
                    explanation.limit = Some(connection.limits().to_string());
                    explanation.remaining = remaining(&store, connection);
                    0
                }
                Err(failure) => {
                    let failure = scrub(failure, &redactor(&vault));
                    explanation.reason = Some(failure.to_string());
                    failure.code()
                }
            }
        }
        Err(failure) => {
            explanation.reason = Some(failure.to_string());
            failure.code()
        }
    };
    if json {
        print_json(&explanation)?;
    } else if let Some(reason) = &explanation.reason {
        println!("{reason}");
    } else {
        println!("allowed: {name} ({})", explanation.url.unwrap_or_default());
        for check in &explanation.checks {
            println!("  {check}");
        }
        println!(
            "  limit: {}",
            limit_line(explanation.limit.unwrap_or_default(), explanation.remaining)
        );
    }
    Ok(code)
}

fn remaining(store: &Store, connection: &Connection) -> Option<u32> {
    store
        .read_buckets()
        .get(&key(&connection.name))
        .cloned()
        .unwrap_or_default()
        .remaining(&connection.limits(), now())
}

fn limit_line(limit: String, remaining: Option<u32>) -> String {
    match remaining {
        Some(remaining) => format!("{limit}, {remaining} left now"),
        None => limit,
    }
}
