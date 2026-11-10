use apicli::{Failure, now, print_json};
use apicli_policy::{Connection, Engine};
use apicli_vault::Store;
use serde::Serialize;

use crate::{
    call::{self, find, key, redactor},
    postgres,
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
                limit_line(connection, remaining(&store, connection))
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
    let mut text = Vec::new();
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
                    text.push(format!("allowed: {name} ({})", connection.url));
                    text.extend(explanation.checks.iter().map(|line| format!("  {line}")));
                    text.push(format!(
                        "  limit: {}",
                        limit_line(connection, explanation.remaining)
                    ));
                    0
                }
                Err(failure) => {
                    let failure = call::scrub(failure, &redactor(&vault));
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
        println!("{}", text.join("\n"));
    }
    Ok(code)
}

fn mode(connection: &Connection) -> &'static str {
    match connection.url.engine {
        Engine::Postgres => postgres::mode(connection),
        _ if connection.allow.is_empty() => "read-only",
        _ => "rules",
    }
}

fn describe(connection: &Connection) -> &'static str {
    match connection.url.engine {
        Engine::Postgres => postgres::describe(connection),
        _ if connection.allow.is_empty() => "read-only, other commands need an allow rule",
        _ => "reads, plus what the allow rules below match",
    }
}

fn remaining(store: &Store, connection: &Connection) -> Option<u32> {
    store
        .read_buckets()
        .get(&key(&connection.name))
        .cloned()
        .unwrap_or_default()
        .remaining(&connection.limits(), now())
}

fn limit_line(connection: &Connection, remaining: Option<u32>) -> String {
    match remaining {
        Some(remaining) => format!("{}, {remaining} left now", connection.limits()),
        None => connection.limits().to_string(),
    }
}
