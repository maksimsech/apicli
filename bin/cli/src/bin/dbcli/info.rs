use apicli::{Failure, now, print_json};
use apicli_policy::Connection;
use apicli_vault::Store;
use serde::Serialize;

use crate::{
    call::{find, key, mode, steps},
    cli::RunArgs,
    secret::add_hint,
};

#[derive(Serialize)]
struct Listed {
    name: String,
    url: String,
    mode: &'static str,
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
    mode: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    statements: Option<usize>,
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
    let listed = vault
        .connections
        .iter()
        .map(|connection| Listed {
            name: connection.name.clone(),
            url: connection.url.to_string(),
            mode: mode(connection),
            limit: connection.limits().to_string(),
            remaining: remaining(&store, connection),
        })
        .collect::<Vec<_>>();
    if json {
        print_json(&listed)?;
    } else if listed.is_empty() {
        println!(
            "No connections are configured. The user can add one with: {}",
            add_hint("NAME")
        );
    } else {
        for connection in listed {
            println!("{}", connection.name);
            println!("  url: {}", connection.url);
            println!("  mode: {}", describe(connection.mode));
            println!(
                "  limit: {}",
                limit_line(&connection.limit, connection.remaining)
            );
        }
    }
    Ok(0)
}

pub fn explain(args: &RunArgs, json: bool) -> Result<u8, Failure> {
    let store = Store::open()?;
    let vault = store.load()?;
    let name = args.name.clone().unwrap_or_default();
    let mut explanation = Explanation {
        allowed: false,
        connection: name.clone(),
        url: None,
        mode: None,
        statements: None,
        limit: None,
        remaining: None,
        reason: None,
    };
    let checked = args
        .check()
        .and_then(|_| steps(args))
        .and_then(|steps| find(&vault, &name).map(|connection| (connection, steps.len())));
    let code = match checked {
        Ok((connection, count)) => {
            explanation.allowed = true;
            explanation.url = Some(connection.url.to_string());
            explanation.mode = Some(mode(connection));
            explanation.statements = Some(count);
            explanation.limit = Some(connection.limits().to_string());
            explanation.remaining = remaining(&store, connection);
            0
        }
        Err(failure) => {
            explanation.reason = Some(failure.to_string());
            failure.code()
        }
    };
    if json {
        print_json(&explanation)?;
    } else if explanation.allowed {
        println!("allowed: {name} ({})", explanation.url.unwrap_or_default());
        println!(
            "  statements: {}",
            explanation.statements.unwrap_or_default()
        );
        let mode = explanation.mode.unwrap_or_default();
        println!("  mode: {}", describe(mode));
        if mode == "read-only" {
            println!("  to allow writes, the user can run: dbcli allow add {name} write");
        }
        println!(
            "  limit: {}",
            limit_line(
                &explanation.limit.unwrap_or_default(),
                explanation.remaining
            )
        );
    } else {
        println!("{}", explanation.reason.unwrap_or_default());
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

fn describe(mode: &str) -> &'static str {
    if mode == "read-write" {
        "read-write, each statement commits"
    } else {
        "read-only, each statement runs in a read-only transaction"
    }
}

fn limit_line(limit: &str, remaining: Option<u32>) -> String {
    match remaining {
        Some(remaining) => format!("{limit}, {remaining} left now"),
        None => limit.to_string(),
    }
}
