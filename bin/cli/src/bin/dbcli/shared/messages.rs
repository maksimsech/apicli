use apicli::Failure;
use apicli_policy::Connection;

use super::text::quote;

pub fn add_hint(name: &str) -> String {
    format!(
        "dbcli secret add {name} --url 'postgres://USER@HOST:5432/DATABASE' (or a redis://, mongodb://, cassandra:// or clickhouse:// URL)"
    )
}

pub fn rotate_hint(name: &str) -> String {
    format!("if the password changed, the user can run: dbcli secret rotate {name}")
}

pub fn write_hint(name: &str) -> String {
    format!("to allow writes, the user can run: dbcli allow add {name} write")
}

pub const COMMITS: &str = "read-write, each statement commits";

pub fn flag(connection: &Connection) -> &'static str {
    if connection.write {
        "read-write"
    } else {
        "read-only"
    }
}

pub fn writes(connection: &Connection, statements: usize, describe: &str) -> Vec<String> {
    let mut lines = vec![
        format!("statements: {statements}"),
        format!("mode: {describe}"),
    ];
    if !connection.write {
        lines.push(write_hint(&connection.name));
    }
    lines
}

pub fn read_only(connection: &Connection, detail: &str) -> Failure {
    Failure::Denied(format!(
        "denied: {} is read-only{detail}\n{}",
        connection.name,
        write_hint(&connection.name)
    ))
}

pub fn not_allowed(
    connection: &Connection,
    reads: &str,
    action: &str,
    on: Option<&str>,
    target: Option<&str>,
) -> Failure {
    let name = &connection.name;
    let on = on.map(|on| format!(" on {on}")).unwrap_or_default();
    let target = target
        .map(|target| format!(" {}", quote(target)))
        .unwrap_or_default();
    Failure::Denied(format!(
        "denied: {name} allows {reads} only, and no allow rule covers {action}{on}\nto allow it, the user can run: dbcli allow add {name} {}{target}",
        quote(action)
    ))
}

pub fn summary(rules: impl IntoIterator<Item = Option<String>>) -> String {
    let mut seen = Vec::new();
    for rule in rules {
        let rule = rule.unwrap_or_else(|| "read".into());
        if !seen.contains(&rule) {
            seen.push(rule);
        }
    }
    seen.join(", ")
}
