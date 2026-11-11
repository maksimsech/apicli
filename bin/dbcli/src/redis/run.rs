use std::io::{Read, stdin};

use fieldkit_common::Failure;
use fieldkit_policy::Connection;

use super::{
    args::{RedisArgs, parse},
    client::Client,
    reply::{Mode, Reply, format, lossy, repr},
    rules::find,
};
use crate::shared::{ConnectionUrl, Context, not_allowed, quote};

const READS: [&str; 2] = ["PING", "INFO"];

struct Verdict {
    action: String,
    keys: Vec<Vec<u8>>,
    rule: Option<String>,
}

pub async fn run(
    connection: &Connection,
    url: &ConnectionUrl,
    args: &[String],
    context: &mut Context<'_>,
) -> Result<u8, Failure> {
    let args = parse(args)?;
    context.statements(&[statement(&args)]);
    let mut words = words(&args);
    if args.stdin {
        let mut input = Vec::new();
        stdin()
            .read_to_end(&mut input)
            .map_err(|error| Failure::Read(format!("stdin: {error}")))?;
        words.push(input);
    }
    context.take(connection, args.common.wait)?;
    let mut client = Client::open(connection, url, db(url, &args)).await?;
    let result = if args.scan {
        scan(&mut client, &args, context).await
    } else {
        execute(&mut client, connection, &args, &words, context).await
    };
    client.close().await;
    result
}

pub async fn explain(
    connection: &Connection,
    url: &ConnectionUrl,
    args: &[String],
) -> Result<Vec<String>, Failure> {
    let args = parse(args)?;
    if args.scan {
        return Ok(vec!["command: SCAN, a read command".into()]);
    }
    let mut words = words(&args);
    if args.stdin {
        words.push(b"STDIN".to_vec());
    }
    let mut client = Client::open(connection, url, db(url, &args)).await?;
    let verdict = classify(&mut client, connection, &words).await;
    client.close().await;
    let verdict = verdict?;
    let mut lines = vec![format!("command: {}", verdict.action)];
    if !verdict.keys.is_empty() {
        lines.push(format!("keys: {}", shown(&verdict.keys)));
    }
    lines.push(match verdict.rule {
        Some(rule) => format!("allowed by: {rule}"),
        None => "a read command, so it runs".into(),
    });
    Ok(lines)
}

async fn execute(
    client: &mut Client,
    connection: &Connection,
    args: &RedisArgs,
    words: &[Vec<u8>],
    context: &mut Context<'_>,
) -> Result<u8, Failure> {
    let verdict = classify(client, connection, words).await?;
    context.entry.rule = Some(verdict.rule.unwrap_or_else(|| "read".into()));
    if args.json {
        client.call(&[b"HELLO", b"3"]).await?;
    }
    let reply = client.call(&refs(words)).await?;
    if let Reply::Error(error) = &reply {
        let text = lossy(error);
        context.entry.error = Some(context.clean(&text));
        if args.errors {
            return Err(Failure::Database(text));
        }
    }
    context.print(&format(
        &reply,
        mode(args, context.terminal),
        verbatim(words),
    ))?;
    Ok(0)
}

async fn classify(
    client: &mut Client,
    connection: &Connection,
    words: &[Vec<u8>],
) -> Result<Verdict, Failure> {
    let name = String::from_utf8_lossy(&words[0]).to_ascii_uppercase();
    if name.contains('|') {
        return Err(Failure::Usage(format!("{name} is not a Redis command")));
    }
    let mut action = name.clone();
    let mut info = lookup(client, &name).await?;
    let container = info.as_ref().is_some_and(|entry| {
        entry
            .items()
            .get(9)
            .is_some_and(|subs| !subs.items().is_empty())
    });
    if container && let Some(sub) = words.get(1) {
        action = format!("{name}|{}", lossy(sub).to_ascii_uppercase());
        info = lookup(client, &action).await?;
    }
    let read = READS.contains(&action.as_str())
        || info.as_ref().is_some_and(|entry| {
            let flags = texts(entry.items().get(2));
            let categories = texts(entry.items().get(6));
            flags.contains(&&b"readonly"[..])
                && !categories
                    .iter()
                    .any(|category| matches!(*category, b"@dangerous" | b"@scripting"))
        });
    if read {
        return Ok(Verdict {
            action,
            keys: Vec::new(),
            rule: None,
        });
    }
    let mut keys = Vec::new();
    if info.is_some() {
        let mut call = vec![&b"COMMAND"[..], b"GETKEYS"];
        call.extend(refs(words));
        match client.call(&call).await? {
            Reply::Array(items) => {
                keys = items
                    .iter()
                    .filter_map(|item| item.text().map(<[u8]>::to_vec))
                    .collect();
            }
            Reply::Error(error) if !error.ends_with(b"no key arguments") => {
                return Err(Failure::Database(lossy(&error)));
            }
            _ => {}
        }
    }
    match find(&connection.allow, &action, &refs(&keys)) {
        Some(rule) => Ok(Verdict {
            rule: Some(rule.to_string()),
            action,
            keys,
        }),
        None if info.is_none() => Err(Failure::Denied(format!(
            "denied: the server doesn't list {action} in COMMAND INFO, check the name\nif it is right, the user can allow it with: dbcli allow add {} {}",
            connection.name,
            quote(&action)
        ))),
        None => Err(denied(connection, &action, &keys)),
    }
}

async fn lookup(client: &mut Client, name: &str) -> Result<Option<Reply>, Failure> {
    match client.call(&[b"COMMAND", b"INFO", name.as_bytes()]).await? {
        Reply::Error(error) => Err(Failure::Database(format!(
            "dbcli needs COMMAND INFO and COMMAND GETKEYS to check commands: {}",
            lossy(&error)
        ))),
        reply => Ok(reply
            .items()
            .first()
            .filter(|entry| **entry != Reply::Nil)
            .cloned()),
    }
}

async fn scan(
    client: &mut Client,
    args: &RedisArgs,
    context: &mut Context<'_>,
) -> Result<u8, Failure> {
    context.entry.rule = Some("read".into());
    let quoted = mode(args, context.terminal) == Mode::Standard;
    let count = args.count.to_string();
    let mut cursor = b"0".to_vec();
    loop {
        let mut call = vec![&b"SCAN"[..], &cursor];
        if let Some(pattern) = &args.pattern {
            call.extend([&b"MATCH"[..], pattern.as_bytes()]);
        }
        call.extend([&b"COUNT"[..], count.as_bytes()]);
        let reply = client.call(&call).await?;
        if let Reply::Error(error) = &reply {
            return Err(Failure::Database(lossy(error)));
        }
        let next = reply
            .items()
            .first()
            .and_then(Reply::text)
            .ok_or_else(|| Failure::Network("bad SCAN reply from the server".into()))?
            .to_vec();
        let mut out = Vec::new();
        for key in reply.items().get(1).map(Reply::items).unwrap_or_default() {
            let key = key.text().unwrap_or_default();
            if quoted {
                out.extend_from_slice(&repr(key));
            } else {
                out.extend_from_slice(key);
            }
            out.push(b'\n');
        }
        context.print(&out)?;
        if next == b"0" {
            return Ok(0);
        }
        cursor = next;
    }
}

fn denied(connection: &Connection, action: &str, keys: &[Vec<u8>]) -> Failure {
    let (on, target) = if keys.is_empty() {
        (None, None)
    } else {
        (Some(shown(keys)), Some(pattern(keys)))
    };
    not_allowed(
        connection,
        "read commands",
        action,
        on.as_deref(),
        target.as_deref(),
    )
}

fn pattern(keys: &[Vec<u8>]) -> String {
    let escape = |bytes: &[u8]| {
        lossy(bytes)
            .chars()
            .flat_map(|character| {
                let escaped = matches!(character, '*' | '?' | '[' | ']' | '\\');
                escaped.then_some('\\').into_iter().chain([character])
            })
            .collect::<String>()
    };
    let [first, rest @ ..] = keys else {
        return "*".into();
    };
    if rest.iter().all(|key| key == first) {
        return escape(first);
    }
    let common = rest.iter().fold(first.len(), |length, key| {
        first
            .iter()
            .zip(key)
            .take(length)
            .take_while(|(left, right)| left == right)
            .count()
    });
    format!("{}*", escape(&first[..common]))
}

fn shown(keys: &[Vec<u8>]) -> String {
    keys.iter()
        .map(|key| lossy(key))
        .collect::<Vec<_>>()
        .join(", ")
}

fn words(args: &RedisArgs) -> Vec<Vec<u8>> {
    args.command
        .iter()
        .map(|word| word.as_bytes().to_vec())
        .collect()
}

fn refs(words: &[Vec<u8>]) -> Vec<&[u8]> {
    words.iter().map(Vec::as_slice).collect()
}

fn texts(reply: Option<&Reply>) -> Vec<&[u8]> {
    reply
        .map(Reply::items)
        .unwrap_or_default()
        .iter()
        .filter_map(Reply::text)
        .collect()
}

fn statement(args: &RedisArgs) -> String {
    if args.scan {
        match &args.pattern {
            Some(pattern) => format!("--scan --pattern {pattern}"),
            None => "--scan".into(),
        }
    } else {
        args.command.join(" ")
    }
}

fn db(url: &ConnectionUrl, args: &RedisArgs) -> u32 {
    args.db.unwrap_or_else(|| url.database.parse().unwrap_or(0))
}

fn mode(args: &RedisArgs, terminal: bool) -> Mode {
    if args.json {
        Mode::Json
    } else if args.csv {
        Mode::Csv
    } else if args.raw {
        Mode::Raw
    } else if args.no_raw || terminal {
        Mode::Standard
    } else {
        Mode::Raw
    }
}

fn verbatim(words: &[Vec<u8>]) -> bool {
    let word = |index: usize| {
        words
            .get(index)
            .map(|word| lossy(word).to_ascii_lowercase())
            .unwrap_or_default()
    };
    let (command, sub, count) = (word(0), word(1), words.len());
    match command.as_str() {
        "info" | "lolwut" => true,
        "debug" => {
            count >= 2 && matches!(sub.as_str(), "htstats" | "htstats-key" | "client-eviction")
        }
        "memory" => count >= 2 && matches!(sub.as_str(), "malloc-stats" | "doctor"),
        "cluster" => count == 2 && matches!(sub.as_str(), "nodes" | "info"),
        "client" => count >= 2 && matches!(sub.as_str(), "list" | "info"),
        "latency" => (count == 3 && sub == "graph") || (count == 2 && sub == "doctor"),
        "proxy" => count >= 2 && sub == "info",
        _ => false,
    }
}
