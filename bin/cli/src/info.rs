use apicli_core::{Grant, Rule, authorize};
use apicli_vault::Store;
use serde::Serialize;

use crate::{
    admin::add_hint,
    failure::Failure,
    request::{denied, now, parse_url},
    rules::load_policy,
};

#[derive(Serialize)]
struct Host {
    host: String,
    credential: String,
    header: String,
    methods: Vec<String>,
    allow: Vec<String>,
    deny: Vec<String>,
    limit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining: Option<u32>,
}

#[derive(Serialize)]
struct Explanation {
    allowed: bool,
    method: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

pub fn hosts(json: bool) -> Result<u8, Failure> {
    let store = Store::open()?;
    let vault = store.load()?;
    let policy = load_policy(&store, &vault)?;
    let buckets = store.read_buckets();
    let now = now();
    let hosts = vault
        .credentials
        .iter()
        .map(|credential| {
            let rules = policy.host(&credential.origin);
            Host {
                host: credential.origin.to_string(),
                credential: credential.name.clone(),
                header: credential.header.clone(),
                methods: rules.methods.clone(),
                allow: rules.allow.iter().map(describe).collect(),
                deny: rules.deny.iter().map(Rule::to_string).collect(),
                limit: rules.limits().to_string(),
                remaining: buckets
                    .get(&credential.origin.to_string())
                    .cloned()
                    .unwrap_or_default()
                    .remaining(&rules.limits(), now),
            }
        })
        .collect::<Vec<_>>();
    if json {
        print_json(&hosts)?;
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
            for rule in host.allow {
                println!("  allow: {rule}");
            }
            for rule in host.deny {
                println!("  deny: {rule}");
            }
            match host.remaining {
                Some(remaining) => println!("  limit: {}, {remaining} left now", host.limit),
                None => println!("  limit: {}", host.limit),
            }
        }
    }
    Ok(0)
}

pub fn explain(method: &str, url: &str, json: bool) -> Result<u8, Failure> {
    let store = Store::open()?;
    let vault = store.load()?;
    let policy = load_policy(&store, &vault)?;
    let url = parse_url(url)?;
    let method = method.to_ascii_uppercase();
    let mut explanation = Explanation {
        allowed: false,
        method: method.clone(),
        url: url.to_string(),
        credential: None,
        rule: None,
        reason: None,
    };
    let code = match authorize(&url, &method, None, &vault, &policy) {
        Ok((credential, grant)) => {
            explanation.allowed = true;
            explanation.credential = Some(format!("{} ({})", credential.name, credential.header));
            explanation.rule = Some(match grant {
                Grant::Default => format!(
                    "allowed: {}",
                    policy.host(&credential.origin).methods.join(", ")
                ),
                Grant::Rule(rule) => format!("allow: {}", describe(&rule)),
            });
            0
        }
        Err(denial) => {
            let failure = denied(denial, &url, &method, &vault, &policy);
            explanation.reason = Some(failure.to_string());
            failure.code()
        }
    };
    if json {
        print_json(&explanation)?;
    } else if explanation.allowed {
        println!("allowed: {method} {url}");
        println!(
            "  credential: {}",
            explanation.credential.unwrap_or_default()
        );
        println!("  {}", explanation.rule.unwrap_or_default());
    } else {
        println!("{}", explanation.reason.unwrap_or_default());
    }
    Ok(code)
}

fn describe(rule: &Rule) -> String {
    let mut limits = Vec::new();
    if let Some(max) = rule.max_body {
        limits.push(format!("body up to {max} bytes"));
    }
    if let Some(content_type) = &rule.content_type {
        limits.push(content_type.clone());
    }
    if rule.allow_body {
        limits.push("body allowed".into());
    }
    if limits.is_empty() {
        rule.to_string()
    } else {
        format!("{rule} ({})", limits.join(", "))
    }
}

fn print_json(value: &impl Serialize) -> Result<(), Failure> {
    let text = serde_json::to_string(value).map_err(|error| Failure::Write(error.to_string()))?;
    println!("{text}");
    Ok(())
}
