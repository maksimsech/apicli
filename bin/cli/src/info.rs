use std::collections::BTreeMap;

use apicli_core::{Grant, Origin, Rule, authorize};
use apicli_vault::Store;
use serde::Serialize;

use crate::{
    admin::add_hint,
    failure::Failure,
    request::{denied, now, parse_url},
};

#[derive(Serialize)]
struct Host {
    host: String,
    credentials: Vec<Secret>,
    methods: Vec<String>,
    allow: Vec<String>,
    deny: Vec<String>,
    limit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining: Option<u32>,
}

#[derive(Serialize)]
struct Secret {
    name: String,
    header: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    paths: Vec<String>,
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
    let buckets = store.read_buckets();
    let now = now();
    let mut origins = BTreeMap::<&Origin, Vec<Secret>>::new();
    for credential in &vault.credentials {
        origins.entry(&credential.origin).or_default().push(Secret {
            name: credential.name.clone(),
            header: credential.header.clone(),
            paths: credential.paths.clone(),
        });
    }
    let hosts = origins
        .into_iter()
        .map(|(origin, credentials)| {
            let rules = vault.policy.host(origin);
            Host {
                host: origin.to_string(),
                credentials,
                methods: rules.methods.clone(),
                allow: rules.allow.iter().map(describe).collect(),
                deny: rules.deny.iter().map(Rule::to_string).collect(),
                limit: rules.limits().to_string(),
                remaining: buckets
                    .get(&origin.to_string())
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
            for secret in host.credentials {
                if secret.paths.is_empty() {
                    println!("  credential: {} ({})", secret.name, secret.header);
                } else {
                    println!(
                        "  credential: {} ({}) on {}",
                        secret.name,
                        secret.header,
                        secret.paths.join(", ")
                    );
                }
            }
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
    let vault = Store::open()?.load()?;
    let url = parse_url(url)?;
    let mut explanation = Explanation {
        allowed: false,
        method: method.to_string(),
        url: url.to_string(),
        credential: None,
        rule: None,
        reason: None,
    };
    let code = match authorize(&url, method, None, &vault) {
        Ok((credential, grant)) => {
            explanation.allowed = true;
            explanation.credential = Some(format!("{} ({})", credential.name, credential.header));
            explanation.rule = Some(match grant {
                Grant::Default => format!(
                    "allowed: {}",
                    vault.policy.host(&credential.origin).methods.join(", ")
                ),
                Grant::Rule(rule) => format!("allow: {}", describe(&rule)),
            });
            0
        }
        Err(denial) => {
            let failure = denied(denial, &url, method, &vault);
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
