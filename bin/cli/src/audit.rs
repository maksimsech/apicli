use std::io;

use apicli_vault::Store;
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::failure::Failure;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Entry {
    pub time: String,
    pub outcome: String,
    pub method: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub ms: u64,
}

impl Entry {
    pub fn start() -> Entry {
        Entry {
            time: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            ..Entry::default()
        }
    }

    fn summary(&self) -> String {
        let mut parts = vec![
            self.time.clone(),
            self.outcome.clone(),
            self.method.clone(),
            self.url.clone(),
        ];
        if let Some(status) = self.status {
            parts.push(status.to_string());
        }
        if let Some(bytes) = self.bytes {
            parts.push(format!("{bytes} B"));
        }
        if let Some(rule) = &self.rule {
            parts.push(rule.clone());
        }
        if let Some(error) = &self.error {
            parts.push(error.clone());
        }
        parts.push(format!("{} ms", self.ms));
        parts.join("  ")
    }
}

pub fn record(store: &Store, entry: &Entry, limit_mb: u32) {
    let result = serde_json::to_string(entry)
        .map_err(io::Error::other)
        .and_then(|line| store.append_log(&line, u64::from(limit_mb) * 1_000_000));
    if let Err(error) = result {
        eprintln!("apicli: warning: could not write the audit log: {error}");
    }
}

pub fn log(tail: usize, json: bool) -> Result<u8, Failure> {
    let store = Store::open()?;
    let text = store
        .read_log()
        .map_err(|error| Failure::Read(format!("the audit log: {error}")))?;
    let lines = text.lines().collect::<Vec<_>>();
    for line in &lines[lines.len().saturating_sub(tail)..] {
        match serde_json::from_str::<Entry>(line) {
            Ok(entry) if !json => println!("{}", entry.summary()),
            _ => println!("{line}"),
        }
    }
    Ok(0)
}
