use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use super::Origin;
use crate::{Limits, Rate};

const READ_METHODS: [&str; 3] = ["GET", "HEAD", "OPTIONS"];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub log_limit_mb: u32,
    pub hosts: BTreeMap<Origin, HostPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPolicy {
    #[serde(default = "read_methods")]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<Rate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_body: bool,
}

fn read_methods() -> Vec<String> {
    READ_METHODS
        .iter()
        .map(|method| method.to_string())
        .collect()
}

fn is_false(value: &bool) -> bool {
    !value
}

impl Policy {
    pub fn host(&self, origin: &Origin) -> HostPolicy {
        self.hosts.get(origin).cloned().unwrap_or_default()
    }
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            log_limit_mb: 10,
            hosts: BTreeMap::new(),
        }
    }
}

impl Default for HostPolicy {
    fn default() -> Self {
        HostPolicy {
            methods: read_methods(),
            rate: None,
            burst: None,
            daily: None,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

impl HostPolicy {
    pub fn limits(&self) -> Limits {
        Limits {
            rate: self.rate,
            burst: self.burst,
            daily: self.daily,
        }
    }

    pub fn summary(&self) -> String {
        let mut parts = vec![self.methods.join(", ")];
        parts.extend(self.allow.iter().map(|rule| rule.to_string()));
        parts.join("; ")
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{} {}", self.method, self.path)
    }
}
