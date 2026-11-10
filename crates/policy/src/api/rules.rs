use std::{collections::BTreeMap, fmt};

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};

use super::Origin;
use crate::{Limits, Rate};

pub const READ_METHODS: [&str; 3] = ["GET", "HEAD", "OPTIONS"];

#[derive(Debug, PartialEq, Eq)]
pub enum Denial {
    Userinfo,
    EncodedSeparator,
    MethodOverride(String),
    Unconfigured(String),
    Uncovered,
    Rule(Rule),
    NotAllowed,
    Body(String),
}

pub const METHOD_OVERRIDES: [&str; 3] = [
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grant {
    Default,
    Rule(Rule),
}

pub struct Body<'a> {
    pub len: usize,
    pub content_type: Option<&'a str>,
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
    pub fn parse(text: &str) -> Result<Policy, String> {
        let policy: Policy = toml::from_str(text).map_err(|error| error.to_string())?;
        if policy.log_limit_mb == 0 {
            return Err("log_limit_mb must be at least 1".into());
        }
        for (origin, host) in &policy.hosts {
            for method in &host.methods {
                validate_method(method).map_err(|error| format!("{origin}: {error}"))?;
            }
            for rule in host.allow.iter().chain(&host.deny) {
                rule.validate()
                    .map_err(|error| format!("{origin}: {error}"))?;
            }
        }
        Ok(policy)
    }

    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string(self).map_err(|error| error.to_string())
    }

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
    pub fn check(&self, method: &str, path: &str, body: Option<Body>) -> Result<Grant, Denial> {
        if let Some(rule) = self.deny.iter().find(|rule| {
            (rule.method == method || rule.method == "GET" && method == "HEAD")
                && matches(&rule.path, path, true)
        }) {
            return Err(Denial::Rule(rule.clone()));
        }
        let read = self.methods.iter().any(|allowed| allowed == method);
        if read && body.is_none() {
            return Ok(Grant::Default);
        }
        let mut problem = None;
        for rule in self
            .allow
            .iter()
            .filter(|rule| rule.method == method && matches(&rule.path, path, false))
        {
            match rule.body_problem(read, body.as_ref()) {
                Some(reason) => problem = Some(reason),
                None => return Ok(Grant::Rule(rule.clone())),
            }
        }
        Err(problem.map_or(Denial::NotAllowed, Denial::Body))
    }

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

impl Rule {
    pub fn validate(&self) -> Result<(), String> {
        validate_method(&self.method)?;
        validate_path(&self.path).map_err(|error| format!("{} {error}", self.method))
    }

    fn body_problem(&self, read: bool, body: Option<&Body>) -> Option<String> {
        let body = body?;
        if read && !self.allow_body {
            return Some(format!("{self} does not allow a request body"));
        }
        if let Some(max) = self.max_body
            && body.len > max
        {
            return Some(format!(
                "the body is {} bytes, {self} allows {max}",
                body.len
            ));
        }
        if let Some(expected) = &self.content_type {
            let actual = body
                .content_type
                .and_then(|value| value.split(';').next())
                .map(str::trim);
            if !actual.is_some_and(|actual| actual.eq_ignore_ascii_case(expected)) {
                return Some(format!("{self} needs Content-Type {expected}"));
            }
        }
        None
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{} {}", self.method, self.path)
    }
}

fn validate_method(method: &str) -> Result<(), String> {
    if !method.is_empty() && method.bytes().all(|byte| byte.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(format!("{method} is not an uppercase HTTP method"))
    }
}

pub fn validate_path(path: &str) -> Result<(), String> {
    let Some(rest) = path.strip_prefix('/') else {
        return Err(format!("{path}: the path must start with /"));
    };
    let parts = rest.split('/').collect::<Vec<_>>();
    if parts.iter().take(parts.len() - 1).any(|part| *part == "**") {
        return Err(format!("{path}: ** must be the last segment"));
    }
    Ok(())
}

pub fn matches(pattern: &str, path: &str, loose: bool) -> bool {
    let pattern = segments(pattern, loose);
    let path = segments(path, loose);
    for (index, part) in pattern.iter().enumerate() {
        if part == "**" {
            return true;
        }
        let Some(segment) = path.get(index) else {
            return false;
        };
        let wildcard = part == "*" || part.starts_with('{') && part.ends_with('}');
        if wildcard && segment.is_empty() || !wildcard && part != segment {
            return false;
        }
    }
    pattern.len() == path.len()
}

fn segments(path: &str, loose: bool) -> Vec<String> {
    path.strip_prefix('/')
        .unwrap_or(path)
        .split('/')
        .map(|segment| percent_decode_str(segment).decode_utf8_lossy().into_owned())
        .map(|segment| {
            if loose {
                segment.to_lowercase()
            } else {
                segment
            }
        })
        .filter(|segment| !loose || !segment.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(method: &str, path: &str) -> Rule {
        Rule {
            method: method.into(),
            path: path.into(),
            max_body: None,
            content_type: None,
            allow_body: false,
        }
    }

    fn host(allow: Vec<Rule>, deny: Vec<Rule>) -> HostPolicy {
        HostPolicy {
            allow,
            deny,
            ..HostPolicy::default()
        }
    }

    fn json(len: usize) -> Option<Body<'static>> {
        Some(Body {
            len,
            content_type: Some("application/json; charset=utf-8"),
        })
    }

    #[test]
    fn single_segment_wildcards() {
        assert!(matches("/v1/orders/*/notes", "/v1/orders/123/notes", false));
        assert!(matches(
            "/v1/orders/{id}/notes",
            "/v1/orders/123/notes",
            false
        ));
        assert!(!matches(
            "/v1/orders/*/notes",
            "/v1/orders/1/2/notes",
            false
        ));
        assert!(!matches("/v1/orders/*/notes", "/v1/orders//notes", false));
    }

    #[test]
    fn trailing_wildcard() {
        assert!(matches("/v1/exports/**", "/v1/exports", false));
        assert!(matches(
            "/v1/exports/**",
            "/v1/exports/2026/11/file.csv",
            false
        ));
        assert!(!matches("/v1/exports/**", "/v1/export", false));
    }

    #[test]
    fn allow_rules_match_strictly() {
        assert!(!matches(
            "/v1/orders/*/notes",
            "/v1/orders/123/notes/",
            false
        ));
        assert!(!matches(
            "/v1/orders/*/notes",
            "/V1/orders/123/notes",
            false
        ));
        assert!(!matches(
            "/v1/orders/*/notes",
            "/v1//orders/123/notes",
            false
        ));
    }

    #[test]
    fn deny_rules_match_loosely() {
        assert!(matches("/v1/exports/**", "/V1/Exports/all", true));
        assert!(matches("/v1/exports/**", "/v1//exports//all", true));
        assert!(matches("/v1/exports/**", "/v1/%65xports/all", true));
        assert!(matches("/v1/admin", "/v1/admin/", true));
    }

    #[test]
    fn deny_wins_over_default_methods() {
        let policy = host(vec![], vec![rule("GET", "/v1/exports/**")]);

        assert_eq!(policy.check("GET", "/v1/users", None), Ok(Grant::Default));
        assert_eq!(
            policy.check("GET", "/V1/exports/all", None),
            Err(Denial::Rule(rule("GET", "/v1/exports/**")))
        );
    }

    #[test]
    fn deny_get_also_denies_head() {
        let policy = host(vec![], vec![rule("GET", "/v1/exports/**")]);

        assert_eq!(
            policy.check("HEAD", "/v1/exports/all", None),
            Err(Denial::Rule(rule("GET", "/v1/exports/**")))
        );
        assert_eq!(policy.check("HEAD", "/v1/users", None), Ok(Grant::Default));
    }

    #[test]
    fn writes_need_an_allow_rule() {
        let policy = host(vec![rule("POST", "/v1/orders/*/notes")], vec![]);

        assert_eq!(
            policy.check("POST", "/v1/orders/1/notes", json(10)),
            Ok(Grant::Rule(rule("POST", "/v1/orders/*/notes")))
        );
        assert_eq!(
            policy.check("POST", "/v1/orders/1/refund", json(10)),
            Err(Denial::NotAllowed)
        );
        assert_eq!(
            policy.check("DELETE", "/v1/orders/1/notes", None),
            Err(Denial::NotAllowed)
        );
    }

    #[test]
    fn get_with_body_needs_allow_body() {
        let mut search = rule("GET", "/v1/search");
        let policy = host(vec![search.clone()], vec![]);

        assert!(matches!(
            policy.check("GET", "/v1/search", json(10)),
            Err(Denial::Body(_))
        ));

        search.allow_body = true;
        let policy = host(vec![search.clone()], vec![]);

        assert_eq!(
            policy.check("GET", "/v1/search", json(10)),
            Ok(Grant::Rule(search))
        );
    }

    #[test]
    fn body_limits_apply() {
        let mut notes = rule("POST", "/v1/notes");
        notes.max_body = Some(16);
        notes.content_type = Some("application/json".into());
        let policy = host(vec![notes], vec![]);

        assert!(policy.check("POST", "/v1/notes", json(16)).is_ok());
        assert!(matches!(
            policy.check("POST", "/v1/notes", json(17)),
            Err(Denial::Body(_))
        ));
        let form = Some(Body {
            len: 4,
            content_type: Some("application/x-www-form-urlencoded"),
        });
        assert!(matches!(
            policy.check("POST", "/v1/notes", form),
            Err(Denial::Body(_))
        ));
    }

    #[test]
    fn parse_rejects_bad_rules_and_unknown_fields() {
        assert!(Policy::parse("[hosts.\"https://api.example.com\"]\nallow = [{ method = \"post\", path = \"/x\" }]").is_err());
        assert!(
            Policy::parse(
                "[hosts.\"https://api.example.com\"]\nallow = [{ method = \"POST\", path = \"x\" }]"
            )
            .is_err()
        );
        assert!(Policy::parse("[hosts.\"https://api.example.com\"]\nallow = [{ method = \"POST\", path = \"/**/x\" }]").is_err());
        assert!(Policy::parse("[hosts.\"https://api.example.com\"]\nmethod = [\"GET\"]").is_err());
    }

    #[test]
    fn round_trips_through_toml() {
        let mut policy = Policy::default();
        policy.hosts.insert(
            Origin::parse("api.example.com").unwrap(),
            host(
                vec![rule("POST", "/v1/notes")],
                vec![rule("GET", "/v1/exports/**")],
            ),
        );

        let parsed = Policy::parse(&policy.to_toml().unwrap()).unwrap();

        assert_eq!(parsed.hosts.len(), 1);
        assert_eq!(
            parsed.host(&Origin::parse("api.example.com").unwrap()).deny,
            vec![rule("GET", "/v1/exports/**")]
        );
    }
}
