use percent_encoding::percent_decode_str;
use url::Url;

use crate::{
    config::{Config, Credential, HostPolicy, Policy, Rule},
    origin::Origin,
};

pub const METHOD_OVERRIDES: [&str; 3] = [
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grant {
    Default,
    Rule(Rule),
}

pub struct Body<'a> {
    pub len: usize,
    pub content_type: Option<&'a str>,
}

pub fn authorize<'a>(
    url: &Url,
    method: &str,
    body: Option<Body>,
    config: &'a Config,
) -> Result<(&'a Credential, Grant), Denial> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Denial::Userinfo);
    }
    let path = url.path().to_ascii_lowercase();
    if path.contains("%2f") || path.contains("%5c") {
        return Err(Denial::EncodedSeparator);
    }
    if url
        .query_pairs()
        .any(|(name, _)| name.eq_ignore_ascii_case("_method"))
    {
        return Err(Denial::MethodOverride("_method".into()));
    }
    let origin = Origin::of(url).ok_or_else(|| Denial::Unconfigured(url.to_string()))?;
    if !config
        .credentials
        .iter()
        .any(|credential| credential.origin == origin)
    {
        return Err(Denial::Unconfigured(origin.to_string()));
    }
    let grant = check(&config.policy.host(&origin), method, url.path(), body)?;
    let credential = credential(config, &origin, url.path()).ok_or(Denial::Uncovered)?;
    Ok((credential, grant))
}

fn credential<'a>(config: &'a Config, origin: &Origin, path: &str) -> Option<&'a Credential> {
    let mut hosted = config
        .credentials
        .iter()
        .filter(|credential| &credential.origin == origin);
    hosted
        .clone()
        .find(|credential| {
            credential
                .paths
                .iter()
                .any(|pattern| matches(pattern, path, false))
        })
        .or_else(|| hosted.find(|credential| credential.paths.is_empty()))
}

fn check(host: &HostPolicy, method: &str, path: &str, body: Option<Body>) -> Result<Grant, Denial> {
    if let Some(rule) = host.deny.iter().find(|rule| {
        (rule.method == method || rule.method == "GET" && method == "HEAD")
            && matches(&rule.path, path, true)
    }) {
        return Err(Denial::Rule(rule.clone()));
    }
    let read = host.methods.iter().any(|allowed| allowed == method);
    if read && body.is_none() {
        return Ok(Grant::Default);
    }
    let mut problem = None;
    for rule in host
        .allow
        .iter()
        .filter(|rule| rule.method == method && matches(&rule.path, path, false))
    {
        match body_problem(rule, read, body.as_ref()) {
            Some(reason) => problem = Some(reason),
            None => return Ok(Grant::Rule(rule.clone())),
        }
    }
    Err(problem.map_or(Denial::NotAllowed, Denial::Body))
}

fn body_problem(rule: &Rule, read: bool, body: Option<&Body>) -> Option<String> {
    let body = body?;
    if read && !rule.allow_body {
        return Some(format!("{rule} does not allow a request body"));
    }
    if let Some(max) = rule.max_body
        && body.len > max
    {
        return Some(format!(
            "the body is {} bytes, {rule} allows {max}",
            body.len
        ));
    }
    if let Some(expected) = &rule.content_type {
        let actual = body
            .content_type
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if !actual.is_some_and(|actual| actual.eq_ignore_ascii_case(expected)) {
            return Some(format!("{rule} needs Content-Type {expected}"));
        }
    }
    None
}

fn matches(pattern: &str, path: &str, loose: bool) -> bool {
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

pub fn parse_policy(text: &str) -> Result<Policy, String> {
    let policy: Policy = toml::from_str(text).map_err(|error| error.to_string())?;
    for (origin, host) in &policy.hosts {
        for method in &host.methods {
            validate_method(method).map_err(|error| format!("{origin}: {error}"))?;
        }
        for rule in host.allow.iter().chain(&host.deny) {
            validate_rule(rule).map_err(|error| format!("{origin}: {error}"))?;
        }
    }
    Ok(policy)
}

pub fn policy_toml(policy: &Policy) -> Result<String, String> {
    toml::to_string(policy).map_err(|error| error.to_string())
}

pub fn validate_rule(rule: &Rule) -> Result<(), String> {
    validate_method(&rule.method)?;
    validate_path(&rule.path).map_err(|error| format!("{} {error}", rule.method))
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

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

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

    fn credential(name: &str, paths: &[&str]) -> Credential {
        Credential {
            name: name.into(),
            origin: Origin::parse("api.example.com").unwrap(),
            paths: paths.iter().map(|path| path.to_string()).collect(),
            header: "X-API-Key".into(),
            template: "{secret}".into(),
            secret: SecretString::from("key-1234567890"),
        }
    }

    fn config() -> Config {
        Config {
            credentials: vec![credential("example", &[])],
            ..Config::default()
        }
    }

    fn authorized(url: &str, method: &str) -> Result<String, Denial> {
        let config = config();
        authorize(&Url::parse(url).unwrap(), method, None, &config)
            .map(|(credential, _)| credential.name.clone())
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

        assert_eq!(check(&policy, "GET", "/v1/users", None), Ok(Grant::Default));
        assert_eq!(
            check(&policy, "GET", "/V1/exports/all", None),
            Err(Denial::Rule(rule("GET", "/v1/exports/**")))
        );
    }

    #[test]
    fn deny_get_also_denies_head() {
        let policy = host(vec![], vec![rule("GET", "/v1/exports/**")]);

        assert_eq!(
            check(&policy, "HEAD", "/v1/exports/all", None),
            Err(Denial::Rule(rule("GET", "/v1/exports/**")))
        );
        assert_eq!(
            check(&policy, "HEAD", "/v1/users", None),
            Ok(Grant::Default)
        );
    }

    #[test]
    fn writes_need_an_allow_rule() {
        let policy = host(vec![rule("POST", "/v1/orders/*/notes")], vec![]);

        assert_eq!(
            check(&policy, "POST", "/v1/orders/1/notes", json(10)),
            Ok(Grant::Rule(rule("POST", "/v1/orders/*/notes")))
        );
        assert_eq!(
            check(&policy, "POST", "/v1/orders/1/refund", json(10)),
            Err(Denial::NotAllowed)
        );
        assert_eq!(
            check(&policy, "DELETE", "/v1/orders/1/notes", None),
            Err(Denial::NotAllowed)
        );
    }

    #[test]
    fn get_with_body_needs_allow_body() {
        let mut search = rule("GET", "/v1/search");
        let policy = host(vec![search.clone()], vec![]);

        assert!(matches!(
            check(&policy, "GET", "/v1/search", json(10)),
            Err(Denial::Body(_))
        ));

        search.allow_body = true;
        let policy = host(vec![search.clone()], vec![]);

        assert_eq!(
            check(&policy, "GET", "/v1/search", json(10)),
            Ok(Grant::Rule(search))
        );
    }

    #[test]
    fn body_limits_apply() {
        let mut notes = rule("POST", "/v1/notes");
        notes.max_body = Some(16);
        notes.content_type = Some("application/json".into());
        let policy = host(vec![notes], vec![]);

        assert!(check(&policy, "POST", "/v1/notes", json(16)).is_ok());
        assert!(matches!(
            check(&policy, "POST", "/v1/notes", json(17)),
            Err(Denial::Body(_))
        ));
        let form = Some(Body {
            len: 4,
            content_type: Some("application/x-www-form-urlencoded"),
        });
        assert!(matches!(
            check(&policy, "POST", "/v1/notes", form),
            Err(Denial::Body(_))
        ));
    }

    #[test]
    fn parse_rejects_bad_rules_and_unknown_fields() {
        assert!(parse_policy("[hosts.\"https://api.example.com\"]\nallow = [{ method = \"post\", path = \"/x\" }]").is_err());
        assert!(
            parse_policy(
                "[hosts.\"https://api.example.com\"]\nallow = [{ method = \"POST\", path = \"x\" }]"
            )
            .is_err()
        );
        assert!(parse_policy("[hosts.\"https://api.example.com\"]\nallow = [{ method = \"POST\", path = \"/**/x\" }]").is_err());
        assert!(parse_policy("[hosts.\"https://api.example.com\"]\nmethod = [\"GET\"]").is_err());
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

        let parsed = parse_policy(&policy_toml(&policy).unwrap()).unwrap();

        assert_eq!(parsed.hosts.len(), 1);
        assert_eq!(
            parsed.host(&Origin::parse("api.example.com").unwrap()).deny,
            vec![rule("GET", "/v1/exports/**")]
        );
    }

    #[test]
    fn bound_origin_gets_its_credential() {
        assert_eq!(
            authorized("https://api.example.com/v1/users", "GET"),
            Ok("example".into())
        );
    }

    #[test]
    fn path_scoped_credentials_cover_only_their_paths() {
        let mut config = Config {
            credentials: vec![
                credential("reports", &["/v1/reports/**"]),
                credential("export", &["/v1/exports/*"]),
            ],
            ..Config::default()
        };
        let pick = |config: &Config, url: &str| {
            authorize(&Url::parse(url).unwrap(), "GET", None, config)
                .map(|(credential, _)| credential.name.clone())
        };

        assert_eq!(
            pick(&config, "https://api.example.com/v1/reports/1/rows"),
            Ok("reports".into())
        );
        assert_eq!(
            pick(&config, "https://api.example.com/v1/exports/7"),
            Ok("export".into())
        );
        assert_eq!(
            pick(&config, "https://api.example.com/V1/reports/1"),
            Err(Denial::Uncovered)
        );
        assert_eq!(
            pick(&config, "https://api.example.com/v1/exports/7/file"),
            Err(Denial::Uncovered)
        );

        config.credentials.push(credential("main", &[]));

        assert_eq!(
            pick(&config, "https://api.example.com/v1/reports"),
            Ok("reports".into())
        );
        assert_eq!(
            pick(&config, "https://api.example.com/v1/users"),
            Ok("main".into())
        );
        assert_eq!(
            pick(&config, "https://api.example.com/v1//reports/1"),
            Ok("main".into())
        );
    }

    #[test]
    fn other_origins_are_unconfigured() {
        assert!(matches!(
            authorized("https://api.example.com.attacker.example/", "GET"),
            Err(Denial::Unconfigured(_))
        ));
        assert!(matches!(
            authorized("http://api.example.com/", "GET"),
            Err(Denial::Unconfigured(_))
        ));
    }

    #[test]
    fn redirect_to_another_origin_is_unconfigured() {
        let next = Url::parse("https://api.example.com/v1/download")
            .unwrap()
            .join("//attacker.example/collect")
            .unwrap();
        let config = config();

        assert!(matches!(
            authorize(&next, "GET", None, &config),
            Err(Denial::Unconfigured(_))
        ));
    }

    #[test]
    fn writes_are_denied_by_default() {
        assert_eq!(
            authorized("https://api.example.com/v1/users", "POST"),
            Err(Denial::NotAllowed)
        );
        assert_eq!(
            authorized("https://api.example.com/v1/users", "DELETE"),
            Err(Denial::NotAllowed)
        );
    }

    #[test]
    fn userinfo_is_rejected() {
        assert_eq!(
            authorized("https://user:pass@api.example.com/", "GET"),
            Err(Denial::Userinfo)
        );
    }

    #[test]
    fn encoded_separators_are_rejected() {
        assert_eq!(
            authorized("https://api.example.com/v1/a%2Fb", "GET"),
            Err(Denial::EncodedSeparator)
        );
        assert_eq!(
            authorized("https://api.example.com/v1/a%5cb", "GET"),
            Err(Denial::EncodedSeparator)
        );
    }

    #[test]
    fn method_parameter_is_rejected() {
        assert_eq!(
            authorized("https://api.example.com/v1/users/1?_method=DELETE", "GET"),
            Err(Denial::MethodOverride("_method".into()))
        );
    }

    #[test]
    fn dot_segments_are_normalized_before_checks() {
        assert_eq!(
            Url::parse("https://api.example.com/v1/../admin")
                .unwrap()
                .path(),
            "/admin"
        );
        assert_eq!(
            Url::parse("https://api.example.com/v1/%2e%2e/admin")
                .unwrap()
                .path(),
            "/admin"
        );
    }
}
