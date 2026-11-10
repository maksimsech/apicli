use std::fmt;

use serde::{Deserialize, Serialize};

use super::{Connection, Engine};

const TABLE_WRITES: [&str; 4] = ["INSERT", "UPDATE", "DELETE", "TRUNCATE"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allow {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

impl fmt::Display for Allow {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match &self.target {
            Some(target) => write!(formatter, "{} {target}", self.action),
            None => write!(formatter, "{}", self.action),
        }
    }
}

impl Connection {
    pub fn check_rule(&self, action: &str, target: Option<&str>) -> Result<Allow, String> {
        let target = target.map(String::from);
        match self.url.engine {
            Engine::Postgres | Engine::ClickHouse => Err(format!(
                "{} connections take only `dbcli allow add {} write`, limits on tables belong in GRANTs",
                self.url.engine.name(),
                self.name
            )),
            Engine::Cassandra => {
                let action = action.to_ascii_uppercase();
                if action.is_empty() || !action.bytes().all(|byte| byte.is_ascii_alphabetic()) {
                    return Err(format!(
                        "{action} is not a CQL statement keyword, use one like INSERT, UPDATE or CREATE"
                    ));
                }
                if target.is_none() && TABLE_WRITES.contains(&action.as_str()) {
                    return Err(format!(
                        "{action} rules need a table, like 'shop.orders', 'shop.*' or '*'"
                    ));
                }
                Ok(Allow { action, target })
            }
            Engine::Redis => {
                let valid = action.split('|').count() <= 2
                    && action.split('|').all(|part| {
                        !part.is_empty()
                            && part
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
                    });
                if !valid {
                    return Err(format!(
                        "{action} is not a Redis command, use one like SET or 'CONFIG|SET'"
                    ));
                }
                Ok(Allow {
                    action: action.to_ascii_uppercase(),
                    target,
                })
            }
            Engine::Mongo => {
                if action.is_empty() || !action.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
                    return Err(format!(
                        "{action} is not a MongoDB command name, use one like insert, update or delete"
                    ));
                }
                if target.is_none() {
                    return Err(
                        "MongoDB rules need a namespace, like 'shop.orders', 'shop.*' or '*'"
                            .into(),
                    );
                }
                Ok(Allow {
                    action: action.to_string(),
                    target,
                })
            }
        }
    }

    pub fn rule(&self, action: &str, targets: &[&[u8]]) -> Option<&Allow> {
        self.allow.iter().find(|rule| match self.url.engine {
            Engine::Postgres | Engine::ClickHouse => false,
            Engine::Cassandra => {
                rule.action.eq_ignore_ascii_case(action)
                    && match &rule.target {
                        None => targets.is_empty(),
                        Some(pattern) => targets.len() == 1 && glob(pattern.as_bytes(), targets[0]),
                    }
            }
            Engine::Redis => {
                let named = rule.action.eq_ignore_ascii_case(action)
                    || action
                        .split_once('|')
                        .is_some_and(|(container, _)| rule.action.eq_ignore_ascii_case(container));
                named
                    && match &rule.target {
                        None => targets.is_empty(),
                        Some(pattern) => {
                            !targets.is_empty()
                                && targets
                                    .iter()
                                    .all(|target| glob(pattern.as_bytes(), target))
                        }
                    }
            }
            Engine::Mongo => {
                rule.action.eq_ignore_ascii_case(action)
                    && rule.target.as_ref().is_some_and(|pattern| {
                        targets.len() == 1 && glob(pattern.as_bytes(), targets[0])
                    })
            }
        })
    }
}

pub fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star = None;
    while t < text.len() {
        if pattern.get(p) == Some(&b'*') {
            star = Some((p, t));
            p += 1;
        } else if let Some(width) = single(&pattern[p..], text[t]) {
            p += width;
            t += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, t));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|byte| *byte == b'*')
}

fn single(pattern: &[u8], byte: u8) -> Option<usize> {
    let (first, rest) = pattern.split_first()?;
    match first {
        b'?' => Some(1),
        b'[' => match class(rest, Some(byte)) {
            Some((true, after)) => Some(pattern.len() - after.len()),
            Some((false, _)) => None,
            None => (byte == b'[').then_some(1),
        },
        b'\\' if !rest.is_empty() => (rest[0] == byte).then_some(2),
        _ => (*first == byte).then_some(1),
    }
}

fn class(pattern: &[u8], byte: Option<u8>) -> Option<(bool, &[u8])> {
    let (negate, mut rest) = match pattern.split_first() {
        Some((b'^', rest)) => (true, rest),
        _ => (false, pattern),
    };
    let mut found = false;
    let mut first = true;
    loop {
        match rest {
            [] => return None,
            [b']', after @ ..] if !first => {
                return Some((byte.is_some() && found != negate, after));
            }
            [b'\\', escaped, after @ ..] => {
                found |= byte == Some(*escaped);
                rest = after;
            }
            [low, b'-', high, after @ ..] if *high != b']' => {
                found |= byte.is_some_and(|byte| (*low.min(high)..=*low.max(high)).contains(&byte));
                rest = after;
            }
            [single, after @ ..] => {
                found |= byte == Some(*single);
                rest = after;
            }
        }
        first = false;
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;
    use crate::ConnectionUrl;

    fn with_rules(url: &str, allow: &[(&str, Option<&str>)]) -> Connection {
        let mut connection = Connection::new(
            "test".into(),
            ConnectionUrl::parse(url).unwrap(),
            SecretString::from("password-123"),
        );
        connection.allow = allow
            .iter()
            .map(|(action, target)| Allow {
                action: action.to_string(),
                target: target.map(String::from),
            })
            .collect();
        connection
    }

    #[test]
    fn glob_matches_like_redis() {
        assert!(glob(b"cache:*", b"cache:"));
        assert!(glob(b"cache:*", b"cache:user:1"));
        assert!(!glob(b"cache:*", b"session:1"));
        assert!(glob(b"user:?", b"user:7"));
        assert!(!glob(b"user:?", b"user:17"));
        assert!(glob(b"user:[0-9]", b"user:5"));
        assert!(!glob(b"user:[0-9]", b"user:x"));
        assert!(glob(b"user:[^0-9]", b"user:x"));
        assert!(glob(b"a\\*b", b"a*b"));
        assert!(!glob(b"a\\*b", b"axb"));
        assert!(glob(b"shop.*", b"shop.orders"));
        assert!(!glob(b"shop.*", b"shopping.orders"));
        assert!(!glob(b"shop.orders", b"shop.orders2"));
    }

    #[test]
    fn redis_rules_need_every_key_to_match() {
        let connection = with_rules("redis://cache.example.com", &[("SET", Some("cache:*"))]);

        assert!(connection.rule("SET", &[b"cache:1"]).is_some());
        assert!(connection.rule("set", &[b"cache:1"]).is_some());
        assert!(connection.rule("SET", &[b"session:1"]).is_none());
        assert!(connection.rule("MSET", &[b"cache:1"]).is_none());
        assert!(connection.rule("SET", &[]).is_none());

        let connection = with_rules("redis://cache.example.com", &[("MSET", Some("cache:*"))]);

        assert!(
            connection
                .rule("MSET", &[&b"cache:1"[..], &b"cache:2"[..]])
                .is_some()
        );
        assert!(
            connection
                .rule("MSET", &[&b"cache:1"[..], &b"session:2"[..]])
                .is_none()
        );
    }

    #[test]
    fn redis_rules_without_a_glob_cover_only_keyless_commands() {
        let connection = with_rules(
            "redis://cache.example.com",
            &[("FLUSHDB", None), ("CONFIG", None)],
        );

        assert!(connection.rule("FLUSHDB", &[]).is_some());
        assert!(connection.rule("CONFIG|SET", &[]).is_some());
        assert!(connection.rule("DEL", &[b"any"]).is_none());

        let connection = with_rules("redis://cache.example.com", &[("CONFIG|GET", None)]);

        assert!(connection.rule("CONFIG|GET", &[]).is_some());
        assert!(connection.rule("CONFIG|SET", &[]).is_none());
    }

    #[test]
    fn mongo_rules_match_command_and_namespace() {
        let connection = with_rules(
            "mongodb://agent@db.example.com/shop",
            &[("update", Some("shop.orders")), ("insert", Some("shop.*"))],
        );

        assert!(connection.rule("update", &[b"shop.orders"]).is_some());
        assert!(connection.rule("update", &[b"shop.users"]).is_none());
        assert!(connection.rule("delete", &[b"shop.orders"]).is_none());
        assert!(connection.rule("insert", &[b"shop.anything"]).is_some());
        assert!(connection.rule("insert", &[b"admin.users"]).is_none());
    }

    #[test]
    fn cassandra_rules_match_keyword_and_table() {
        let connection = with_rules(
            "cassandra://agent@10.0.0.1/shop",
            &[("INSERT", Some("shop.*")), ("GRANT", None)],
        );

        assert!(connection.rule("insert", &[b"shop.orders"]).is_some());
        assert!(connection.rule("INSERT", &[b"other.orders"]).is_none());
        assert!(connection.rule("UPDATE", &[b"shop.orders"]).is_none());
        assert!(connection.rule("GRANT", &[]).is_some());
        assert!(connection.rule("GRANT", &[b"shop.orders"]).is_none());
        assert!(connection.rule("INSERT", &[]).is_none());
    }

    #[test]
    fn rules_are_checked_per_engine() {
        let postgres = with_rules("postgres://agent@db.example.com/app", &[]);
        let redis = with_rules("redis://cache.example.com", &[]);
        let mongo = with_rules("mongodb://agent@db.example.com/shop", &[]);

        assert!(postgres.check_rule("SET", None).is_err());
        assert_eq!(
            redis.check_rule("config|set", None).unwrap().action,
            "CONFIG|SET"
        );
        assert!(redis.check_rule("SET; FLUSHALL", None).is_err());
        assert!(mongo.check_rule("update", None).is_err());
        assert!(mongo.check_rule("update", Some("shop.orders")).is_ok());
        assert!(mongo.check_rule("$where", Some("*")).is_err());

        let cassandra = with_rules("cassandra://agent@10.0.0.1/shop", &[]);
        let clickhouse = with_rules("clickhouse://agent@db.example.com/default", &[]);

        assert!(cassandra.check_rule("INSERT", None).is_err());
        assert!(cassandra.check_rule("DROP; GRANT", None).is_err());
        assert_eq!(
            cassandra
                .check_rule("create", Some("shop.*"))
                .unwrap()
                .action,
            "CREATE"
        );
        assert!(clickhouse.check_rule("INSERT", Some("default.t")).is_err());
    }
}
