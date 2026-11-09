use std::fmt;

use percent_encoding::percent_decode_str;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::{Limits, Rate, Vault, vault::expose};

#[derive(Debug, Serialize, Deserialize)]
pub struct Connection {
    pub name: String,
    pub url: ConnectionUrl,
    #[serde(serialize_with = "expose")]
    pub password: SecretString,
    #[serde(default, skip_serializing_if = "is_false")]
    pub write: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<Rate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls {
    Disable,
    Prefer,
    Require,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ConnectionUrl {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub database: String,
    pub tls: Tls,
    pub root_cert: Option<String>,
    text: String,
}

fn is_false(value: &bool) -> bool {
    !value
}

impl Connection {
    pub fn limits(&self) -> Limits {
        Limits {
            rate: self.rate,
            burst: self.burst,
            daily: self.daily,
        }
    }
}

impl Vault {
    pub fn connection(&self, name: &str) -> Option<&Connection> {
        self.connections
            .iter()
            .find(|connection| connection.name == name)
    }

    pub fn connection_mut(&mut self, name: &str) -> Option<&mut Connection> {
        self.connections
            .iter_mut()
            .find(|connection| connection.name == name)
    }
}

impl ConnectionUrl {
    pub fn parse(text: &str) -> Result<ConnectionUrl, String> {
        let example = "like postgres://agent@db.example.com:5432/app";
        let url = Url::parse(text).map_err(|error| format!("{text}: {error}, {example}"))?;
        if !matches!(url.scheme(), "postgres" | "postgresql") {
            return Err(format!(
                "unsupported scheme {}://, use postgres://",
                url.scheme()
            ));
        }
        if url.password().is_some() {
            return Err("leave the password out of the URL, dbcli asks for it".into());
        }
        let user = decode(url.username());
        if user.is_empty() {
            return Err(format!("{text} has no user, {example}"));
        }
        let host = match url.host() {
            Some(Host::Ipv6(ip)) => ip.to_string(),
            Some(Host::Ipv4(ip)) => ip.to_string(),
            Some(Host::Domain(domain)) if !domain.is_empty() => decode(domain),
            _ => return Err(format!("{text} has no host, {example}")),
        };
        if host.contains(',') {
            return Err("only one host is supported".into());
        }
        if url.fragment().is_some() {
            return Err(format!("{text} has a #fragment, remove it"));
        }
        let path = url.path().strip_prefix('/').unwrap_or(url.path());
        if path.contains('/') {
            return Err(format!("{text} has more than a database name in its path"));
        }
        let database = if path.is_empty() {
            user.clone()
        } else {
            decode(path)
        };
        let mut tls = Tls::Prefer;
        let mut root_cert = None;
        for (name, value) in url.query_pairs() {
            match name.as_ref() {
                "sslmode" => {
                    tls = match value.as_ref() {
                        "disable" => Tls::Disable,
                        "allow" | "prefer" => Tls::Prefer,
                        "require" | "verify-ca" | "verify-full" => Tls::Require,
                        _ => return Err(format!("sslmode={value} is not a valid sslmode")),
                    }
                }
                "sslrootcert" => root_cert = Some(value.into_owned()),
                _ => {
                    return Err(format!(
                        "the {name} parameter is not supported, only sslmode and sslrootcert"
                    ));
                }
            }
        }
        Ok(ConnectionUrl {
            host,
            port: url.port().unwrap_or(5432),
            user,
            database,
            tls,
            root_cert,
            text: url.to_string(),
        })
    }
}

fn decode(text: &str) -> String {
    percent_decode_str(text).decode_utf8_lossy().into_owned()
}

impl fmt::Display for ConnectionUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{}", self.text)
    }
}

impl TryFrom<String> for ConnectionUrl {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        ConnectionUrl::parse(&text)
    }
}

impl From<ConnectionUrl> for String {
    fn from(url: ConnectionUrl) -> String {
        url.text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_url() {
        let url = ConnectionUrl::parse("postgres://agent@db.example.com:6543/app?sslmode=require")
            .unwrap();

        assert_eq!(url.host, "db.example.com");
        assert_eq!(url.port, 6543);
        assert_eq!(url.user, "agent");
        assert_eq!(url.database, "app");
        assert_eq!(url.tls, Tls::Require);
    }

    #[test]
    fn defaults_follow_libpq() {
        let url = ConnectionUrl::parse("postgresql://agent@[::1]").unwrap();

        assert_eq!(url.host, "::1");
        assert_eq!(url.port, 5432);
        assert_eq!(url.database, "agent");
        assert_eq!(url.tls, Tls::Prefer);
    }

    #[test]
    fn rejects_a_password_in_the_url() {
        assert!(ConnectionUrl::parse("postgres://agent:hunter22@db.example.com/app").is_err());
    }

    #[test]
    fn rejects_parameters_that_change_the_target_or_session() {
        for query in [
            "host=attacker.example",
            "hostaddr=203.0.113.9",
            "port=6543",
            "user=postgres",
            "dbname=other",
            "options=-c%20default_transaction_read_only%3Doff",
            "service=prod",
        ] {
            assert!(
                ConnectionUrl::parse(&format!("postgres://agent@db.example.com/app?{query}"))
                    .is_err(),
                "{query}"
            );
        }
    }

    #[test]
    fn rejects_other_shapes() {
        for text in [
            "mysql://agent@db.example.com/app",
            "postgres://db.example.com/app",
            "postgres://agent@db1.example.com,db2.example.com/app",
            "postgres://agent@db.example.com/app/extra",
            "postgres://agent@/app",
            "postgres:///app",
        ] {
            assert!(ConnectionUrl::parse(text).is_err(), "{text}");
        }
    }
}
