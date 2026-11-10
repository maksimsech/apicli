use std::fmt;

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use url::{Host, Url, form_urlencoded};

const MONGO_OPTIONS: [&str; 13] = [
    "authsource",
    "authmechanism",
    "replicaset",
    "tls",
    "ssl",
    "tlscafile",
    "directconnection",
    "readpreference",
    "retrywrites",
    "retryreads",
    "w",
    "appname",
    "loadbalanced",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    Postgres,
    Redis,
    Mongo,
    Cassandra,
    ClickHouse,
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
    pub engine: Engine,
    pub host: String,
    pub port: u16,
    pub hosts: Vec<(String, u16)>,
    pub user: String,
    pub database: String,
    pub tls: Tls,
    pub root_cert: Option<String>,
    text: String,
}

impl Engine {
    pub fn name(self) -> &'static str {
        match self {
            Engine::Postgres => "Postgres",
            Engine::Redis => "Redis",
            Engine::Mongo => "MongoDB",
            Engine::Cassandra => "Cassandra",
            Engine::ClickHouse => "ClickHouse",
        }
    }
}

impl ConnectionUrl {
    pub fn parse(text: &str) -> Result<ConnectionUrl, String> {
        match text.split_once("://").map(|(scheme, _)| scheme) {
            Some("postgres" | "postgresql") => postgres(text),
            Some("redis" | "rediss") => redis(text),
            Some("mongodb" | "mongodb+srv") => mongo(text),
            Some("cassandra") => cassandra(text),
            Some("clickhouse") => clickhouse(text),
            Some(scheme) => Err(format!(
                "unsupported scheme {scheme}://, use postgres://, redis://, rediss://, mongodb://, mongodb+srv://, cassandra:// or clickhouse://"
            )),
            None => Err(format!(
                "{text} is not a URL, use one like postgres://agent@db.example.com:5432/app"
            )),
        }
    }
}

fn postgres(text: &str) -> Result<ConnectionUrl, String> {
    let example = "like postgres://agent@db.example.com:5432/app";
    let url = Url::parse(text).map_err(|error| format!("{text}: {error}, {example}"))?;
    let (host, user) = authority(&url, text, example)?;
    if user.is_empty() {
        return Err(format!("{text} has no user, {example}"));
    }
    let path = single_path(&url, text)?;
    let database = if path.is_empty() { user.clone() } else { path };
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
    let port = url.port().unwrap_or(5432);
    Ok(ConnectionUrl {
        engine: Engine::Postgres,
        hosts: vec![(host.clone(), port)],
        host,
        port,
        user,
        database,
        tls,
        root_cert,
        text: url.to_string(),
    })
}

fn redis(text: &str) -> Result<ConnectionUrl, String> {
    let example = "like redis://agent@cache.example.com:6379/0";
    let url = Url::parse(text).map_err(|error| format!("{text}: {error}, {example}"))?;
    let (host, user) = authority(&url, text, example)?;
    let path = single_path(&url, text)?;
    let database = if path.is_empty() { "0".into() } else { path };
    if database.parse::<u32>().is_err() {
        return Err(format!(
            "{database} is not a Redis database number, {example}"
        ));
    }
    let tls = if url.scheme() == "rediss" {
        Tls::Require
    } else {
        Tls::Disable
    };
    let mut root_cert = None;
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "cacert" if tls == Tls::Require => root_cert = Some(value.into_owned()),
            _ => {
                return Err(format!(
                    "the {name} parameter is not supported, only cacert on rediss:// URLs"
                ));
            }
        }
    }
    let port = url.port().unwrap_or(6379);
    Ok(ConnectionUrl {
        engine: Engine::Redis,
        hosts: vec![(host.clone(), port)],
        host,
        port,
        user,
        database,
        tls,
        root_cert,
        text: url.to_string(),
    })
}

fn mongo(text: &str) -> Result<ConnectionUrl, String> {
    let example = "like mongodb://agent@db.example.com:27017/shop";
    let srv = text.starts_with("mongodb+srv://");
    let Parts {
        user,
        hosts,
        path,
        query,
    } = multiple(text, 27017, srv, example)?;
    let database = if path.is_empty() {
        "test".to_string()
    } else {
        path
    };
    let mut tls = if srv { Tls::Require } else { Tls::Disable };
    let mut root_cert = None;
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        let key = name.to_ascii_lowercase();
        if !MONGO_OPTIONS.contains(&key.as_str()) {
            return Err(format!(
                "the {name} option is not supported, only {}",
                MONGO_OPTIONS.join(", ")
            ));
        }
        match key.as_str() {
            "tls" | "ssl" => {
                tls = if value == "true" {
                    Tls::Require
                } else {
                    Tls::Disable
                }
            }
            "tlscafile" => root_cert = Some(value.into_owned()),
            "authmechanism" if !matches!(value.as_ref(), "SCRAM-SHA-1" | "SCRAM-SHA-256") => {
                return Err(
                    "dbcli logs in with a password, use SCRAM-SHA-256 or SCRAM-SHA-1".into(),
                );
            }
            _ => {}
        }
    }
    Ok(ConnectionUrl {
        engine: Engine::Mongo,
        host: hosts[0].0.clone(),
        port: hosts[0].1,
        hosts,
        user,
        database,
        tls,
        root_cert,
        text: text.to_string(),
    })
}

fn cassandra(text: &str) -> Result<ConnectionUrl, String> {
    let example = "like cassandra://agent@10.0.0.1,10.0.0.2:9042/shop";
    let Parts {
        user,
        hosts,
        path: keyspace,
        query,
    } = multiple(text, 9042, false, example)?;
    let (tls, root_cert) = secure(&query, "tls", "cassandra")?;
    Ok(ConnectionUrl {
        engine: Engine::Cassandra,
        host: hosts[0].0.clone(),
        port: hosts[0].1,
        hosts,
        user,
        database: keyspace,
        tls,
        root_cert,
        text: text.to_string(),
    })
}

fn clickhouse(text: &str) -> Result<ConnectionUrl, String> {
    let example = "like clickhouse://agent@db.example.com:8123/default";
    let url = Url::parse(text).map_err(|error| format!("{text}: {error}, {example}"))?;
    let (host, user) = authority(&url, text, example)?;
    if user.is_empty() {
        return Err(format!("{text} has no user, {example}"));
    }
    let path = single_path(&url, text)?;
    let database = if path.is_empty() {
        "default".into()
    } else {
        path
    };
    let (tls, root_cert) = secure(url.query().unwrap_or_default(), "secure", "clickhouse")?;
    let port = url
        .port()
        .unwrap_or(if tls == Tls::Require { 8443 } else { 8123 });
    Ok(ConnectionUrl {
        engine: Engine::ClickHouse,
        hosts: vec![(host.clone(), port)],
        host,
        port,
        user,
        database,
        tls,
        root_cert,
        text: url.to_string(),
    })
}

struct Parts {
    user: String,
    hosts: Vec<(String, u16)>,
    path: String,
    query: String,
}

fn multiple(text: &str, default_port: u16, srv: bool, example: &str) -> Result<Parts, String> {
    let (_, rest) = text.split_once("://").unwrap_or_default();
    let (authority, tail) = rest.split_at(rest.find(['/', '?']).unwrap_or(rest.len()));
    let Some((userinfo, list)) = authority.rsplit_once('@') else {
        return Err(format!("{text} has no user, {example}"));
    };
    if userinfo.contains(':') {
        return Err("leave the password out of the URL, dbcli asks for it".into());
    }
    let user = decode(userinfo);
    if user.is_empty() {
        return Err(format!("{text} has no user, {example}"));
    }
    let mut hosts = Vec::new();
    for entry in list.split(',') {
        let (host, port) = match entry.rsplit_once(':') {
            Some((host, port)) if !host.ends_with(']') || entry.starts_with('[') => {
                let port = port
                    .parse::<u16>()
                    .map_err(|_| format!("{entry} has an invalid port, {example}"))?;
                (host, Some(port))
            }
            _ => (entry, None),
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if host.is_empty() || host.contains(['/', '@', '?', '#']) {
            return Err(format!("{text} has an invalid host, {example}"));
        }
        if srv && port.is_some() {
            return Err("mongodb+srv:// URLs take a host name without a port".into());
        }
        hosts.push((host.to_string(), port.unwrap_or(default_port)));
    }
    if srv && hosts.len() > 1 {
        return Err("mongodb+srv:// URLs take one host name".into());
    }
    if tail.contains('#') {
        return Err(format!("{text} has a #fragment, remove it"));
    }
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    let path = path.strip_prefix('/').unwrap_or(path);
    if path.contains('/') {
        return Err(format!("{text} has more than a database name in its path"));
    }
    Ok(Parts {
        user,
        hosts,
        path: decode(path),
        query: query.to_string(),
    })
}

fn secure(query: &str, flag: &str, scheme: &str) -> Result<(Tls, Option<String>), String> {
    let mut tls = Tls::Disable;
    let mut root_cert = None;
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        match name.as_ref() {
            _ if name == flag => {
                tls = match value.as_ref() {
                    "true" | "1" => Tls::Require,
                    "false" | "0" => Tls::Disable,
                    _ => return Err(format!("{flag}={value} is not true or false")),
                }
            }
            "cacert" => root_cert = Some(value.into_owned()),
            _ => {
                return Err(format!(
                    "the {name} parameter is not supported, {scheme}:// URLs take only {flag} and cacert"
                ));
            }
        }
    }
    if root_cert.is_some() && tls == Tls::Disable {
        return Err(format!("cacert needs {flag}=true"));
    }
    Ok((tls, root_cert))
}

fn authority(url: &Url, text: &str, example: &str) -> Result<(String, String), String> {
    if url.password().is_some() {
        return Err("leave the password out of the URL, dbcli asks for it".into());
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
    Ok((host, decode(url.username())))
}

fn single_path(url: &Url, text: &str) -> Result<String, String> {
    let path = url.path().strip_prefix('/').unwrap_or(url.path());
    if path.contains('/') {
        return Err(format!("{text} has more than a database in its path"));
    }
    Ok(decode(path))
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
    fn parses_a_full_postgres_url() {
        let url = ConnectionUrl::parse("postgres://agent@db.example.com:6543/app?sslmode=require")
            .unwrap();

        assert_eq!(url.engine, Engine::Postgres);
        assert_eq!(url.host, "db.example.com");
        assert_eq!(url.port, 6543);
        assert_eq!(url.user, "agent");
        assert_eq!(url.database, "app");
        assert_eq!(url.tls, Tls::Require);
    }

    #[test]
    fn postgres_defaults_follow_libpq() {
        let url = ConnectionUrl::parse("postgresql://agent@[::1]").unwrap();

        assert_eq!(url.host, "::1");
        assert_eq!(url.port, 5432);
        assert_eq!(url.database, "agent");
        assert_eq!(url.tls, Tls::Prefer);
    }

    #[test]
    fn parses_redis_urls() {
        let url = ConnectionUrl::parse("rediss://agent@cache.example.com:6380/2").unwrap();

        assert_eq!(url.engine, Engine::Redis);
        assert_eq!(url.port, 6380);
        assert_eq!(url.user, "agent");
        assert_eq!(url.database, "2");
        assert_eq!(url.tls, Tls::Require);

        let url = ConnectionUrl::parse("redis://cache.example.com").unwrap();

        assert_eq!(url.user, "");
        assert_eq!(url.port, 6379);
        assert_eq!(url.database, "0");
        assert_eq!(url.tls, Tls::Disable);
    }

    #[test]
    fn parses_mongo_urls() {
        let url = ConnectionUrl::parse(
            "mongodb://agent@db1.example.com:27018,db2.example.com/shop?replicaSet=rs0&authSource=admin&tls=true",
        )
        .unwrap();

        assert_eq!(url.engine, Engine::Mongo);
        assert_eq!(url.host, "db1.example.com");
        assert_eq!(url.port, 27018);
        assert_eq!(url.database, "shop");
        assert_eq!(url.tls, Tls::Require);

        let url = ConnectionUrl::parse("mongodb+srv://agent@cluster0.example.net").unwrap();

        assert_eq!(url.database, "test");
        assert_eq!(url.tls, Tls::Require);
    }

    #[test]
    fn parses_cassandra_and_clickhouse_urls() {
        let url =
            ConnectionUrl::parse("cassandra://agent@10.0.0.1,10.0.0.2:9142/shop?tls=true").unwrap();

        assert_eq!(url.engine, Engine::Cassandra);
        assert_eq!(
            url.hosts,
            [
                ("10.0.0.1".to_string(), 9042),
                ("10.0.0.2".to_string(), 9142)
            ]
        );
        assert_eq!(url.database, "shop");
        assert_eq!(url.tls, Tls::Require);

        let url = ConnectionUrl::parse("clickhouse://agent@db.example.com?secure=true").unwrap();

        assert_eq!(url.engine, Engine::ClickHouse);
        assert_eq!(url.port, 8443);
        assert_eq!(url.database, "default");
        assert_eq!(url.tls, Tls::Require);
    }

    #[test]
    fn rejects_a_password_in_the_url() {
        for text in [
            "postgres://agent:hunter22@db.example.com/app",
            "redis://agent:hunter22@cache.example.com",
            "redis://:hunter22@cache.example.com",
            "mongodb://agent:hunter22@db.example.com/shop",
            "mongodb+srv://agent:hunter22@cluster0.example.net/shop",
            "cassandra://agent:hunter22@10.0.0.1/shop",
            "clickhouse://agent:hunter22@db.example.com/default",
        ] {
            assert!(ConnectionUrl::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn rejects_parameters_that_change_the_target_or_session() {
        for text in [
            "postgres://agent@db.example.com/app?host=attacker.example",
            "postgres://agent@db.example.com/app?hostaddr=203.0.113.9",
            "postgres://agent@db.example.com/app?port=6543",
            "postgres://agent@db.example.com/app?user=postgres",
            "postgres://agent@db.example.com/app?dbname=other",
            "postgres://agent@db.example.com/app?options=-c%20default_transaction_read_only%3Doff",
            "postgres://agent@db.example.com/app?service=prod",
            "redis://cache.example.com/0?cacert=/tmp/ca.pem",
            "redis://cache.example.com/0?protocol=3",
            "cassandra://agent@10.0.0.1/shop?dc=eu1",
            "cassandra://agent@10.0.0.1/shop?cacert=/tmp/ca.pem",
            "clickhouse://agent@db.example.com/default?readonly=0",
            "clickhouse://agent@db.example.com/default?user=default",
            "clickhouse://agent@db.example.com/default?database=system",
            "mongodb://agent@db.example.com/shop?tlsInsecure=true",
            "mongodb://agent@db.example.com/shop?tlsAllowInvalidCertificates=true",
            "mongodb://agent@db.example.com/shop?tlsAllowInvalidHostnames=true",
            "mongodb://agent@db.example.com/shop?proxyHost=attacker.example",
            "mongodb://agent@db.example.com/shop?authMechanism=MONGODB-X509",
            "mongodb://agent@db.example.com/shop?tlsCertificateKeyFile=/tmp/key.pem",
        ] {
            assert!(ConnectionUrl::parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn rejects_other_shapes() {
        for text in [
            "mysql://agent@db.example.com/app",
            "db.example.com",
            "postgres://db.example.com/app",
            "postgres://agent@db1.example.com,db2.example.com/app",
            "postgres://agent@db.example.com/app/extra",
            "postgres://agent@/app",
            "postgres:///app",
            "redis://cache.example.com/zero",
            "redis://cache.example.com/0/1",
            "mongodb://db.example.com/shop",
            "mongodb://agent@/shop",
            "mongodb://agent@db.example.com:port/shop",
            "mongodb+srv://agent@cluster0.example.net:27017/shop",
            "mongodb+srv://agent@a.example.net,b.example.net/shop",
            "mongodb://agent@db.example.com/shop/extra",
            "cassandra://10.0.0.1/shop",
            "cassandra://agent@10.0.0.1:port/shop",
            "clickhouse://db.example.com/default",
            "clickhouse://agent@db1.example.com,db2.example.com/default",
        ] {
            assert!(ConnectionUrl::parse(text).is_err(), "{text}");
        }
    }
}
