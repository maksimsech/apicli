use std::{
    io::{IsTerminal, stderr, stdout},
    time::Instant,
};

use fieldkit_common::{Entry, Failure, record};
use fieldkit_policy::{Allow, Connection, Redactor, Vault};
use fieldkit_vault::Store;

use crate::{
    cassandra, clickhouse, mongo, postgres, redis,
    shared::{ConnectionUrl, Context, add_hint, flag},
};

pub async fn send(name: &str, args: &[String]) -> Result<u8, Failure> {
    let store = Store::open()?;
    let vault = store.load()?;
    let mut entry = Entry::start();
    let started = Instant::now();
    let terminal = stdout().is_terminal();
    let mut out = stdout().lock();
    let mut err = stderr().lock();
    let mut context = Context::new(&store, &vault, &mut out, &mut err, &mut entry, terminal);
    let result = perform(name, args, &vault, &mut context).await;
    entry.ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match &result {
        Ok(_) => entry.outcome = "sent".into(),
        Err(failure) => {
            entry.outcome = failure.outcome().into();
            entry.error = failure.to_string().lines().next().map(String::from);
        }
    }
    record("dbcli", &store, &entry, vault.policy.log_limit_mb);
    result
}

pub async fn perform(
    name: &str,
    args: &[String],
    vault: &Vault,
    context: &mut Context<'_>,
) -> Result<u8, Failure> {
    context.entry.connection = Some(name.to_string());
    let connection = find(vault, name)?;
    let (engine, url) = target(connection)?;
    let result = match engine {
        Engine::Postgres => postgres::run(connection, &url, args, context).await,
        Engine::Redis => redis::run(connection, &url, args, context).await,
        Engine::Mongo => mongo::run(connection, &url, args, context).await,
        Engine::Cassandra => cassandra::run(connection, &url, args, context).await,
        Engine::ClickHouse => clickhouse::run(connection, &url, args, context).await,
    };
    result.map_err(|failure| scrub(failure, &context.redactor))
}

pub async fn explain(connection: &Connection, args: &[String]) -> Result<Vec<String>, Failure> {
    let (engine, url) = target(connection)?;
    match engine {
        Engine::Postgres => postgres::explain(connection, args),
        Engine::Redis => redis::explain(connection, &url, args).await,
        Engine::Mongo => mongo::explain(connection, &url, args),
        Engine::Cassandra => cassandra::explain(connection, &url, args),
        Engine::ClickHouse => clickhouse::explain(connection, args),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    Postgres,
    Redis,
    Mongo,
    Cassandra,
    ClickHouse,
}

impl Engine {
    pub fn of(url: &str) -> Result<Engine, String> {
        match url.split_once("://").map(|(scheme, _)| scheme) {
            Some("postgres" | "postgresql") => Ok(Engine::Postgres),
            Some("redis" | "rediss") => Ok(Engine::Redis),
            Some("mongodb" | "mongodb+srv") => Ok(Engine::Mongo),
            Some("cassandra") => Ok(Engine::Cassandra),
            Some("clickhouse") => Ok(Engine::ClickHouse),
            Some(scheme) => Err(format!(
                "unsupported scheme {scheme}://, use postgres://, redis://, rediss://, mongodb://, mongodb+srv://, cassandra:// or clickhouse://"
            )),
            None => Err(format!(
                "{url} is not a URL, use one like postgres://agent@db.example.com:5432/app"
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Engine::Postgres => "Postgres",
            Engine::Redis => "Redis",
            Engine::Mongo => "MongoDB",
            Engine::Cassandra => "Cassandra",
            Engine::ClickHouse => "ClickHouse",
        }
    }

    pub fn write_flag(self) -> bool {
        matches!(self, Engine::Postgres | Engine::ClickHouse)
    }

    pub fn parse(self, url: &str) -> Result<ConnectionUrl, String> {
        match self {
            Engine::Postgres => postgres::parse(url),
            Engine::Redis => redis::parse(url),
            Engine::Mongo => mongo::parse(url),
            Engine::Cassandra => cassandra::parse(url),
            Engine::ClickHouse => clickhouse::parse(url),
        }
    }

    pub fn rule(self, name: &str, action: &str, target: Option<&str>) -> Result<Allow, String> {
        match self {
            Engine::Redis => redis::rule(action, target),
            Engine::Mongo => mongo::rule(action, target),
            Engine::Cassandra => cassandra::rule(action, target),
            Engine::Postgres | Engine::ClickHouse => Err(format!(
                "{} connections take only `dbcli allow add {name} write`, limits on tables belong in GRANTs",
                self.name()
            )),
        }
    }

    pub fn mode(self, connection: &Connection) -> &'static str {
        match self {
            _ if self.write_flag() => flag(connection),
            _ if connection.allow.is_empty() => "read-only",
            _ => "rules",
        }
    }

    pub fn describe(self, connection: &Connection) -> &'static str {
        match self {
            Engine::Postgres => postgres::describe(connection),
            Engine::ClickHouse => clickhouse::describe(connection),
            _ if connection.allow.is_empty() => "read-only, other commands need an allow rule",
            _ => "reads, plus what the allow rules below match",
        }
    }
}

pub fn parse(url: &str) -> Result<ConnectionUrl, String> {
    Engine::of(url)?.parse(url)
}

fn target(connection: &Connection) -> Result<(Engine, ConnectionUrl), Failure> {
    let stored = |error: String| {
        Failure::Integrity(format!(
            "the stored URL of {} is invalid: {error}",
            connection.name
        ))
    };
    let engine = Engine::of(&connection.url).map_err(stored)?;
    Ok((engine, engine.parse(&connection.url).map_err(stored)?))
}

pub fn find<'a>(vault: &'a Vault, name: &str) -> Result<&'a Connection, Failure> {
    vault.connection(name).ok_or_else(|| {
        let names = vault
            .connections
            .iter()
            .map(|connection| connection.name.as_str())
            .collect::<Vec<_>>();
        let known = if names.is_empty() {
            "no connections are configured yet".to_string()
        } else {
            format!("configured: {}", names.join(", "))
        };
        Failure::Unconfigured(format!(
            "{name} is not configured\n{known}\nto add it, the user can run: {}",
            add_hint(name)
        ))
    })
}

pub fn scrub(failure: Failure, redactor: &Redactor) -> Failure {
    let clean = |text: String| redactor.redact_str(&text);
    match failure {
        Failure::Connect(text) => Failure::Connect(clean(text)),
        Failure::Tls(text) => Failure::Tls(clean(text)),
        Failure::Network(text) => Failure::Network(clean(text)),
        Failure::Database(text) => Failure::Database(clean(text)),
        Failure::Denied(text) => Failure::Denied(clean(text)),
        Failure::Usage(text) => Failure::Usage(clean(text)),
        failure => failure,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::Tls;

    #[test]
    fn parses_a_full_postgres_url() {
        let url = parse("postgres://agent@db.example.com:6543/app?sslmode=require").unwrap();

        assert_eq!(Engine::of(&url.text), Ok(Engine::Postgres));
        assert_eq!(url.host, "db.example.com");
        assert_eq!(url.port, 6543);
        assert_eq!(url.user, "agent");
        assert_eq!(url.database, "app");
        assert_eq!(url.tls, Tls::Require);
    }

    #[test]
    fn postgres_defaults_follow_libpq() {
        let url = parse("postgresql://agent@[::1]").unwrap();

        assert_eq!(url.host, "::1");
        assert_eq!(url.port, 5432);
        assert_eq!(url.database, "agent");
        assert_eq!(url.tls, Tls::Prefer);
    }

    #[test]
    fn parses_redis_urls() {
        let url = parse("rediss://agent@cache.example.com:6380/2").unwrap();

        assert_eq!(Engine::of(&url.text), Ok(Engine::Redis));
        assert_eq!(url.port, 6380);
        assert_eq!(url.user, "agent");
        assert_eq!(url.database, "2");
        assert_eq!(url.tls, Tls::Require);

        let url = parse("redis://cache.example.com").unwrap();

        assert_eq!(url.user, "");
        assert_eq!(url.port, 6379);
        assert_eq!(url.database, "0");
        assert_eq!(url.tls, Tls::Disable);
    }

    #[test]
    fn parses_mongo_urls() {
        let url = parse(
            "mongodb://agent@db1.example.com:27018,db2.example.com/shop?replicaSet=rs0&authSource=admin&tls=true",
        )
        .unwrap();

        assert_eq!(Engine::of(&url.text), Ok(Engine::Mongo));
        assert_eq!(url.host, "db1.example.com");
        assert_eq!(url.port, 27018);
        assert_eq!(url.database, "shop");
        assert_eq!(url.tls, Tls::Require);

        let url = parse("mongodb+srv://agent@cluster0.example.net").unwrap();

        assert_eq!(url.database, "test");
        assert_eq!(url.tls, Tls::Require);
    }

    #[test]
    fn parses_cassandra_and_clickhouse_urls() {
        let url = parse("cassandra://agent@10.0.0.1,10.0.0.2:9142/shop?tls=true").unwrap();

        assert_eq!(Engine::of(&url.text), Ok(Engine::Cassandra));
        assert_eq!(
            url.hosts,
            [
                ("10.0.0.1".to_string(), 9042),
                ("10.0.0.2".to_string(), 9142)
            ]
        );
        assert_eq!(url.database, "shop");
        assert_eq!(url.tls, Tls::Require);

        let url = parse("clickhouse://agent@db.example.com?secure=true").unwrap();

        assert_eq!(Engine::of(&url.text), Ok(Engine::ClickHouse));
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
            assert!(parse(text).is_err(), "{text}");
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
            assert!(parse(text).is_err(), "{text}");
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
            assert!(parse(text).is_err(), "{text}");
        }
    }
}
