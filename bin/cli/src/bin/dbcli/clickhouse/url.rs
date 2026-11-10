use url::Url;

use crate::shared::{ConnectionUrl, Tls, authority, encryption, single_path};

pub fn parse(text: &str) -> Result<ConnectionUrl, String> {
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
    let (tls, root_cert) = encryption(url.query().unwrap_or_default(), "secure", "clickhouse")?;
    let port = url
        .port()
        .unwrap_or(if tls == Tls::Require { 8443 } else { 8123 });
    Ok(ConnectionUrl {
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
