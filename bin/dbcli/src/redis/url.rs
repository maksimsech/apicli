use url::Url;

use crate::shared::{ConnectionUrl, Tls, authority, single_path};

pub fn parse(text: &str) -> Result<ConnectionUrl, String> {
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
