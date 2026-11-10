use url::Url;

use crate::shared::{ConnectionUrl, Tls, authority, single_path};

pub fn parse(text: &str) -> Result<ConnectionUrl, String> {
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
