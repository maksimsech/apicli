use url::form_urlencoded;

use crate::shared::{ConnectionUrl, Parts, Tls, multiple};

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

pub fn parse(text: &str) -> Result<ConnectionUrl, String> {
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
