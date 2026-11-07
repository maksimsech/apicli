use std::fmt;

use serde::{Deserialize, Serialize};
use url::{Host, Url};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    pub fn of(url: &Url) -> Option<Origin> {
        Some(Origin {
            scheme: url.scheme().into(),
            host: url.host_str()?.into(),
            port: url.port_or_known_default()?,
        })
    }

    pub fn parse(input: &str) -> Result<Origin, String> {
        let text = if input.contains("://") {
            input.to_string()
        } else {
            format!("https://{input}")
        };
        let url = Url::parse(&text).map_err(|error| format!("{input}: {error}"))?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(format!(
                "{input} must be only a host with an optional scheme and port, like https://api.example.com"
            ));
        }
        let origin = Origin::of(&url).ok_or_else(|| format!("{input} has no host"))?;
        match origin.scheme.as_str() {
            "https" => Ok(origin),
            "http" if is_loopback(&url) => Ok(origin),
            "http" => Err(format!(
                "{input} uses http://, which is only allowed for localhost"
            )),
            scheme => Err(format!("unsupported scheme {scheme}://")),
        }
    }
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain == "localhost",
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let default = match self.scheme.as_str() {
            "https" => 443,
            "http" => 80,
            _ => 0,
        };
        if self.port == default {
            write!(formatter, "{}://{}", self.scheme, self.host)
        } else {
            write!(formatter, "{}://{}:{}", self.scheme, self.host, self.port)
        }
    }
}

impl TryFrom<String> for Origin {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        Origin::parse(&text)
    }
}

impl From<Origin> for String {
    fn from(origin: Origin) -> String {
        origin.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url_origin(url: &str) -> Origin {
        Origin::of(&Url::parse(url).unwrap()).unwrap()
    }

    #[test]
    fn parse_defaults_to_https() {
        assert_eq!(
            Origin::parse("api.example.com").unwrap(),
            url_origin("https://api.example.com/")
        );
    }

    #[test]
    fn host_case_and_default_port_match() {
        assert_eq!(
            Origin::parse("https://API.Example.com:443").unwrap(),
            url_origin("https://api.example.com/v1")
        );
    }

    #[test]
    fn lookalike_hosts_ports_and_schemes_do_not_match() {
        let origin = Origin::parse("api.example.com").unwrap();

        assert_ne!(
            origin,
            url_origin("https://api.example.com.attacker.example/")
        );
        assert_ne!(origin, url_origin("https://attacker-api.example.com/"));
        assert_ne!(origin, url_origin("https://api.example.com:8443/"));
        assert_ne!(origin, url_origin("http://api.example.com/"));
    }

    #[test]
    fn parse_rejects_paths_and_userinfo() {
        assert!(Origin::parse("https://api.example.com/v1").is_err());
        assert!(Origin::parse("https://user@api.example.com").is_err());
    }

    #[test]
    fn parse_allows_http_only_for_loopback() {
        assert!(Origin::parse("http://localhost:8080").is_ok());
        assert!(Origin::parse("http://127.0.0.1:8080").is_ok());
        assert!(Origin::parse("http://api.example.com").is_err());
    }
}
