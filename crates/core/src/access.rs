use url::Url;

use crate::{Credential, Origin};

pub const READ_METHODS: [&str; 3] = ["GET", "HEAD", "OPTIONS"];

#[derive(Debug, PartialEq, Eq)]
pub enum Denial {
    Userinfo,
    EncodedSeparator,
    Unconfigured(String),
    Method { method: String, origin: Origin },
}

pub fn authorize<'a>(
    url: &Url,
    method: &str,
    credentials: &'a [Credential],
) -> Result<&'a Credential, Denial> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Denial::Userinfo);
    }
    let path = url.path().to_ascii_lowercase();
    if path.contains("%2f") || path.contains("%5c") {
        return Err(Denial::EncodedSeparator);
    }
    let origin = Origin::of(url).ok_or_else(|| Denial::Unconfigured(url.to_string()))?;
    let credential = credentials
        .iter()
        .find(|credential| credential.origin == origin)
        .ok_or_else(|| Denial::Unconfigured(origin.to_string()))?;
    if !READ_METHODS.contains(&method) {
        return Err(Denial::Method {
            method: method.into(),
            origin,
        });
    }
    Ok(credential)
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    fn credentials() -> Vec<Credential> {
        vec![Credential {
            name: "example".into(),
            origin: Origin::parse("api.example.com").unwrap(),
            header: "X-API-Key".into(),
            template: "{secret}".into(),
            secret: SecretString::from("key-1234567890"),
        }]
    }

    fn check(url: &str, method: &str) -> Result<String, Denial> {
        let credentials = credentials();
        authorize(&Url::parse(url).unwrap(), method, &credentials)
            .map(|credential| credential.name.clone())
    }

    #[test]
    fn bound_origin_gets_its_credential() {
        assert_eq!(
            check("https://api.example.com/v1/users", "GET"),
            Ok("example".into())
        );
    }

    #[test]
    fn other_origins_are_unconfigured() {
        assert!(matches!(
            check("https://api.example.com.attacker.example/", "GET"),
            Err(Denial::Unconfigured(_))
        ));
        assert!(matches!(
            check("http://api.example.com/", "GET"),
            Err(Denial::Unconfigured(_))
        ));
    }

    #[test]
    fn redirect_to_another_origin_is_unconfigured() {
        let current = Url::parse("https://api.example.com/v1/download").unwrap();
        let next = current.join("//attacker.example/collect").unwrap();
        let credentials = credentials();

        assert!(matches!(
            authorize(&next, "GET", &credentials),
            Err(Denial::Unconfigured(_))
        ));
    }

    #[test]
    fn writes_are_denied() {
        assert!(matches!(
            check("https://api.example.com/v1/users", "POST"),
            Err(Denial::Method { .. })
        ));
        assert!(matches!(
            check("https://api.example.com/v1/users", "DELETE"),
            Err(Denial::Method { .. })
        ));
    }

    #[test]
    fn userinfo_is_rejected() {
        assert_eq!(
            check("https://user:pass@api.example.com/", "GET"),
            Err(Denial::Userinfo)
        );
    }

    #[test]
    fn encoded_separators_are_rejected() {
        assert_eq!(
            check("https://api.example.com/v1/a%2Fb", "GET"),
            Err(Denial::EncodedSeparator)
        );
        assert_eq!(
            check("https://api.example.com/v1/a%5cb", "GET"),
            Err(Denial::EncodedSeparator)
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
