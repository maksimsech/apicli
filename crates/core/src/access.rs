use url::Url;

use crate::{Body, Credential, Grant, Origin, Policy, Rule, Vault};

pub const READ_METHODS: [&str; 3] = ["GET", "HEAD", "OPTIONS"];

#[derive(Debug, PartialEq, Eq)]
pub enum Denial {
    Userinfo,
    EncodedSeparator,
    MethodOverride(String),
    Unconfigured(String),
    Rule(Rule),
    NotAllowed,
    Body(String),
}

pub fn authorize<'a>(
    url: &Url,
    method: &str,
    body: Option<Body>,
    vault: &'a Vault,
    policy: &Policy,
) -> Result<(&'a Credential, Grant), Denial> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Denial::Userinfo);
    }
    let path = url.path().to_ascii_lowercase();
    if path.contains("%2f") || path.contains("%5c") {
        return Err(Denial::EncodedSeparator);
    }
    if url
        .query_pairs()
        .any(|(name, _)| name.eq_ignore_ascii_case("_method"))
    {
        return Err(Denial::MethodOverride("_method".into()));
    }
    let origin = Origin::of(url).ok_or_else(|| Denial::Unconfigured(url.to_string()))?;
    let credential = vault
        .credentials
        .iter()
        .find(|credential| credential.origin == origin)
        .ok_or_else(|| Denial::Unconfigured(origin.to_string()))?;
    let grant = policy.host(&origin).check(method, url.path(), body)?;
    Ok((credential, grant))
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    fn vault() -> Vault {
        Vault {
            credentials: vec![Credential {
                name: "example".into(),
                origin: Origin::parse("api.example.com").unwrap(),
                header: "X-API-Key".into(),
                template: "{secret}".into(),
                secret: SecretString::from("key-1234567890"),
            }],
            ..Vault::default()
        }
    }

    fn check(url: &str, method: &str) -> Result<String, Denial> {
        let vault = vault();
        authorize(
            &Url::parse(url).unwrap(),
            method,
            None,
            &vault,
            &Policy::default(),
        )
        .map(|(credential, _)| credential.name.clone())
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
        let next = Url::parse("https://api.example.com/v1/download")
            .unwrap()
            .join("//attacker.example/collect")
            .unwrap();
        let vault = vault();

        assert!(matches!(
            authorize(&next, "GET", None, &vault, &Policy::default()),
            Err(Denial::Unconfigured(_))
        ));
    }

    #[test]
    fn writes_are_denied_by_default() {
        assert_eq!(
            check("https://api.example.com/v1/users", "POST"),
            Err(Denial::NotAllowed)
        );
        assert_eq!(
            check("https://api.example.com/v1/users", "DELETE"),
            Err(Denial::NotAllowed)
        );
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
    fn method_parameter_is_rejected() {
        assert_eq!(
            check("https://api.example.com/v1/users/1?_method=DELETE", "GET"),
            Err(Denial::MethodOverride("_method".into()))
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
