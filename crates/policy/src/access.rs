use url::Url;

use crate::{
    Vault,
    api::{Body, Credential, Denial, Grant, Origin},
};

pub fn authorize<'a>(
    url: &Url,
    method: &str,
    body: Option<Body>,
    vault: &'a Vault,
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
    if !vault
        .credentials
        .iter()
        .any(|credential| credential.origin == origin)
    {
        return Err(Denial::Unconfigured(origin.to_string()));
    }
    let grant = vault.policy.host(&origin).check(method, url.path(), body)?;
    let credential = vault
        .credential(&origin, url.path())
        .ok_or(Denial::Uncovered)?;
    Ok((credential, grant))
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    fn credential(name: &str, paths: &[&str]) -> Credential {
        Credential {
            name: name.into(),
            origin: Origin::parse("api.example.com").unwrap(),
            paths: paths.iter().map(|path| path.to_string()).collect(),
            header: "X-API-Key".into(),
            template: "{secret}".into(),
            secret: SecretString::from("key-1234567890"),
        }
    }

    fn vault() -> Vault {
        Vault {
            credentials: vec![credential("example", &[])],
            ..Vault::default()
        }
    }

    fn check(url: &str, method: &str) -> Result<String, Denial> {
        let vault = vault();
        authorize(&Url::parse(url).unwrap(), method, None, &vault)
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
    fn path_scoped_credentials_cover_only_their_paths() {
        let mut vault = Vault {
            credentials: vec![
                credential("reports", &["/v1/reports/**"]),
                credential("export", &["/v1/exports/*"]),
            ],
            ..Vault::default()
        };
        let pick = |vault: &Vault, url: &str| {
            authorize(&Url::parse(url).unwrap(), "GET", None, vault)
                .map(|(credential, _)| credential.name.clone())
        };

        assert_eq!(
            pick(&vault, "https://api.example.com/v1/reports/1/rows"),
            Ok("reports".into())
        );
        assert_eq!(
            pick(&vault, "https://api.example.com/v1/exports/7"),
            Ok("export".into())
        );
        assert_eq!(
            pick(&vault, "https://api.example.com/V1/reports/1"),
            Err(Denial::Uncovered)
        );
        assert_eq!(
            pick(&vault, "https://api.example.com/v1/exports/7/file"),
            Err(Denial::Uncovered)
        );

        vault.credentials.push(credential("main", &[]));

        assert_eq!(
            pick(&vault, "https://api.example.com/v1/reports"),
            Ok("reports".into())
        );
        assert_eq!(
            pick(&vault, "https://api.example.com/v1/users"),
            Ok("main".into())
        );
        assert_eq!(
            pick(&vault, "https://api.example.com/v1//reports/1"),
            Ok("main".into())
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
            authorize(&next, "GET", None, &vault),
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
