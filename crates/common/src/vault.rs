use std::collections::BTreeMap;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer, de::DeserializeOwned};
use serde_json::Value;

use crate::Failure;

type Secrets = BTreeMap<String, BTreeMap<String, SecretString>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Admin {
    pub hash: String,
    pub failures: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Vault {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<Admin>,
    #[serde(default = "log_limit_mb")]
    pub log_limit_mb: u32,
    #[serde(default, serialize_with = "expose")]
    secrets: Secrets,
    #[serde(default)]
    tools: BTreeMap<String, Value>,
}

impl Default for Vault {
    fn default() -> Self {
        Vault {
            admin: None,
            log_limit_mb: log_limit_mb(),
            secrets: Secrets::new(),
            tools: BTreeMap::new(),
        }
    }
}

impl Vault {
    pub fn secrets(&self) -> impl Iterator<Item = &str> {
        self.secrets
            .values()
            .flat_map(|named| named.values())
            .map(|secret| secret.expose_secret())
    }

    pub fn secret(&self, tool: &str, name: &str) -> Result<SecretString, Failure> {
        self.secrets
            .get(tool)
            .and_then(|named| named.get(name))
            .cloned()
            .ok_or_else(|| Failure::Integrity(format!("the vault has no secret for {tool} {name}")))
    }

    pub fn section<T: DeserializeOwned + Default>(&self, tool: &str) -> Result<T, Failure> {
        match self.tools.get(tool) {
            Some(value) => T::deserialize(value).map_err(|error| {
                Failure::Integrity(format!("the vault's {tool} section is invalid: {error}"))
            }),
            None => Ok(T::default()),
        }
    }

    pub fn set_section<T: Serialize>(
        &mut self,
        tool: &str,
        section: &T,
        secrets: impl IntoIterator<Item = (String, SecretString)>,
    ) -> Result<(), Failure> {
        let value = serde_json::to_value(section).map_err(|error| {
            Failure::Integrity(format!("could not store the {tool} section: {error}"))
        })?;
        self.tools.insert(tool.to_string(), value);
        self.secrets
            .insert(tool.to_string(), secrets.into_iter().collect());
        Ok(())
    }
}

fn log_limit_mb() -> u32 {
    10
}

fn expose<S: Serializer>(secrets: &Secrets, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_map(secrets.iter().map(|(tool, named)| {
        let named = named
            .iter()
            .map(|(name, secret)| (name, secret.expose_secret()))
            .collect::<BTreeMap<_, _>>();
        (tool, named)
    }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn named(name: &str, secret: &str) -> Vec<(String, SecretString)> {
        vec![(name.into(), SecretString::from(secret))]
    }

    #[test]
    fn every_tool_sees_every_secret_and_sections_hold_none() {
        let mut vault = Vault::default();
        vault
            .set_section("apicli", &json!({ "hosts": 1 }), named("github", "ghp-1"))
            .unwrap();
        vault
            .set_section("dbcli", &json!({ "connections": 2 }), named("prod", "pg-2"))
            .unwrap();
        vault
            .set_section("apicli", &json!({ "hosts": 3 }), named("github", "ghp-3"))
            .unwrap();

        let text = serde_json::to_string(&vault).unwrap();
        let loaded: Vault = serde_json::from_str(&text).unwrap();

        let mut secrets = loaded.secrets().collect::<Vec<_>>();
        secrets.sort();
        assert_eq!(secrets, ["ghp-3", "pg-2"]);
        assert_eq!(
            loaded.section::<Value>("apicli").unwrap(),
            json!({ "hosts": 3 })
        );
        assert_eq!(
            loaded.section::<Value>("dbcli").unwrap(),
            json!({ "connections": 2 })
        );
        assert!(!loaded.tools.values().any(|section| {
            let section = section.to_string();
            section.contains("ghp-") || section.contains("pg-2")
        }));
    }
}
