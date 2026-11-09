use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{Origin, rules::matches};
use crate::{Vault, vault::expose};

#[derive(Debug, Serialize, Deserialize)]
pub struct Credential {
    pub name: String,
    pub origin: Origin,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    pub header: String,
    pub template: String,
    #[serde(serialize_with = "expose")]
    pub secret: SecretString,
}

impl Credential {
    pub fn value(&self) -> SecretString {
        SecretString::from(
            self.template
                .replace("{secret}", self.secret.expose_secret()),
        )
    }
}

impl Vault {
    pub fn find(&self, name: &str) -> Option<&Credential> {
        self.credentials
            .iter()
            .find(|credential| credential.name == name)
    }

    pub fn credential(&self, origin: &Origin, path: &str) -> Option<&Credential> {
        let mut hosted = self
            .credentials
            .iter()
            .filter(|credential| &credential.origin == origin);
        hosted
            .clone()
            .find(|credential| {
                credential
                    .paths
                    .iter()
                    .any(|pattern| matches(pattern, path, false))
            })
            .or_else(|| hosted.find(|credential| credential.paths.is_empty()))
    }

    pub fn find_mut(&mut self, name: &str) -> Option<&mut Credential> {
        self.credentials
            .iter_mut()
            .find(|credential| credential.name == name)
    }
}
