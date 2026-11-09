use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};

use crate::{Origin, Policy, policy::matches};

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

fn expose<S: Serializer>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret.expose_secret())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Admin {
    pub hash: String,
    pub failures: u32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Vault {
    pub credentials: Vec<Credential>,
    #[serde(default)]
    pub admin: Option<Admin>,
    #[serde(default)]
    pub policy: Policy,
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

    pub fn secrets(&self) -> impl Iterator<Item = &str> {
        self.credentials
            .iter()
            .map(|credential| credential.secret.expose_secret())
    }
}
