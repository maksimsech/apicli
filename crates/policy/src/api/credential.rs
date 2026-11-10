use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::Origin;
use crate::secret::expose;

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
