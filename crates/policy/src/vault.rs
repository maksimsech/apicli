use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};

use crate::{Connection, Credential, Policy};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Admin {
    pub hash: String,
    pub failures: u32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Vault {
    pub credentials: Vec<Credential>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connections: Vec<Connection>,
    #[serde(default)]
    pub admin: Option<Admin>,
    #[serde(default)]
    pub policy: Policy,
}

impl Vault {
    pub fn secrets(&self) -> impl Iterator<Item = &str> {
        self.credentials
            .iter()
            .map(|credential| credential.secret.expose_secret())
            .chain(
                self.connections
                    .iter()
                    .map(|connection| connection.password.expose_secret()),
            )
    }
}

pub fn expose<S: Serializer>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret.expose_secret())
}
