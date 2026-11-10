use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::{
    api::{Credential, Origin, Policy, matches},
    db::Connection,
};

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

    pub fn connection(&self, name: &str) -> Option<&Connection> {
        self.connections
            .iter()
            .find(|connection| connection.name == name)
    }

    pub fn connection_mut(&mut self, name: &str) -> Option<&mut Connection> {
        self.connections
            .iter_mut()
            .find(|connection| connection.name == name)
    }
}
