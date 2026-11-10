use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use super::{Allow, ConnectionUrl};
use crate::{Limits, Rate, Vault, vault::expose};

#[derive(Debug, Serialize, Deserialize)]
pub struct Connection {
    pub name: String,
    pub url: ConnectionUrl,
    #[serde(serialize_with = "expose")]
    pub password: SecretString,
    #[serde(default, skip_serializing_if = "is_false")]
    pub write: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<Allow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<Rate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily: Option<u32>,
}

fn is_false(value: &bool) -> bool {
    !value
}

impl Connection {
    pub fn new(name: String, url: ConnectionUrl, password: SecretString) -> Connection {
        Connection {
            name,
            url,
            password,
            write: false,
            allow: Vec::new(),
            rate: None,
            burst: None,
            daily: None,
        }
    }

    pub fn limits(&self) -> Limits {
        Limits {
            rate: self.rate,
            burst: self.burst,
            daily: self.daily,
        }
    }
}

impl Vault {
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
