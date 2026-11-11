use std::fmt;

use fieldkit_common::{Failure, Limits, Rate, Vault};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

const SECTION: &str = "dbcli";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connections: Vec<Connection>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Connection {
    pub name: String,
    pub url: String,
    #[serde(skip)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allow {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !value
}

impl Config {
    pub fn load(vault: &Vault) -> Result<Config, Failure> {
        let mut config: Config = vault.section(SECTION)?;
        for connection in &mut config.connections {
            connection.password = vault.secret(SECTION, &connection.name)?;
        }
        Ok(config)
    }

    pub fn save(&self, vault: &mut Vault) -> Result<(), Failure> {
        let secrets = self
            .connections
            .iter()
            .map(|connection| (connection.name.clone(), connection.password.clone()));
        vault.set_section(SECTION, self, secrets)
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

impl Connection {
    pub fn new(name: String, url: String, password: SecretString) -> Connection {
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

impl fmt::Display for Allow {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match &self.target {
            Some(target) => write!(formatter, "{} {target}", self.action),
            None => write!(formatter, "{}", self.action),
        }
    }
}
