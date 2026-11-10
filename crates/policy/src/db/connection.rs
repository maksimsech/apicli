use std::fmt;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::{Limits, Rate, secret::expose};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allow {
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

impl fmt::Display for Allow {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match &self.target {
            Some(target) => write!(formatter, "{} {target}", self.action),
            None => write!(formatter, "{}", self.action),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Connection {
    pub name: String,
    pub url: String,
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
