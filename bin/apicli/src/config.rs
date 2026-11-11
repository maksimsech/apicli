use std::{collections::BTreeMap, fmt};

use fieldkit_common::{Failure, Limits, Rate, Vault};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::origin::Origin;

const SECTION: &str = "apicli";

const READ_METHODS: [&str; 3] = ["GET", "HEAD", "OPTIONS"];

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<Credential>,
    #[serde(default)]
    pub policy: Policy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Credential {
    pub name: String,
    pub origin: Origin,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    pub header: String,
    pub template: String,
    #[serde(skip)]
    pub secret: SecretString,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub hosts: BTreeMap<Origin, HostPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPolicy {
    #[serde(default = "read_methods")]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<Rate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_body: bool,
}

fn read_methods() -> Vec<String> {
    READ_METHODS
        .iter()
        .map(|method| method.to_string())
        .collect()
}

fn is_false(value: &bool) -> bool {
    !value
}

impl Config {
    pub fn load(vault: &Vault) -> Result<Config, Failure> {
        let mut config: Config = vault.section(SECTION)?;
        for credential in &mut config.credentials {
            credential.secret = vault.secret(SECTION, &credential.name)?;
        }
        Ok(config)
    }

    pub fn save(&self, vault: &mut Vault) -> Result<(), Failure> {
        let secrets = self
            .credentials
            .iter()
            .map(|credential| (credential.name.clone(), credential.secret.clone()));
        vault.set_section(SECTION, self, secrets)
    }

    pub fn find(&self, name: &str) -> Option<&Credential> {
        self.credentials
            .iter()
            .find(|credential| credential.name == name)
    }

    pub fn find_mut(&mut self, name: &str) -> Option<&mut Credential> {
        self.credentials
            .iter_mut()
            .find(|credential| credential.name == name)
    }
}

impl Credential {
    pub fn value(&self) -> SecretString {
        SecretString::from(
            self.template
                .replace("{secret}", self.secret.expose_secret()),
        )
    }
}

impl Policy {
    pub fn host(&self, origin: &Origin) -> HostPolicy {
        self.hosts.get(origin).cloned().unwrap_or_default()
    }
}

impl Default for HostPolicy {
    fn default() -> Self {
        HostPolicy {
            methods: read_methods(),
            rate: None,
            burst: None,
            daily: None,
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }
}

impl HostPolicy {
    pub fn limits(&self) -> Limits {
        Limits {
            rate: self.rate,
            burst: self.burst,
            daily: self.daily,
        }
    }

    pub fn summary(&self) -> String {
        let mut parts = vec![self.methods.join(", ")];
        parts.extend(self.allow.iter().map(|rule| rule.to_string()));
        parts.join("; ")
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{} {}", self.method, self.path)
    }
}
