use apicli_vault::VaultError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Failure {
    #[error("{0}")]
    Usage(String),
    #[error("{flag} is not supported: {reason}")]
    Refused { flag: String, reason: &'static str },
    #[error("this command must be run by the user in a terminal")]
    NeedsTerminal,
    #[error("unsupported scheme {0}://, use https://")]
    Scheme(String),
    #[error("{0}")]
    Url(String),
    #[error("could not resolve host: {0}")]
    Dns(String),
    #[error("could not connect: {0}")]
    Connect(String),
    #[error("could not write output: {0}")]
    Write(String),
    #[error("could not read {0}")]
    Read(String),
    #[error("request timed out")]
    Timeout,
    #[error("TLS failed: {0}")]
    Tls(String),
    #[error("stopped after {0} redirects, raise --max-redirs to follow more")]
    Redirects(u32),
    #[error("request failed: {0}")]
    Network(String),
    #[error("{0}")]
    Database(String),
    #[error("{0}")]
    Denied(String),
    #[error("{0}")]
    Limited(String),
    #[error("{0}")]
    Unconfigured(String),
    #[error("{0}")]
    Integrity(String),
    #[error("{0}")]
    Setup(String),
}

impl Failure {
    pub fn code(&self) -> u8 {
        match self {
            Self::Scheme(_) | Self::Database(_) => 1,
            Self::Usage(_) | Self::Refused { .. } | Self::NeedsTerminal => 2,
            Self::Url(_) => 3,
            Self::Dns(_) => 6,
            Self::Connect(_) => 7,
            Self::Write(_) => 23,
            Self::Read(_) => 26,
            Self::Timeout => 28,
            Self::Tls(_) => 35,
            Self::Redirects(_) => 47,
            Self::Network(_) => 56,
            Self::Denied(_) => 110,
            Self::Limited(_) => 111,
            Self::Unconfigured(_) => 112,
            Self::Integrity(_) => 113,
            Self::Setup(_) => 114,
        }
    }

    pub fn outcome(&self) -> &'static str {
        match self {
            Self::Database(_) => "error",
            Self::Denied(_) => "denied",
            Self::Limited(_) => "limited",
            Self::Unconfigured(_) => "unconfigured",
            Self::Integrity(_) | Self::Setup(_) => "broken",
            Self::Scheme(_)
            | Self::Usage(_)
            | Self::Refused { .. }
            | Self::NeedsTerminal
            | Self::Url(_) => "invalid",
            _ => "failed",
        }
    }
}

impl From<VaultError> for Failure {
    fn from(error: VaultError) -> Self {
        match error {
            VaultError::NoHome | VaultError::Crypto(_) => Self::Setup(error.to_string()),
            VaultError::Corrupt(_) | VaultError::Io(_) => Self::Integrity(error.to_string()),
        }
    }
}
