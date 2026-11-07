use std::error::Error as StdError;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Failure {
    #[error("{0}")]
    Usage(String),
    #[error("{flag} is not supported: {reason}")]
    Refused { flag: String, reason: &'static str },
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
    #[error("request failed: {0}")]
    Network(String),
}

impl Failure {
    pub fn code(&self) -> u8 {
        match self {
            Self::Scheme(_) => 1,
            Self::Usage(_) | Self::Refused { .. } => 2,
            Self::Url(_) => 3,
            Self::Dns(_) => 6,
            Self::Connect(_) => 7,
            Self::Write(_) => 23,
            Self::Read(_) => 26,
            Self::Timeout => 28,
            Self::Tls(_) => 35,
            Self::Network(_) => 56,
        }
    }
}

impl From<reqwest::Error> for Failure {
    fn from(error: reqwest::Error) -> Self {
        let chain = sources(&error);
        let text = chain.join(": ");
        let cause = chain.last().cloned().unwrap_or_else(|| error.to_string());
        if error.is_timeout() {
            Self::Timeout
        } else if error.is_connect() && text.contains("dns error") {
            Self::Dns(cause)
        } else if error.is_connect()
            && ["certificate", "alert", "peer"]
                .iter()
                .any(|word| text.contains(word))
        {
            Self::Tls(cause)
        } else if error.is_connect() {
            Self::Connect(cause)
        } else {
            Self::Network(cause)
        }
    }
}

fn sources(error: &dyn StdError) -> Vec<String> {
    let mut chain = Vec::new();
    let mut source = error.source();
    while let Some(error) = source {
        chain.push(error.to_string());
        source = error.source();
    }
    chain
}
