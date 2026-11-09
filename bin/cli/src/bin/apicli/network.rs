use std::error::Error as StdError;

use apicli::Failure;

pub fn network(error: reqwest::Error) -> Failure {
    let chain = sources(&error);
    let text = chain.join(": ");
    let cause = chain.last().cloned().unwrap_or_else(|| error.to_string());
    if error.is_timeout() {
        Failure::Timeout
    } else if error.is_connect() && text.contains("dns error") {
        Failure::Dns(cause)
    } else if error.is_connect()
        && [
            "certificate",
            "alert",
            "peer is incompatible",
            "peer misbehaved",
        ]
        .iter()
        .any(|word| text.contains(word))
    {
        Failure::Tls(cause)
    } else if error.is_connect() {
        Failure::Connect(cause)
    } else {
        Failure::Network(cause)
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
