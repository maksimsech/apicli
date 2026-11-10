use secrecy::{ExposeSecret, SecretString};
use serde::Serializer;

pub fn expose<S: Serializer>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret.expose_secret())
}
