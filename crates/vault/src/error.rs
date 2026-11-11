use std::{io, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("no home directory to keep fieldkit's files in")]
    NoHome,
    #[error("{0}")]
    Crypto(String),
    #[error("{0} can't be decrypted. Remove it to start over, which deletes every stored secret")]
    Corrupt(PathBuf),
    #[error("{0}")]
    Io(#[from] io::Error),
}
