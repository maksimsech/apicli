use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use apicli_core::Vault;
use directories::ProjectDirs;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{keystore, sealed};

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("no home directory to keep apicli's files in")]
    NoHome,
    #[error("the keystore failed: {0}")]
    Keystore(String),
    #[error("{0} can't be decrypted. Remove it to start over, which deletes every stored secret")]
    Corrupt(PathBuf),
    #[error("{0}")]
    Io(#[from] io::Error),
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open() -> Result<Store, VaultError> {
        let dirs = ProjectDirs::from("dev", "", "apicli").ok_or(VaultError::NoHome)?;
        Ok(Store {
            dir: dirs.data_dir().to_path_buf(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn master_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        keystore::read(&self.dir)
    }

    pub fn load(&self) -> Result<Vault, VaultError> {
        let path = self.vault_path();
        if !path.exists() {
            return Ok(Vault::default());
        }
        let corrupt = || VaultError::Corrupt(path.clone());
        let key = self.master_key()?.ok_or_else(corrupt)?;
        let plain = sealed::open(&key, &fs::read(&path)?).ok_or_else(corrupt)?;
        serde_json::from_slice(&plain).map_err(|_| corrupt())
    }

    pub fn save(&self, vault: &Vault) -> Result<(), VaultError> {
        self.create_dir()?;
        let key = match self.master_key()? {
            Some(key) => key,
            None => {
                let key = sealed::random_key()
                    .ok_or_else(|| VaultError::Keystore("no system randomness".into()))?;
                keystore::write(&self.dir, &key)?;
                key
            }
        };
        let plain = Zeroizing::new(serde_json::to_vec(vault).map_err(io::Error::other)?);
        let sealed =
            sealed::seal(&key, &plain).ok_or_else(|| VaultError::Corrupt(self.vault_path()))?;
        write_private(&self.vault_path(), &sealed)?;
        Ok(())
    }

    fn vault_path(&self) -> PathBuf {
        self.dir.join("vault.bin")
    }

    fn create_dir(&self) -> io::Result<()> {
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(&self.dir)
    }
}

pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temp = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(&temp)?.write_all(bytes)?;
    fs::rename(temp, path)
}
